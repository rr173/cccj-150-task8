"""机构签发密钥轮换、回执撤销与离线信任包。

所有状态推进都在中继独立 SQLite 的单写事务内完成。密钥轮换记录是一条只追加
的连续签名链；撤销清单按机构单调出版本；离线信任包携带单调 trust_version、
完整公钥链和当前撤销摘要，供核验器在没有网络和数据库时定位拒绝原因。
"""
from __future__ import annotations

import json
import shutil
import sqlite3
from datetime import datetime, timedelta, timezone

from . import config, crypto, ed25519
from .store import tx, audit
from ..services.ids import new_id, now_iso


class TrustError(Exception):
    def __init__(self, message: str, code: str, status: int = 400, extra=None):
        super().__init__(message)
        self.code = code
        self.status = status
        self.extra = extra or {}


def _iso(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def _rowdict(row) -> dict:
    return dict(row) if row is not None else None


def _canonical_json(obj) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), default=str)


def _fingerprint(**kwargs) -> str:
    return crypto.sha256_hex(crypto.canonical(kwargs))


def _institution_row(conn, code: str, required: bool = True):
    row = conn.execute(
        "SELECT * FROM relay_institution_state WHERE institution_code=?",
        (code,)).fetchone()
    if row is None and required:
        raise TrustError(f"机构尚未初始化: {code}", "INSTITUTION_NOT_READY", 409)
    return row


def ensure_institution(conn, code: str, title: str | None = None) -> dict:
    """在状态表中引导根公钥（seq=0）。文件密钥必须已经创建。"""
    row = _institution_row(conn, code, required=False)
    if row is not None:
        return dict(row)
    try:
        pub0 = crypto.load_institution_public(code, 0)
    except FileNotFoundError:
        pub0 = crypto.load_institution_public(code)
        shutil.copyfile(crypto.institution_pub_path(code),
                        crypto.institution_pub_path(code, 0))
    try:
        crypto.load_institution_seed(code, 0)
    except FileNotFoundError:
        shutil.copyfile(crypto.institution_seed_path(code),
                        crypto.institution_seed_path(code, 0))
    at = now_iso()
    genesis = crypto.rotation_genesis_record(code, pub0, at)
    conn.execute(
        "INSERT INTO relay_institution_state(institution_code,title,"
        "current_key_seq,next_receipt_serial,revocation_version,trust_version,"
        "created_at,updated_at) VALUES(?,?,0,1,0,0,?,?)",


        (code, title or code, at, at))
    conn.execute(
        "INSERT INTO relay_key_rotation(institution_code,key_seq,public_key,"
        "effective_watermark,register_request_key,registered_by,registered_at,"
        "status,previous_record_hash,record_hash,signature,activated_at)"
        " VALUES(?,0,?,NULL,'GENESIS',?,?,'ACTIVE',NULL,?,?,?)",
        (code, pub0, "bootstrap", at,
         genesis["record_hash"], genesis["signature"], at))
    audit(conn, "INSTITUTION_BOOTSTRAP", sender_id=None,
          detail={"institution": code, "key_seq": 0})
    return dict(conn.execute(
        "SELECT * FROM relay_institution_state WHERE institution_code=?",
        (code,)).fetchone())


def _persist_admin_action(conn, *, request_key: str, code: str,
                          action_type: str, target_type: str, target_id: str,
                          payload: dict, status_code: int, response: dict):
    try:
        conn.execute(
            "INSERT INTO relay_admin_action(request_key,institution_code,"
            "action_type,target_type,target_id,fingerprint,status_code,"
            "response_json,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
            (request_key, code, action_type, target_type, target_id,
             _fingerprint(**payload), status_code,
             json.dumps(response, ensure_ascii=False, default=str), now_iso()))
    except sqlite3.IntegrityError:
        row = conn.execute(
            "SELECT * FROM relay_admin_action WHERE request_key=?",
            (request_key,)).fetchone()
        if row["fingerprint"] != _fingerprint(**payload):
            raise TrustError("同一请求键已绑定不同内容", "REQUEST_KEY_CONFLICT", 409)
        stored = json.loads(row["response_json"])
        stored["replayed"] = True
        return stored
    response["replayed"] = False
    return response


def _stored_action(conn, request_key: str, payload: dict):
    row = conn.execute(
        "SELECT * FROM relay_admin_action WHERE request_key=?",
        (request_key,)).fetchone()
    if row is None:
        return None
    if row["fingerprint"] != _fingerprint(**payload):
        raise TrustError("同一请求键已绑定不同内容", "REQUEST_KEY_CONFLICT", 409)
    out = json.loads(row["response_json"])
    out["replayed"] = True
    return out


def _rotation(conn, code: str, seq: int):
    return conn.execute(
        "SELECT * FROM relay_key_rotation WHERE institution_code=? AND key_seq=?",
        (code, seq)).fetchone()


def _public_rotation_records(conn, code: str) -> list[dict]:
    rows = conn.execute(
        "SELECT * FROM relay_key_rotation WHERE institution_code=? "
        "AND status IN ('ROTATED','ACTIVE') ORDER BY key_seq", (code,)).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        out.append(d)
    return out


def _key_for_serial(records: list[dict], serial: int):
    """返回可签该签发水位的最后一把 ACTIVE 钥。"""
    chosen = records[0]
    for rec in records[1:]:
        wm = rec["effective_watermark"]
        if rec["status"] == "ACTIVE" and wm is not None and serial >= wm:
            chosen = rec
        else:
            break
    return chosen


def _auto_activate_due(conn, code: str, state: dict) -> dict | None:
    """批准后的轮换达到 next_receipt_serial 水位时，在同一写事务内切换。

    旧钥已经签发的 serial < effective_watermark 全部保持旧钥；下一把钥从
    effective_watermark 开始独占签发。状态行单调更新，重启重放不会回退。
    """
    current_seq = state["current_key_seq"]
    rec = conn.execute(
        "SELECT * FROM relay_key_rotation WHERE institution_code=? AND status='APPROVED' "
        "ORDER BY key_seq LIMIT 1", (code,)).fetchone()
    if rec is None:
        return None
    next_serial = state["next_receipt_serial"]
    if next_serial < rec["effective_watermark"]:
        return None
    old = _rotation(conn, code, current_seq)
    if old is None or old["status"] != "ACTIVE":
        raise TrustError("机构密钥链当前活动记录缺失", "ROTATION_CHAIN_BROKEN", 500)
    old_seed = crypto.load_institution_seed(code, current_seq)
    updated = dict(rec)
    at = now_iso()
    updated.update({"status": "ACTIVE", "activated_at": at})
    updated["record_hash"] = crypto.rotation_record_hash(updated)
    updated["signature"] = crypto.sign_rotation_record(updated, old_seed)
    # 批准阶段保存的待生效私钥只在生效瞬间进入正式 seq 文件名；文件不影响权威状态。
    pending_seed = config.key_dir() / f"{code}.pending.{rec['key_seq']}.seed"
    if pending_seed.exists():
        shutil.copyfile(pending_seed,
                        crypto.institution_seed_path(code, rec["key_seq"]))
        crypto.institution_seed_path(code, rec["key_seq"]).chmod(0o600)
    else:
        # 离线登记公钥时私钥由外部保管；必须由部署者放入正式文件后才能再签发。
        try:
            crypto.load_institution_seed(code, rec["key_seq"])
        except FileNotFoundError as exc:
            raise TrustError(
                "新钥已到生效水位，但机构私钥尚未导入",
                "NEW_SIGNING_KEY_UNAVAILABLE", 409,
                {"key_seq": rec["key_seq"],
                 "expected_seed_path": str(crypto.institution_seed_path(code, rec["key_seq"]))}) from exc
    # 保留旧根记录 status=ACTIVE（该字段进入自签哈希）；seq>0 表上的唯一索引
    # 仍保证当前签发钥唯一。导出链用单独的 current 标记区分当前钥。
    conn.execute(
        "UPDATE relay_key_rotation SET activated_at=? "
        "WHERE institution_code=? AND key_seq=?",
        (at, code, current_seq))
    conn.execute(
        "UPDATE relay_key_rotation SET status='ACTIVE',activated_at=?,"
        "record_hash=?,signature=? WHERE institution_code=? AND key_seq=?",
        (at, updated["record_hash"], updated["signature"], code, rec["key_seq"]))
    conn.execute(
        "UPDATE relay_institution_state SET current_key_seq=?,updated_at=? "
        "WHERE institution_code=?", (rec["key_seq"], now_iso(), code))
    audit(conn, "ROTATION_ACTIVATE",
          detail={"institution": code, "key_seq": rec["key_seq"],
                  "effective_watermark": rec["effective_watermark"]})
    return updated


# ---------------------------------------------------------------------------
# 轮换：预演 / 登记 / 批准 / 生效
# ---------------------------------------------------------------------------

def rotation_preview(institution_code: str, *, effective_watermark: int,
                     public_key: str | None = None) -> dict:
    init = init_institution_state(institution_code)
    with tx() as conn:
        state = ensure_institution(conn, institution_code)
        wm = int(effective_watermark)
        if wm < state["next_receipt_serial"]:
            raise TrustError(
                "生效水位不能早于下一回执签发水位", "WATERMARK_BACKDATED", 422,
                {"effective_watermark": wm,
                 "minimum_watermark": state["next_receipt_serial"]})
        open_rec = conn.execute(
            "SELECT * FROM relay_key_rotation WHERE institution_code=? "
            "AND status IN ('PROPOSED','APPROVED')",
            (institution_code,)).fetchone()
        return {
            "institution_code": institution_code,
            "current_key_seq": state["current_key_seq"],
            "next_key_seq": (open_rec["key_seq"] if open_rec
                             else state["current_key_seq"] + 1),
            "next_receipt_serial": state["next_receipt_serial"],
            "requested_watermark": wm,
            "old_key_signs": f"serial < {wm}",
            "new_key_signs": f"serial >= {wm}",
            "would_activate_immediately":
                state["next_receipt_serial"] >= wm,
            "open_rotation": dict(open_rec) if open_rec else None,
            "public_key_valid": _valid_public_key(public_key)
            if public_key else None,
            "initialized": init,
        }


def _valid_public_key(pubhex: str) -> bool:
    try:
        return len(bytes.fromhex(pubhex)) == 32
    except (TypeError, ValueError):
        return False


def _new_key_proof_message(code: str, seq: int, request_key: str,
                           public_key: str) -> bytes:
    return crypto.canonical({
        "institution_code": code, "key_seq": seq,
        "register_request_key": request_key, "public_key": public_key})


def _verify_new_key_proof(code: str, seq: int, request_key: str,
                          public_key: str, signature_hex: str) -> bool:
    try:
        return ed25519.verify(
            _new_key_proof_message(code, seq, request_key, public_key),
            bytes.fromhex(signature_hex), bytes.fromhex(public_key))
    except (ValueError, TypeError, ed25519.SignatureError,
            ed25519.PublicKeyError):
        return False


def init_institution_state(institution_code: str, title: str | None = None) -> dict:
    with tx() as conn:
        return ensure_institution(conn, institution_code, title)


def register_rotation(*, institution_code: str, request_key: str,
                      effective_watermark: int, public_key: str | None = None,
                      new_key_self_signature: str | None = None,
                      registered_by: str | None = None,
                      title: str | None = None) -> dict:
    if not request_key:
        raise TrustError("request_key 必填", "BAD_REQUEST", 400)
    try:
        wm = int(effective_watermark)
    except (TypeError, ValueError):
        raise TrustError("effective_watermark 必须为整数", "BAD_REQUEST", 422)
    payload = {"institution_code": institution_code,
               "effective_watermark": wm, "public_key": public_key,
               "new_key_self_signature": new_key_self_signature,
               "registered_by": registered_by}
    with tx() as conn:
        state = ensure_institution(conn, institution_code, title)
        replay = _stored_action(conn, request_key, payload)
        if replay:
            return replay
        if wm < state["next_receipt_serial"]:
            raise TrustError("生效水位不能早于下一回执签发水位",
                             "WATERMARK_BACKDATED", 422,
                             {"minimum_watermark": state["next_receipt_serial"]})
        existing_open = conn.execute(
            "SELECT * FROM relay_key_rotation WHERE institution_code=? "
            "AND status IN ('PROPOSED','APPROVED')",
            (institution_code,)).fetchone()
        if existing_open:
            raise TrustError("已有待生效轮换；必须先批准、生效或拒绝",
                             "ROTATION_OPEN_EXISTS", 409,
                             {"key_seq": existing_open["key_seq"],
                              "status": existing_open["status"]})
        key_seq = state["current_key_seq"] + 1
        local_seed = None
        if public_key is None:
            # 登记只公开公钥与自签证明；正式 .{seq}.seed 不存在，防止未批准
            # 轮换被误用来签发。批准后仅保存 pending 副本，生效时才进入正式名。
            created = crypto.create_institution_keys(
                institution_code, overwrite=False, seq=key_seq)
            public_key = created["public_key"]
            local_seed = crypto.load_institution_seed(institution_code, key_seq)
            pending_path = config.key_dir() / f"{institution_code}.pending.{key_seq}.seed"
            pending_path.write_text(local_seed.hex(), encoding="ascii")
            pending_path.chmod(0o600)
            crypto.institution_seed_path(
                institution_code, key_seq).unlink(missing_ok=True)
        elif not _valid_public_key(public_key):
            raise TrustError("public_key 必须是 32 字节 Ed25519 公钥 hex",
                             "BAD_PUBLIC_KEY", 422)
        self_sig = new_key_self_signature
        if self_sig is None and local_seed is not None:
            self_sig = ed25519.sign(
                crypto.canonical({"institution_code": institution_code,
                                  "key_seq": key_seq,
                                  "register_request_key": request_key,
                                  "public_key": public_key}),
                local_seed).hex()
        if not self_sig:
            raise TrustError(
                "外部登记公钥必须提供 new_key_self_signature（新私钥对登记声明签名）",
                "NEW_KEY_PROOF_REQUIRED", 422)
        if not _verify_new_key_proof(institution_code, key_seq, request_key,
                                     public_key, self_sig):
            raise TrustError("新公钥自签证明无效", "NEW_KEY_PROOF_INVALID", 422)
        at = now_iso()
        rec = {
            "institution_code": institution_code, "key_seq": key_seq,
            "public_key": public_key, "effective_watermark": wm,
            "register_request_key": request_key,
            "registered_by": registered_by, "registered_at": at,
            "status": "PROPOSED", "approved_by": None, "approved_at": None,
            "activated_at": None,
            "previous_record_hash": _rotation(
                conn, institution_code, state["current_key_seq"])["record_hash"],
            "new_key_self_signature": self_sig,
        }
        try:
            conn.execute(
                "INSERT INTO relay_key_rotation(institution_code,key_seq,"
                "public_key,effective_watermark,register_request_key,"
                "registered_by,registered_at,status,previous_record_hash,"
                "new_key_self_signature)"
                " VALUES(?,?,?,?,?,?,?,?,?,?)",
                (institution_code, key_seq, public_key, wm, request_key,
                 registered_by, at, "PROPOSED", rec["previous_record_hash"],
                 self_sig))
        except sqlite3.IntegrityError as exc:
            raise TrustError("并发登记冲突：只有一个登记请求可生效",
                             "ROTATION_REGISTER_CONFLICT", 409) from exc
        out = {"rotation": rec, "status": "PROPOSED",
               "effective_watermark": wm,
               "immediately_effective": False}
        audit(conn, "ROTATION_REGISTER",
              detail={"institution": institution_code, "key_seq": key_seq,
                      "request_key": request_key, "watermark": wm})
        return _persist_admin_action(
            conn, request_key=request_key, code=institution_code,
            action_type="ROTATION_REGISTER", target_type="ROTATION",
            target_id=str(key_seq), payload=payload, status_code=201,
            response=out)


def approve_rotation(*, institution_code: str, key_seq: int,
                     approver: str, request_key: str) -> dict:
    if not request_key:
        raise TrustError("request_key 必填", "BAD_REQUEST", 400)
    payload = {"institution_code": institution_code, "key_seq": int(key_seq),
               "approver": approver}
    with tx() as conn:
        ensure_institution(conn, institution_code)
        replay = _stored_action(conn, request_key, payload)
        if replay:
            return replay
        rec = _rotation(conn, institution_code, int(key_seq))
        if rec is None:
            raise TrustError("轮换记录不存在", "ROTATION_NOT_FOUND", 404)
        if rec["status"] != "PROPOSED":
            raise TrustError(
                f"轮换 {key_seq} 已处于 {rec['status']}，批准请求不能再次改变状态",
                "ROTATION_NOT_PROPOSED", 409,
                {"key_seq": key_seq, "status": rec["status"],
                 "approved_by": rec["approved_by"]})
        at = now_iso()
        try:
            cur = conn.execute(
                "UPDATE relay_key_rotation SET status='APPROVED',approved_by=?,"
                "approved_at=? WHERE institution_code=? AND key_seq=? "
                "AND status='PROPOSED'",
                (approver, at, institution_code, key_seq))
        except sqlite3.IntegrityError as exc:
            raise TrustError("并发批准冲突：只有一个批准结果可生效",
                             "ROTATION_APPROVE_CONFLICT", 409) from exc
        if cur.rowcount != 1:
            raise TrustError("并发批准冲突：只有一个批准结果可生效",
                             "ROTATION_APPROVE_CONFLICT", 409)
        conn.execute(
            "UPDATE relay_institution_state SET updated_at=? WHERE institution_code=?",
            (now_iso(), institution_code))
        out = {"key_seq": key_seq, "status": "APPROVED",
               "approved_by": approver, "approved_at": at,
               "effective_watermark": rec["effective_watermark"]}
        audit(conn, "ROTATION_APPROVE",
              detail={"institution": institution_code, "key_seq": key_seq,
                      "approver": approver, "request_key": request_key})
        return _persist_admin_action(
            conn, request_key=request_key, code=institution_code,
            action_type="APPROVE", target_type="ROTATION",
            target_id=str(key_seq), payload=payload, status_code=200,
            response=out)


def activate_rotation(*, institution_code: str, key_seq: int | None = None,
                      request_key: str | None = None,
                      actor: str | None = None) -> dict:
    payload = {"institution_code": institution_code, "key_seq": key_seq,
               "actor": actor, "request_key": request_key}
    with tx() as conn:
        state = ensure_institution(conn, institution_code)
        if request_key:
            replay = _stored_action(conn, request_key, payload)
            if replay:
                return replay
        rec = conn.execute(
            "SELECT * FROM relay_key_rotation WHERE institution_code=? "
            "AND status='APPROVED' ORDER BY key_seq LIMIT 1",
            (institution_code,)).fetchone() if key_seq is None else _rotation(
            conn, institution_code, int(key_seq))
        if rec is None:
            raise TrustError("没有已批准待生效的轮换", "NO_APPROVED_ROTATION", 404)
        if rec["status"] == "ACTIVE":
            return {"key_seq": rec["key_seq"], "status": "ACTIVE",
                    "already_active": True}
        if rec["status"] != "APPROVED":
            raise TrustError(f"轮换状态为 {rec['status']}，不能生效",
                             "ROTATION_NOT_APPROVED", 409)
        if state["next_receipt_serial"] < rec["effective_watermark"]:
            raise TrustError(
                "尚未达到指定生效水位", "WATERMARK_NOT_REACHED", 409,
                {"key_seq": rec["key_seq"],
                 "next_receipt_serial": state["next_receipt_serial"],
                 "effective_watermark": rec["effective_watermark"]})
        activated = _auto_activate_due(conn, institution_code, state)
        out = {"key_seq": activated["key_seq"], "status": "ACTIVE",
               "activated_at": activated["activated_at"],
               "effective_watermark": activated["effective_watermark"],
               "record_hash": activated["record_hash"]}
        if request_key:
            out = _persist_admin_action(
                conn, request_key=request_key, code=institution_code,
                action_type="ACTIVATE", target_type="ROTATION",
                target_id=str(activated["key_seq"]), payload=payload,
                status_code=200, response=out)
        audit(conn, "ROTATION_MANUAL_ACTIVATE",
              detail={"institution": institution_code,
                      "key_seq": activated["key_seq"], "actor": actor})
        return out


def institution_trust_status(institution_code: str) -> dict:
    with tx() as conn:
        state = ensure_institution(conn, institution_code)
        recs = _public_rotation_records(conn, institution_code)
        open_rec = conn.execute(
            "SELECT * FROM relay_key_rotation WHERE institution_code=? "
            "AND status IN ('PROPOSED','APPROVED') ORDER BY key_seq",
            (institution_code,)).fetchall()
        rev = conn.execute(
            "SELECT * FROM relay_revocation_list WHERE institution_code=? "
            "ORDER BY version DESC LIMIT 1", (institution_code,)).fetchone()
        return {
            **{k: state[k] for k in state.keys()},
            "current_public_key": next(
                r["public_key"] for r in recs
                if r["key_seq"] == state["current_key_seq"]),
            "rotation_chain": recs,
            "open_rotation": dict(open_rec[0]) if open_rec else None,
            "latest_revocation": dict(rev) if rev else None,
        }


# ---------------------------------------------------------------------------
# 版本化撤销清单
# ---------------------------------------------------------------------------

def _entry_obj(*, receipt_id=None, receipt_serial=None, issued_from=None,
               issued_to=None, reason, revoked_by, revoked_at) -> dict:
    if not reason:
        raise TrustError("撤销原因 reason 必填", "BAD_REQUEST", 400)
    e = {"receipt_id": receipt_id, "receipt_serial": receipt_serial,
         "issued_from": issued_from, "issued_to": issued_to,
         "reason": reason, "revoked_by": revoked_by, "revoked_at": revoked_at}
    return e


def _entries_for_request(conn, code: str, *, receipt_ids, issued_from,
                         issued_to, reason, revoked_by, at) -> list[dict]:
    entries = []
    for rid in receipt_ids or []:
        row = conn.execute(
            "SELECT request_key,receipt_serial,issued_at FROM relay_receipt "
            "WHERE institution_code=? AND request_key=?", (code, rid)).fetchone()
        serial = row["receipt_serial"] if row else None
        entries.append(_entry_obj(
            receipt_id=rid, receipt_serial=serial, reason=reason,
            revoked_by=revoked_by, revoked_at=at))
    if issued_from or issued_to:
        try:
            start = _iso(issued_from) if issued_from else datetime.min.replace(
                tzinfo=timezone.utc)
            end = _iso(issued_to) if issued_to else datetime.max.replace(
                tzinfo=timezone.utc)
        except (TypeError, ValueError) as exc:
            raise TrustError("签发时间区间必须为 ISO-8601", "BAD_TIME_RANGE", 422) from exc
        if end < start:
            raise TrustError("issued_to 不能早于 issued_from",
                             "BAD_TIME_RANGE", 422)
        rows = conn.execute(
            "SELECT request_key,receipt_serial,issued_at FROM relay_receipt "
            "WHERE institution_code=? ORDER BY receipt_serial", (code,)).fetchall()
        for row in rows:
            ts = _iso(row["issued_at"])
            if start <= ts <= end:
                entries.append(_entry_obj(
                    receipt_id=row["request_key"],
                    receipt_serial=row["receipt_serial"], reason=reason,
                    revoked_by=revoked_by, revoked_at=at))
    return entries


def _current_revocation_entries(conn, code: str) -> list[dict]:
    row = conn.execute(
        "SELECT entries_json FROM relay_revocation_list WHERE institution_code=? "
        "ORDER BY version DESC LIMIT 1", (code,)).fetchone()
    return json.loads(row["entries_json"]) if row else []


def publish_revocation(*, institution_code: str, request_key: str,
                       receipt_ids: list[str] | None = None,
                       issued_from: str | None = None,
                       issued_to: str | None = None,
                       reason: str = "REVOKED",
                       published_by: str | None = None) -> dict:
    if not request_key:
        raise TrustError("request_key 必填", "BAD_REQUEST", 400)
    payload = {"institution_code": institution_code,
               "receipt_ids": sorted(receipt_ids or []),
               "issued_from": issued_from, "issued_to": issued_to,
               "reason": reason, "published_by": published_by}
    with tx() as conn:
        state = ensure_institution(conn, institution_code)
        replay = _stored_action(conn, request_key, payload)
        if replay:
            return replay
        at = now_iso()
        additions = _entries_for_request(
            conn, institution_code, receipt_ids=receipt_ids,
            issued_from=issued_from, issued_to=issued_to, reason=reason,
            revoked_by=published_by, at=at)
        if not additions:
            raise TrustError("撤销选择器未匹配任何回执，禁止发布空撤销清单",
                             "NO_REVOCATION_MATCH", 404)
        existing = _current_revocation_entries(conn, institution_code)
        index = {(e.get("receipt_id"), e.get("receipt_serial"),
                  e.get("issued_from"), e.get("issued_to"),
                  e.get("reason")): e for e in existing}
        added = []
        for e in additions:
            key = (e["receipt_id"], e["receipt_serial"], e["issued_from"],
                   e["issued_to"], e["reason"])
            if key not in index:
                existing.append(e)
                added.append(e)
        entries = sorted(existing, key=lambda e: (
            e.get("receipt_id") or "", e.get("receipt_serial") or 0,
            e.get("issued_from") or "", e.get("issued_to") or ""))
        entries_digest = crypto.revocation_entries_digest(entries)
        version = state["revocation_version"] + 1
        prev_hash = state["revocation_digest"]
        signed_obj = {"institution_code": institution_code,
                      "version": version, "entries": entries,
                      "previous_list_hash": prev_hash, "published_at": at}
        list_hash = crypto.revocation_list_hash(signed_obj, entries_digest)
        _auto_activate_due(conn, institution_code,
                           dict(conn.execute(
                               "SELECT * FROM relay_institution_state WHERE institution_code=?",
                               (institution_code,)).fetchone()))
        fresh_state = _institution_row(conn, institution_code)
        seed = crypto.load_institution_seed(
            institution_code, fresh_state["current_key_seq"])
        signature = crypto.sign_revocation_list(signed_obj, seed)
        conn.execute(
            "INSERT INTO relay_revocation_list(institution_code,version,"
            "entries_json,entries_digest,previous_list_hash,list_hash,"
            "signature,signing_key_seq,published_by,published_at)"
            " VALUES(?,?,?,?,?,?,?,?,?,?)",
            (institution_code, version, json.dumps(entries, ensure_ascii=False),
             entries_digest, prev_hash, list_hash, signature,
             fresh_state["current_key_seq"], published_by, at))
        for e in added:
            conn.execute(
                "INSERT INTO relay_revocation_entry(institution_code,version,"
                "receipt_id,receipt_serial,issued_from,issued_to,reason,"
                "revoked_by,revoked_at,entry_json) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (institution_code, version, e["receipt_id"], e["receipt_serial"],
                 e["issued_from"], e["issued_to"], e["reason"],
                 e["revoked_by"], e["revoked_at"],
                 json.dumps(e, ensure_ascii=False, default=str)))
        conn.execute(
            "UPDATE relay_institution_state SET revocation_version=?,"
            "revocation_digest=?,updated_at=? WHERE institution_code=?",
            (version, list_hash, now_iso(), institution_code))
        out = {"version": version, "entries": entries, "added": added,
               "entries_digest": entries_digest, "list_hash": list_hash,
               "previous_list_hash": prev_hash, "published_at": at,
               "signing_key_seq": fresh_state["current_key_seq"]}
        audit(conn, "REVOCATION_PUBLISH",
              detail={"institution": institution_code, "version": version,
                      "added": len(added), "request_key": request_key})
        return _persist_admin_action(
            conn, request_key=request_key, code=institution_code,
            action_type="REVOKE", target_type="REVOCATION",
            target_id=str(version), payload=payload, status_code=201,
            response=out)


def receipt_status(institution_code: str, receipt_id: str,
                   at: str | None = None) -> dict:
    with tx() as conn:
        state = ensure_institution(conn, institution_code)
        row = conn.execute(
            "SELECT * FROM relay_receipt WHERE institution_code=? AND request_key=?",
            (institution_code, receipt_id)).fetchone()
        if row is None:
            raise TrustError("回执不存在", "RECEIPT_NOT_FOUND", 404)
        entries = _current_revocation_entries(conn, institution_code)
        issued_at = row["issued_at"]
        revoked = None
        for e in entries:
            if e.get("receipt_id") == receipt_id:
                revoked = e
                break
            if e.get("issued_from") or e.get("issued_to"):
                try:
                    start = _iso(e["issued_from"]) if e.get("issued_from") else \
                        datetime.min.replace(tzinfo=timezone.utc)
                    end = _iso(e["issued_to"]) if e.get("issued_to") else \
                        datetime.max.replace(tzinfo=timezone.utc)
                    if start <= _iso(issued_at) <= end:
                        revoked = e
                        break
                except ValueError:
                    continue
        now_dt = _iso(at) if at else datetime.now(timezone.utc)
        return {"receipt_id": receipt_id,
                "receipt_serial": row["receipt_serial"],
                "issued_at": issued_at, "expires_at": row["expires_at"],
                "expired": now_dt >= _iso(row["expires_at"]),
                "signing_key_seq": row["signing_key_seq"],
                "status": "REVOKED" if revoked else (
                    "EXPIRED" if now_dt >= _iso(row["expires_at"]) else "VALID"),
                "revocation": revoked,
                "latest_revocation_version": state["revocation_version"]}


# ---------------------------------------------------------------------------
# 离线信任包
# ---------------------------------------------------------------------------

def _all_revocation_entries(conn, code: str) -> list[dict]:
    rows = conn.execute(
        "SELECT entry_json FROM relay_revocation_entry WHERE institution_code=? "
        "ORDER BY version,receipt_id,receipt_serial,issued_from,issued_to,reason",
        (code,)).fetchall()
    return [json.loads(r["entry_json"]) for r in rows]


def export_trust_package(*, institution_code: str, request_key: str,
                         ttl_seconds: int | None = None,
                         issued_by: str | None = None) -> dict:
    if not request_key:
        raise TrustError("request_key 必填", "BAD_REQUEST", 400)
    ttl = ttl_seconds if ttl_seconds is not None else config.TRUST_TTL_SECONDS
    payload = {"institution_code": institution_code, "request_key": request_key,
               "ttl_seconds": ttl, "issued_by": issued_by}
    with tx() as conn:
        state = ensure_institution(conn, institution_code)
        replay_row = conn.execute(
            "SELECT * FROM relay_trust_export WHERE request_key=?",
            (request_key,)).fetchone()
        if replay_row:
            pkg = json.loads(replay_row["package_json"])
            return {"replayed": True, "package": pkg}
        action_replay = _stored_action(conn, request_key, payload)
        if action_replay:
            return {"replayed": True, "package": action_replay["package"]}
        _auto_activate_due(conn, institution_code, state)
        state = _institution_row(conn, institution_code)
        version = state["trust_version"] + 1
        now_dt = datetime.now(timezone.utc)
        issued_at = now_iso()
        expires_at = (now_dt + timedelta(seconds=ttl)).strftime(
            "%Y-%m-%dT%H:%M:%S.") + f"{(now_dt + timedelta(seconds=ttl)).microsecond // 1000:03d}Z"
        records = _public_rotation_records(conn, institution_code)
        lists_rows = conn.execute(
            "SELECT institution_code,version,entries_json,entries_digest,"
            "previous_list_hash,list_hash,signature,signing_key_seq,"
            "published_by,published_at FROM relay_revocation_list "
            "WHERE institution_code=? ORDER BY version", (institution_code,)).fetchall()
        lists = []
        for r in lists_rows:
            d = dict(r)
            d["entries"] = json.loads(d.pop("entries_json"))
            lists.append(d)
        entries = _current_revocation_entries(conn, institution_code)
        rev_digest = state["revocation_digest"]
        body = {
            "format": crypto.TRUST_FORMAT,
            "institution_code": institution_code,
            "trust_version": version,
            "current_key_seq": state["current_key_seq"],
            "issued_at": issued_at,
            "expires_at": expires_at,
            "rotation_records": records,
            "revocation_lists": lists,
            "revocation_entries": entries,
            "revocation_digest": rev_digest,
            "previous_trust_digest": state["last_trust_digest"],
        }
        digest = crypto.sha256_hex(crypto.canonical(body))
        seed = crypto.load_institution_seed(
            institution_code, state["current_key_seq"])
        signature = crypto.sign_trust_body(body, seed)
        pub = next(r["public_key"] for r in records
                   if r["key_seq"] == state["current_key_seq"])
        package = {"body": body, "trust_digest": digest,
                   "signing_key_seq": state["current_key_seq"],
                   "signing_public_key": pub, "signature": signature}
        pkg_json = json.dumps(package, ensure_ascii=False, default=str)
        conn.execute(
            "INSERT INTO relay_trust_export(request_key,institution_code,"
            "trust_version,package_json,trust_digest,issued_at,expires_at,"
            "created_at) VALUES(?,?,?,?,?,?,?,?)",
            (request_key, institution_code, version, pkg_json, digest,
             issued_at, expires_at, now_iso()))
        conn.execute(
            "UPDATE relay_institution_state SET trust_version=?,"
            "previous_trust_digest=?,last_trust_digest=?,updated_at=? "
            "WHERE institution_code=?",
            (version, state["last_trust_digest"], digest, now_iso(),
             institution_code))
        audit(conn, "TRUST_EXPORT",
              detail={"institution": institution_code, "version": version,
                      "request_key": request_key})
        out = {"replayed": False, "package": package}
        return out


def _is_issuing_institution(conn, code: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM relay_receipt WHERE institution_code=? LIMIT 1",
        (code,)).fetchone()
    return row is not None or crypto.institution_seed_path(code, 0).exists()


# ---------------------------------------------------------------------------
# 信任包导入（离线核验端持久化最新信任锚）
# ---------------------------------------------------------------------------

def import_trust_package(package: dict, *, request_key: str | None = None,
                         at: str | None = None) -> dict:
    """先完全离线验包，再在单事务中持久化；低版本/回滚包不覆盖本地。"""
    from .verifier import verify_trust_package, ReceiptError
    try:
        report = verify_trust_package(package, now=at)
    except ReceiptError as exc:
        raise TrustError(str(exc), exc.code, 422,
                         {"problems": exc.problems}) from exc
    code = report["institution_code"]
    body = report and package["body"]
    digest = package["trust_digest"]
    with tx() as conn:
        row = _institution_row(conn, code, required=False)
        if row is None:
            _bootstrap_state_from_trust(conn, report)
            row = _institution_row(conn, code)
        else:
            if report["trust_version"] < row["trust_version"] and \
                    _is_issuing_institution(conn, code):
                raise TrustError(
                    "签发机构的信任包版本不能低于本地状态，疑似撤销/轮换清单回滚",
                    "TRUST_VERSION_ROLLED_BACK", 409,
                    {"local_version": row["trust_version"],
                     "package_version": report["trust_version"]})
        existing = conn.execute(
            "SELECT * FROM relay_trust_import WHERE institution_code=?",
            (code,)).fetchone()
        if existing:
            if existing["trust_version"] == report["trust_version"]:
                if existing["trust_digest"] != digest:
                    raise TrustError(
                        "同一信任版本绑定不同摘要", "TRUST_DIGEST_CONFLICT", 409)
                return {"replayed": True,
                        "trust_version": report["trust_version"],
                        "trust_digest": digest}
            if report["trust_version"] <= existing["trust_version"]:
                raise TrustError("信任包回滚，拒绝导入",
                                 "TRUST_VERSION_ROLLED_BACK", 409)
        _replace_trust_anchor(conn, report, package)
        out = {"replayed": False, "trust_version": report["trust_version"],
               "trust_digest": digest,
               "rotation_count": len(report["rotation_records"]),
               "revocation_version": report["latest_revocation_version"]}
        if request_key:
            out = _persist_admin_action(
                conn, request_key=request_key, code=code,
                action_type="TRUST_IMPORT", target_type="TRUST",
                target_id=str(report["trust_version"]),
                payload={"trust_digest": digest,
                         "trust_version": report["trust_version"],
                         "request_key": request_key},
                status_code=200, response=out)
        audit(conn, "TRUST_IMPORT",
              detail={"institution": code,
                      "version": report["trust_version"], "digest": digest})
        return out


def _bootstrap_state_from_trust(conn, report: dict):
    now = now_iso()
    records = report["rotation_records"]
    current = records[-1]
    max_wm = max([r.get("effective_watermark") or 0 for r in records] or [0])
    conn.execute(
        "INSERT INTO relay_institution_state(institution_code,title,"
        "current_key_seq,next_receipt_serial,revocation_version,trust_version,"
        "created_at,updated_at) VALUES(?,?,?,?,?,0,?,?)",
        (report["institution_code"], report["institution_code"],
         current["key_seq"], max(max_wm, 1),
         report["latest_revocation_version"], now, now))
    for rec in records:
        conn.execute(
        "INSERT INTO relay_key_rotation(institution_code,key_seq,"
        "public_key,effective_watermark,register_request_key,"
        "registered_by,registered_at,status,approved_by,approved_at,"
        "activated_at,previous_record_hash,record_hash,signature,"
        "new_key_self_signature)"
        " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (rec["institution_code"], rec["key_seq"], rec["public_key"],
         rec.get("effective_watermark"),
         rec.get("register_request_key", "GENESIS" if rec["key_seq"] == 0
                 else "IMPORTED"),
         rec.get("registered_by"), rec.get("registered_at"),
         rec["status"], rec.get("approved_by"), rec.get("approved_at"),
         rec.get("activated_at"), rec.get("previous_record_hash"),
         rec.get("record_hash"), rec.get("signature"),
         rec.get("new_key_self_signature")))


def _replace_trust_anchor(conn, report: dict, package: dict):
    code = report["institution_code"]
    body = package["body"]
    # 信任链只追加，不允许同 seq 覆盖成不同记录；不同历史可定位冲突。
    for rec in report["rotation_records"]:
        conn.execute(
            "INSERT INTO relay_key_rotation(institution_code,key_seq,"
            "public_key,effective_watermark,register_request_key,"
            "registered_by,registered_at,status,approved_by,approved_at,"
            "activated_at,previous_record_hash,record_hash,signature,"
            "new_key_self_signature)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(institution_code,key_seq) DO NOTHING",
            (rec["institution_code"], rec["key_seq"], rec["public_key"],
             rec.get("effective_watermark"),
             rec.get("register_request_key", "IMPORTED"),
             rec.get("registered_by"), rec.get("registered_at"),
             rec["status"], rec.get("approved_by"), rec.get("approved_at"),
             rec.get("activated_at"), rec.get("previous_record_hash"),
             rec.get("record_hash"), rec.get("signature"),
             rec.get("new_key_self_signature")))
    for item in report["revocation_lists"]:
        conn.execute(
            "INSERT INTO relay_revocation_list(institution_code,version,"
            "entries_json,entries_digest,previous_list_hash,list_hash,"
            "signature,signing_key_seq,published_by,published_at)"
            " VALUES(?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(institution_code,version) DO NOTHING",
            (code, item["version"],
             json.dumps(item["entries"], ensure_ascii=False),
             item["entries_digest"], item["previous_list_hash"],
             item["list_hash"], item["signature"], item["signing_key_seq"],
             item.get("published_by"), item["published_at"]))
    # 当前撤销集合来自最高版本；删除旧的导入展开项再按最新清单重建。
    conn.execute("DELETE FROM relay_revocation_entry WHERE institution_code=?",
                 (code,))
    for e in report["revocation_entries"]:
        conn.execute(
            "INSERT INTO relay_revocation_entry(institution_code,version,"
            "receipt_id,receipt_serial,issued_from,issued_to,reason,"
            "revoked_by,revoked_at,entry_json) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (code, report["latest_revocation_version"], e.get("receipt_id"),
             e.get("receipt_serial"), e.get("issued_from"), e.get("issued_to"),
             e.get("reason"), e.get("revoked_by"), e.get("revoked_at"),
             json.dumps(e, ensure_ascii=False, default=str)))
    current = report["rotation_records"][-1]
    latest_digest = report["revocation_digest"]
    conn.execute(
        "UPDATE relay_institution_state SET current_key_seq=?,"
        "revocation_version=?,revocation_digest=?,trust_version=?,"
        "previous_trust_digest=?,last_trust_digest=?,updated_at=? "
        "WHERE institution_code=?",
        (current["key_seq"], report["latest_revocation_version"],
         latest_digest, report["trust_version"],
         body.get("previous_trust_digest"), package["trust_digest"], now_iso(),
         code))
    conn.execute(
        "INSERT INTO relay_trust_import(institution_code,trust_version,"
        "trust_digest,previous_trust_digest,package_json,imported_at)"
        " VALUES(?,?,?,?,?,?) "
        "ON CONFLICT(institution_code) DO UPDATE SET "
        "trust_version=excluded.trust_version,trust_digest=excluded.trust_digest,"
        "previous_trust_digest=excluded.previous_trust_digest,"
        "package_json=excluded.package_json,imported_at=excluded.imported_at",
        (code, report["trust_version"], package["trust_digest"],
         body.get("previous_trust_digest"),
         json.dumps(package, ensure_ascii=False, default=str), now_iso()))
