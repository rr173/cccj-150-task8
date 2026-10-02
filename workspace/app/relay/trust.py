"""机构签发密钥轮换 / 回执撤销 / 离线信任包。

与事件中继同库（独立于主平台库），全部状态变更在 ``BEGIN IMMEDIATE``
串行写事务内完成，崩溃/重启/并发管理员都安全。

信任模型
--------
* 机构签发钥按**纪元（epoch）**组织：epoch 0 为机构创世钥（既有
  ``{code}.pub`` 引导），每次轮换登记下一把公钥，批准后旧钥对整条
  轮换记录签名，形成**连续签名链**（旧钥签新钥）。
* 生效判据是机构内单调的**回执序号水位** ``activate_serial``：
  旧钥签发的回执继续按旧钥验证；达到水位（下一个序号 >= 水位）后
  只能用新钥签发。
* 撤销清单版本化、只追加：每版是完整撤销条目集合，必须是上一版超集
  （防回滚），版本号单调，逐版带摘要链与生效钥签名。
* 离线信任包内含机构公钥链、全部撤销版本与单调包序号，由当前生效钥
  签名；导入后仅凭包即可离线定位拒绝：过期信任包、断链轮换、
  撤销回滚、已撤销回执。
"""
from __future__ import annotations

import json
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


# ---------------------------------------------------------------------------
# 内部工具
# ---------------------------------------------------------------------------

def _iso_ms(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def _rotation_public(conn, code: str, epoch: int) -> str:
    row = conn.execute(
        "SELECT public_key FROM relay_key_rotation WHERE institution_code=? "
        "AND epoch=?", (code, epoch)).fetchone()
    if row is None:
        raise TrustError(f"机构 {code} 缺少纪元 {epoch} 的公钥记录",
                         "KEY_EPOCH_NOT_FOUND", 409)
    return row["public_key"]


def _active_seed(code: str, epoch: int) -> bytes:
    """取某纪元私钥：优先归档文件 {code}.eN.seed；epoch 0 回退旧路径。"""
    p = crypto.epoch_seed_path(code, epoch)
    if p.exists():
        return bytes.fromhex(p.read_text(encoding="ascii").strip())
    if epoch == crypto.GENESIS_EPOCH:
        return crypto.load_institution_seed(code)
    raise TrustError(
        f"纪元 {epoch} 的签发私钥不在本节点（外部托管/HSM 模式无法代签）",
        "SIGNING_KEY_UNAVAILABLE", 409)


def _bootstrap_institution(conn, code: str) -> dict:
    """幂等引导机构：创世钥归档 + 纪元0链记录 + 撤销清单 v1 + 序号回填。

    机构行首次插入时一次性建立全部信任根；之后调用直接返回当前状态。
    """
    row = conn.execute(
        "SELECT * FROM relay_institution WHERE institution_code=?",
        (code,)).fetchone()
    if row is not None:
        return dict(row)

    now = now_iso()
    pubhex = crypto.load_institution_public(code)
    seed = crypto.load_institution_seed(code)
    config.ensure_dirs()
    # 创世钥归档（幂等；既有 {code}.seed/.pub 保持不动）
    sp, pp = crypto.epoch_seed_path(code, 0), crypto.epoch_pub_path(code, 0)
    if not sp.exists():
        sp.write_text(seed.hex(), encoding="ascii")
        sp.chmod(0o600)
    if not pp.exists():
        pp.write_text(pubhex, encoding="ascii")

    conn.execute(
        "INSERT INTO relay_institution(institution_code,active_epoch,"
        "next_serial,next_bundle_serial,created_at,updated_at)"
        " VALUES(?,?,?,?,?,?)",
        (code, 0, 1, 1, now, now))
    # 创世轮换记录（epoch 0，自举 PoP 与批准签章）
    pop = crypto.sign_pop(seed, code, 0, pubhex, 1)
    record = {
        "institution_code": code, "epoch": 0, "public_key": pubhex,
        "activate_serial": 1, "proposed_by": "__genesis__",
        "proposed_at": now, "pop_signature": pop,
        "prev_record_hash": None,
    }
    rh = crypto.rotation_record_hash(record)
    approval = crypto.sign_rotation_approval(rh, seed)
    conn.execute(
        "INSERT INTO relay_key_rotation(id,institution_code,epoch,public_key,"
        "activate_serial,proposed_by,approved_by,proposer_request_key,"
        "approver_request_key,pop_signature,approval_signature,record_hash,"
        "status,proposed_at,approved_at,activated_at)"
        " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (new_id("ROT"), code, 0, pubhex, 1, "__genesis__", "__genesis__",
         None, None, pop, approval, rh, "ACTIVE", now, now, now))

    # 撤销清单 v1（空集合，null 前驱），作为版本化撤销链的锚点
    _publish_revocation_in_tx(conn, code, entries=[], request_key=None,
                              note="genesis", signer_epoch=0, seed=seed,
                              published_at=now)

    # 既有回执序号回填（按签发顺序），全部视作创世钥签发
    olds = conn.execute(
        "SELECT request_key FROM relay_receipt WHERE institution_code=? "
        "ORDER BY issued_at, rowid", (code,)).fetchall()
    serial = 1
    for r in olds:
        conn.execute(
            "UPDATE relay_receipt SET serial_no=?, signer_epoch=COALESCE("
            "signer_epoch,0) WHERE request_key=? AND serial_no IS NULL",
            (serial, r["request_key"]))
        serial += 1
    conn.execute(
        "UPDATE relay_institution SET next_serial=?, updated_at=? "
        "WHERE institution_code=?", (serial, now, code))
    audit(conn, "INSTITUTION_BOOTSTRAP", detail={
        "institution": code, "backfilled_receipts": serial - 1})
    return dict(conn.execute(
        "SELECT * FROM relay_institution WHERE institution_code=?",
        (code,)).fetchone())


def _publish_revocation_in_tx(conn, code: str, *, entries: list[dict],
                              request_key: str | None, note: str | None,
                              signer_epoch: int, seed: bytes,
                              published_at: str) -> dict:
    prev = conn.execute(
        "SELECT version,digest FROM relay_revocation WHERE institution_code=? "
        "ORDER BY version DESC LIMIT 1", (code,)).fetchone()
    version = (prev["version"] + 1) if prev else 1
    prev_digest = prev["digest"] if prev else None
    obj = {"institution_code": code, "version": version,
           "prev_digest": prev_digest, "entries": entries,
           "published_at": published_at}
    digest = crypto.revocation_digest(obj)
    signature = crypto.sign_revocation(digest, seed)
    conn.execute(
        "INSERT INTO relay_revocation(institution_code,version,request_key,"
        "entries_json,entry_count,prev_digest,digest,signer_epoch,signature,"
        "published_at,note) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
        (code, version, request_key,
         json.dumps(entries, ensure_ascii=False), len(entries),
         prev_digest, digest, signer_epoch, signature, published_at, note))
    return {"version": version, "digest": digest, "prev_digest": prev_digest,
            "signature": signature, "signer_epoch": signer_epoch,
            "entry_count": len(entries), "published_at": published_at}


def _latest_revocation_entries(conn, code: str) -> list[dict]:
    row = conn.execute(
        "SELECT entries_json FROM relay_revocation WHERE institution_code=? "
        "ORDER BY version DESC LIMIT 1", (code,)).fetchone()
    return json.loads(row["entries_json"]) if row else []


def _activate_due(conn, code: str, inst: dict) -> dict:
    """把已批准且水位已到的轮换幂等切到 ACTIVE；重启/重入不重复切换。

    返回 (possibly updated) inst 字典。切换顺序严格按纪元，
    激活时归档的旧钥/新钥记录都已在提案阶段固化，只有状态列变化。
    """
    due = conn.execute(
        "SELECT * FROM relay_key_rotation WHERE institution_code=? "
        "AND status='APPROVED' AND activate_serial<=? ORDER BY epoch",
        (code, inst["next_serial"])).fetchall()
    for r in due:
        now = now_iso()
        # 状态条件兜底：并发/重入下只有一次 UPDATE 生效
        cur = conn.execute(
            "UPDATE relay_key_rotation SET status='ACTIVE', activated_at=? "
            "WHERE institution_code=? AND epoch=? AND status='APPROVED'",
            (now, code, r["epoch"]))
        if cur.rowcount:
            conn.execute(
                "UPDATE relay_institution SET active_epoch=?, updated_at=? "
                "WHERE institution_code=?", (r["epoch"], now, code))
            inst["active_epoch"] = r["epoch"]
            audit(conn, "ROTATION_ACTIVATED", detail={
                "institution": code, "epoch": r["epoch"],
                "activate_serial": r["activate_serial"]})
    return inst


# ---------------------------------------------------------------------------
# 密钥轮换：预演 / 登记 / 批准 / 生效
# ---------------------------------------------------------------------------

def rotation_preview(code: str, *, activate_serial: int | None = None,
                     next_public_key: str | None = None) -> dict:
    """只读轮换预演：不落任何状态。给出当前纪元、建议水位、生效预测。"""
    with tx() as conn:
        inst = _bootstrap_institution(conn, code)
        inst = _activate_due(conn, code, inst)
        pending = conn.execute(
            "SELECT * FROM relay_key_rotation WHERE institution_code=? "
            "AND status IN ('PROPOSED','APPROVED') ORDER BY epoch",
            (code,)).fetchone()
        chain = conn.execute(
            "SELECT epoch,activate_serial,status FROM relay_key_rotation "
            "WHERE institution_code=? ORDER BY epoch", (code,)).fetchall()
        next_serial = inst["next_serial"]
        suggested = activate_serial or next_serial
        active_pub = _rotation_public(conn, code, inst["active_epoch"])
        effect = "IMMEDIATE" if suggested <= next_serial else "DEFERRED"
        would_sign_old = max(0, suggested - next_serial)
        return {
            "institution_code": code,
            "active_epoch": inst["active_epoch"],
            "active_public_key": active_pub,
            "next_serial": next_serial,
            "pending_epoch": pending["epoch"] if pending else None,
            "pending_status": pending["status"] if pending else None,
            "suggested_activate_serial": suggested,
            "projected_new_epoch": (inst["active_epoch"] + 1)
            if not pending else pending["epoch"],
            "effect": effect,
            "receipts_still_signed_by_old_key": would_sign_old,
            "note": ("达到水位前签发的回执仍由旧钥验证；自序号 "
                     f"{suggested} 起只能用新钥签发"),
            "chain": [dict(r) for r in chain],
            "next_public_key_preview": next_public_key,
        }


def propose_rotation(code: str, *, request_key: str, proposed_by: str,
                     activate_serial: int,
                     next_public_key: str | None = None,
                     next_seed_hex: str | None = None,
                     pop_signature: str | None = None) -> dict:
    """管理员登记下一把公钥与生效水位（幂等请求键）。

    三种供钥方式：
    * ``next_seed_hex``：直接给新钥种子（演示/单机构部署，服务端托管）；
    * ``next_public_key`` + ``pop_signature``：外部生成钥，新钥对挑战签名；
    * 仅 ``next_public_key`` 且其对应种子已由运维放置（少用）。
    """
    if not request_key or not proposed_by:
        raise TrustError("request_key/proposed_by 必填", "BAD_REQUEST", 400)
    try:
        activate_serial = int(activate_serial)
    except (TypeError, ValueError):
        raise TrustError("activate_serial 必须为整数", "BAD_REQUEST", 400)

    with tx() as conn:
        inst = _bootstrap_institution(conn, code)

        # 幂等：同一登记请求键永远返回首次结果
        dup = conn.execute(
            "SELECT * FROM relay_key_rotation WHERE proposer_request_key=?",
            (request_key,)).fetchone()
        if dup:
            return _rotation_result(conn, dup, replayed=True,
                                    note="同键重放登记")

        inst = _activate_due(conn, code, inst)
        pending = conn.execute(
            "SELECT * FROM relay_key_rotation WHERE institution_code=? "
            "AND status IN ('PROPOSED','APPROVED') ORDER BY epoch",
            (code,)).fetchone()
        if pending:
            raise TrustError(
                "已有未生效轮换，必须先批准/生效/驳回后才能登记新轮换",
                "PENDING_ROTATION_EXISTS", 409,
                {"rotation_id": pending["id"], "epoch": pending["epoch"],
                 "status": pending["status"],
                 "activate_serial": pending["activate_serial"]})

        if activate_serial < inst["next_serial"]:
            raise TrustError(
                f"生效水位 {activate_serial} 已越过当前序号 "
                f"{inst['next_serial']}（轮换不可追溯，防止回退重签）",
                "ACTIVATE_SERIAL_IN_PAST", 400,
                {"next_serial": inst["next_serial"]})

        # 解析新钥
        if next_seed_hex:
            try:
                nseed = bytes.fromhex(next_seed_hex)
                next_public_key = ed25519.public_key_from_seed(nseed).hex()
            except (ValueError, TypeError) as exc:
                raise TrustError(f"next_seed_hex 非法: {exc}",
                                 "BAD_REQUEST", 400)
        if not next_public_key:
            nseed, next_public_key = crypto.generate_next_keypair()
            next_seed_hex = nseed.hex()
        try:
            bytes.fromhex(next_public_key)
        except ValueError:
            raise TrustError("next_public_key 必须是 hex", "BAD_REQUEST", 400)

        # 新钥不得等于任何历史纪元公钥（密钥必须真正轮换）
        if conn.execute(
                "SELECT epoch FROM relay_key_rotation WHERE institution_code=?"
                " AND public_key=?", (code, next_public_key)).fetchone():
            raise TrustError("下一把公钥与既有纪元公钥相同",
                             "PUBLIC_KEY_NOT_ROTATED", 400)

        new_epoch = conn.execute(
            "SELECT COALESCE(MAX(epoch),0)+1 m FROM relay_key_rotation WHERE "
            "institution_code=?", (code,)).fetchone()["m"]

        # PoP：持有种子则直接签；否则必须提供外部 PoP 并校验
        if next_seed_hex:
            nseed = bytes.fromhex(next_seed_hex)
            derived = ed25519.public_key_from_seed(nseed).hex()
            if derived != next_public_key:
                raise TrustError("next_seed_hex 与 next_public_key 不匹配",
                                 "BAD_REQUEST", 400)
            pop = crypto.sign_pop(nseed, code, new_epoch,
                                  next_public_key, activate_serial)
        else:
            pop = pop_signature
            if not pop or not crypto.verify_pop(
                    code, new_epoch, next_public_key, activate_serial, pop):
                raise TrustError(
                    "外部公钥必须附带对轮换挑战的有效新钥签名（PoP）",
                    "POP_SIGNATURE_INVALID", 400)

        now = now_iso()
        prev_hash = conn.execute(
            "SELECT record_hash FROM relay_key_rotation WHERE "
            "institution_code=? ORDER BY epoch DESC LIMIT 1",
            (code,)).fetchone()["record_hash"]
        record = {
            "institution_code": code, "epoch": new_epoch,
            "public_key": next_public_key,
            "activate_serial": activate_serial,
            "proposed_by": proposed_by, "proposed_at": now,
            "pop_signature": pop, "prev_record_hash": prev_hash,
        }
        rh = crypto.rotation_record_hash(record)
        rid = new_id("ROT")
        # 托管种子立即固化到 0600 文件（提案即不可变；批准/崩溃后都可用）
        if next_seed_hex:
            sp = crypto.epoch_seed_path(code, new_epoch)
            if not sp.exists():
                sp.write_text(bytes.fromhex(next_seed_hex).hex(),
                              encoding="ascii")
                sp.chmod(0o600)
            pp = crypto.epoch_pub_path(code, new_epoch)
            if not pp.exists():
                pp.write_text(next_public_key, encoding="ascii")
        try:
            conn.execute(
                "INSERT INTO relay_key_rotation(id,institution_code,epoch,"
                "public_key,activate_serial,proposed_by,proposer_request_key,"
                "pop_signature,record_hash,status,proposed_at)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (rid, code, new_epoch, next_public_key, activate_serial,
                 proposed_by, request_key, pop, rh, "PROPOSED", now))
        except _integrity() as exc:
            # 部分唯一索引：并发登记只有一条胜出
            raise TrustError(
                "并发登记冲突：已有未生效轮换生效",
                "PENDING_ROTATION_EXISTS", 409) from exc
        audit(conn, "ROTATION_PROPOSED", detail={
            "institution": code, "epoch": new_epoch,
            "activate_serial": activate_serial, "by": proposed_by,
            "request_key": request_key})
        row = conn.execute(
            "SELECT * FROM relay_key_rotation WHERE id=?", (rid,)).fetchone()
        return _rotation_result(conn, row, replayed=False,
                                next_seed_hex=next_seed_hex)


def approve_rotation(code: str, *, request_key: str, approved_by: str,
                     epoch: int | None = None,
                     rotation_id: str | None = None) -> dict:
    """第二位管理员批准待决轮换（幂等批准键；并发只有一个结果生效）。"""
    if not request_key or not approved_by:
        raise TrustError("request_key/approved_by 必填", "BAD_REQUEST", 400)
    with tx() as conn:
        _bootstrap_institution(conn, code)

        dup = conn.execute(
            "SELECT * FROM relay_key_rotation WHERE approver_request_key=?",
            (request_key,)).fetchone()
        if dup:
            return _rotation_result(conn, dup, replayed=True,
                                    note="同键重放批准")

        row = _find_pending(conn, code, epoch, rotation_id)
        if row is None:
            # 可能已被并发批准/生效：查目标轮换最新结果便于定位
            if rotation_id:
                done = conn.execute(
                    "SELECT * FROM relay_key_rotation WHERE institution_code=? "
                    "AND id=?", (code, rotation_id)).fetchone()
            elif epoch is not None:
                done = conn.execute(
                    "SELECT * FROM relay_key_rotation WHERE institution_code=?"
                    " AND epoch=?", (code, epoch)).fetchone()
            else:
                done = conn.execute(
                    "SELECT * FROM relay_key_rotation WHERE institution_code=?"
                    " ORDER BY epoch DESC LIMIT 1", (code,)).fetchone()
            if done is not None and done["status"] in ("APPROVED", "ACTIVE"):
                raise TrustError(
                    f"轮换纪元 {done['epoch']} 已被 {done['approved_by']} "
                    f"批准（{done['status']}），并发批准只有一个结果生效",
                    "APPROVAL_RACE", 409,
                    {"epoch": done["epoch"], "status": done["status"],
                     "approved_by": done["approved_by"],
                     "approver_request_key": done["approver_request_key"]})
            raise TrustError("没有待批准的轮换", "NO_PENDING_ROTATION", 409,
                             {"last_epoch": done["epoch"] if done else None,
                              "last_status": done["status"] if done else None})
        if row["status"] != "PROPOSED":
            # 另一管理员（不同批准键）已赢：并发批准只有一个结果生效
            raise TrustError(
                f"轮换纪元 {row['epoch']} 已被 {row['approved_by']} "
                f"批准（{row['status']}），并发批准只有一个结果生效",
                "APPROVAL_RACE", 409,
                {"epoch": row["epoch"], "status": row["status"],
                 "approved_by": row["approved_by"],
                 "approver_request_key": row["approver_request_key"]})
        if approved_by == row["proposed_by"]:
            raise TrustError(
                "登记人与批准人必须是两名不同管理员（双人控制）",
                "APPROVER_MUST_DIFFER", 400,
                {"proposed_by": row["proposed_by"]})

        # 旧钥对整条记录签名（新钥信任由旧钥背书）
        inst = dict(conn.execute(
            "SELECT * FROM relay_institution WHERE institution_code=?",
            (code,)).fetchone())
        signer_epoch = row["epoch"] - 1
        seed = _active_seed(code, signer_epoch)
        approval = crypto.sign_rotation_approval(row["record_hash"], seed)
        now = now_iso()
        cur = conn.execute(
            "UPDATE relay_key_rotation SET status='APPROVED', approved_by=?,"
            "approver_request_key=?,approval_signature=?,approved_at=? "
            "WHERE id=? AND status='PROPOSED'",
            (approved_by, request_key, approval, now, row["id"]))
        if cur.rowcount == 0:
            # 并发批准：另一个请求键已赢
            winner = conn.execute(
                "SELECT * FROM relay_key_rotation WHERE id=?",
                (row["id"],)).fetchone()
            raise TrustError(
                "并发批准：已有另一位管理员的批准生效",
                "APPROVAL_RACE", 409,
                {"epoch": winner["epoch"], "status": winner["status"],
                 "approved_by": winner["approved_by"]})
        audit(conn, "ROTATION_APPROVED", detail={
            "institution": code, "epoch": row["epoch"],
            "by": approved_by, "request_key": request_key})
        # 批准后立即尝试生效（批准时水位可能已到）
        inst = _activate_due(conn, code, inst)
        out = _rotation_result(
            conn, conn.execute(
                "SELECT * FROM relay_key_rotation WHERE id=?",
                (row["id"],)).fetchone(), replayed=False)
        return out


def activate_rotation(code: str, *, epoch: int | None = None,
                      rotation_id: str | None = None) -> dict:
    """手动触发生效检查（通常签发回执时自动触发；预演/恢复场景使用）。"""
    with tx() as conn:
        inst = _bootstrap_institution(conn, code)
        row = _find_pending(conn, code, epoch, rotation_id)
        before = inst["active_epoch"]
        inst = _activate_due(conn, code, inst)
        if row is None:
            raise TrustError("没有待生效的已批准轮换",
                             "NO_APPROVED_ROTATION", 409)
        refreshed = conn.execute(
            "SELECT * FROM relay_key_rotation WHERE id=?",
            (row["id"],)).fetchone()
        return {**_rotation_result(conn, refreshed),
                "switched": inst["active_epoch"] != before,
                "next_serial": inst["next_serial"]}


def _find_pending(conn, code, epoch, rotation_id):
    if rotation_id:
        return conn.execute(
            "SELECT * FROM relay_key_rotation WHERE institution_code=? AND id=?",
            (code, rotation_id)).fetchone()
    if epoch is not None:
        return conn.execute(
            "SELECT * FROM relay_key_rotation WHERE institution_code=? "
            "AND epoch=? AND status IN ('PROPOSED','APPROVED')",
            (code, epoch)).fetchone()
    return conn.execute(
        "SELECT * FROM relay_key_rotation WHERE institution_code=? "
        "AND status IN ('PROPOSED','APPROVED') ORDER BY epoch LIMIT 1",
        (code,)).fetchone()


def _rotation_result(conn, row, *, replayed=False, note=None,
                     next_seed_hex=None) -> dict:
    d = dict(row)
    out = {"replayed": replayed, "rotation": {
        "rotation_id": d["id"], "institution_code": d["institution_code"],
        "epoch": d["epoch"], "public_key": d["public_key"],
        "activate_serial": d["activate_serial"], "status": d["status"],
        "proposed_by": d["proposed_by"], "approved_by": d["approved_by"],
        "proposer_request_key": d["proposer_request_key"],
        "approver_request_key": d["approver_request_key"],
        "pop_signature": d["pop_signature"],
        "approval_signature": d["approval_signature"],
        "record_hash": d["record_hash"],
        "proposed_at": d["proposed_at"], "approved_at": d["approved_at"],
        "activated_at": d["activated_at"]}}
    if note:
        out["note"] = note
    # 服务端托管种子只在**首次登记响应**中回传一次（运维须立即离线保管）
    if next_seed_hex:
        out["next_seed_hex"] = next_seed_hex
        out["seed_warning"] = "新钥种子仅本次返回并已写入服务端 0600 密钥目录"
    return out


def list_rotations(code: str) -> dict:
    with tx() as conn:
        inst = _bootstrap_institution(conn, code)
        inst = _activate_due(conn, code, inst)
        rows = conn.execute(
            "SELECT * FROM relay_key_rotation WHERE institution_code=? "
            "ORDER BY epoch", (code,)).fetchall()
        return {"institution_code": code,
                "active_epoch": inst["active_epoch"],
                "next_serial": inst["next_serial"],
                "rotations": [dict(r) for r in rows]}


def _integrity():
    import sqlite3
    return sqlite3.IntegrityError


# ---------------------------------------------------------------------------
# 签发上下文（供 service.export_receipt 在同一事务内调用）
# ---------------------------------------------------------------------------

def signing_context_in_tx(conn, code: str) -> dict:
    """在回执导出事务内：引导 -> 幂等生效 -> 分配单调序号 -> 取签发钥。"""
    inst = _bootstrap_institution(conn, code)
    inst = _activate_due(conn, code, inst)
    serial = inst["next_serial"]
    now = now_iso()
    conn.execute(
        "UPDATE relay_institution SET next_serial=?, updated_at=? "
        "WHERE institution_code=?", (serial + 1, now, code))
    epoch = inst["active_epoch"]
    seed = _active_seed(code, epoch)
    return {"serial": serial, "epoch": epoch, "seed": seed}


# ---------------------------------------------------------------------------
# 版本化撤销清单
# ---------------------------------------------------------------------------

def _canon_entry(e: dict) -> str:
    return crypto.canonical(e).hex()


def publish_revocation(code: str, *, request_key: str,
                       receipts: list[str] | None = None,
                       entries: list[dict] | None = None,
                       time_range: dict | None = None,
                       note: str | None = None) -> dict:
    """发布新版撤销清单（完整集合只追加；同键重放返回首版）。

    选择方式（可组合，最终取并集）：
    * ``receipts``：按回执请求键撤销整包；
    * ``entries``：显式细粒度条目 ``{sender_id?, session_id, revision}``；
    * ``time_range``：``{issued_from?, issued_to?}`` 撤销区间内签发的回执。
    """
    if not request_key:
        raise TrustError("request_key 必填", "BAD_REQUEST", 400)
    with tx() as conn:
        inst = _bootstrap_institution(conn, code)

        dup = conn.execute(
            "SELECT * FROM relay_revocation WHERE request_key=?",
            (request_key,)).fetchone()
        if dup:
            return {"replayed": True,
                    "revocation": _revocation_dict(dup)}

        inst = _activate_due(conn, code, inst)
        selected: dict[str, dict] = {}
        for e in _latest_revocation_entries(conn, code):
            selected[_canon_entry(e)] = e

        added: list[dict] = []

        def add(e: dict):
            e = {k: v for k, v in e.items() if v is not None}
            k = _canon_entry(e)
            if k not in selected:
                selected[k] = e
                added.append(e)

        for rk in receipts or []:
            add({"receipt_request_key": rk})
        for e in entries or []:
            if not isinstance(e, dict):
                raise TrustError("entries 必须是对象数组", "BAD_REQUEST", 400)
            add(dict(e))
        tr = time_range or {}
        if tr.get("issued_from") or tr.get("issued_to"):
            sql = ("SELECT request_key FROM relay_receipt "
                   "WHERE institution_code=?")
            args: list = [code]
            if tr.get("issued_from"):
                sql += " AND issued_at>=?"
                args.append(tr["issued_from"])
            if tr.get("issued_to"):
                sql += " AND issued_at<=?"
                args.append(tr["issued_to"])
            for r in conn.execute(sql, args).fetchall():
                add({"receipt_request_key": r["request_key"]})

        full = sorted(selected.values(),
                      key=lambda e: crypto.canonical(e).hex())
        seed = _active_seed(code, inst["active_epoch"])
        res = _publish_revocation_in_tx(
            conn, code, entries=full, request_key=request_key, note=note,
            signer_epoch=inst["active_epoch"], seed=seed,
            published_at=now_iso())
        audit(conn, "REVOCATION_PUBLISHED", detail={
            "institution": code, "version": res["version"],
            "added": len(added), "total": len(full),
            "request_key": request_key})
        return {"replayed": False, "revocation": res, "added_entries": added,
                "total_entries": len(full)}


def _revocation_dict(row) -> dict:
    d = dict(row)
    d["entries"] = json.loads(d.pop("entries_json"))
    return d


def list_revocations(code: str) -> dict:
    with tx() as conn:
        _bootstrap_institution(conn, code)
        rows = conn.execute(
            "SELECT institution_code,version,request_key,entries_json,"
            "entry_count,prev_digest,digest,signer_epoch,signature,"
            "published_at,note FROM relay_revocation WHERE "
            "institution_code=? ORDER BY version", (code,)).fetchall()
        versions = [_revocation_dict(r) for r in rows]
        return {"institution_code": code,
                "latest_version": versions[-1]["version"] if versions else 0,
                "versions": versions}


# ---------------------------------------------------------------------------
# 离线信任包导出 / 导入
# ---------------------------------------------------------------------------

def _key_chain_payload(conn, code: str) -> list[dict]:
    rows = conn.execute(
        "SELECT epoch,public_key,activate_serial,status,proposed_by,"
        "approved_by,record_hash,pop_signature,approval_signature,"
        "proposed_at,approved_at,activated_at FROM relay_key_rotation "
        "WHERE institution_code=? AND status IN ('APPROVED','ACTIVE') "
        "ORDER BY epoch", (code,)).fetchall()
    out = []
    prev = None
    for r in rows:
        d = dict(r)
        d["prev_record_hash"] = prev
        out.append(d)
        prev = r["record_hash"]
    return out


def _revocation_payload(conn, code: str) -> list[dict]:
    rows = conn.execute(
        "SELECT institution_code,version,prev_digest,digest,entries_json,"
        "published_at,signer_epoch,signature FROM relay_revocation WHERE "
        "institution_code=? ORDER BY version", (code,)).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["entries"] = json.loads(d.pop("entries_json"))
        out.append(d)
    return out


def export_trust_bundle(code: str, *, request_key: str,
                       ttl_seconds: int | None = None,
                       institution_title: str | None = None) -> dict:
    """导出离线信任包（公钥链 + 全量撤销版本 + 单调包序号），同键重放原包。"""
    if not request_key:
        raise TrustError("request_key 必填", "BAD_REQUEST", 400)
    init_db()
    ttl = (ttl_seconds if ttl_seconds is not None
           else config.TRUST_BUNDLE_TTL_SECONDS)
    with tx() as conn:
        inst = _bootstrap_institution(conn, code)
        inst = _activate_due(conn, code, inst)

        # 导出请求键幂等：持久化映射
        saved = conn.execute(
            "SELECT package_json FROM relay_trust_export WHERE request_key=?",
            (request_key,)).fetchone()
        if saved:
            pkg = json.loads(saved["package_json"])
            if pkg["body"]["institution_code"] != code:
                raise TrustError("请求键已绑定其他机构",
                                 "REQUEST_KEY_CONFLICT", 409)
            return {"replayed": True, "package": pkg}

        chain = _key_chain_payload(conn, code)
        revs = _revocation_payload(conn, code)
        serial = inst["next_bundle_serial"]
        now_dt = datetime.now(timezone.utc)
        issued_at = _iso_ms(now_dt)
        expires_at = _iso_ms(now_dt + timedelta(seconds=ttl))
        body = {
            "format": crypto.TRUST_BUNDLE_FORMAT,
            "bundle_serial": serial,
            "institution_code": code,
            "institution_title": institution_title or code,
            "root_epoch": crypto.GENESIS_EPOCH,
            "key_chain": chain,
            "revocation_versions": revs,
            "issued_at": issued_at,
            "expires_at": expires_at,
        }
        seed = _active_seed(code, inst["active_epoch"])
        signature = crypto.sign_trust_bundle(body, seed)
        signer_public_key = _rotation_public(conn, code, inst["active_epoch"])
        package = {"body": body, "signer_epoch": inst["active_epoch"],
                   "signer_public_key": signer_public_key,
                   "signature": signature}
        now = now_iso()
        conn.execute(
            "UPDATE relay_institution SET next_bundle_serial=?, updated_at=? "
            "WHERE institution_code=?", (serial + 1, now, code))
        conn.execute(
            "INSERT INTO relay_trust_export(request_key,institution_code,"
            "bundle_serial,package_json,created_at) VALUES(?,?,?,?,?)",
            (request_key, code, serial,
             json.dumps(package, ensure_ascii=False, default=str), now))
        audit(conn, "TRUST_BUNDLE_EXPORT", detail={
            "institution": code, "bundle_serial": serial,
            "active_epoch": inst["active_epoch"],
            "revocation_versions": len(revs),
            "request_key": request_key})
        return {"replayed": False, "package": package}


def _parse_dt(v: str) -> datetime:
    return datetime.fromisoformat(v.replace("Z", "+00:00"))


def import_trust_bundle(package: dict, *, at: str | None = None) -> dict:
    """核验并导入离线信任包（重导同序号同内容幂等；异内容 409）。"""
    from .verifier import verify_trust_bundle, TrustBundleError
    try:
        # 导入新信任锚时过期包同样拒绝（必须重新获取未过期包）；
        # 已导入的旧包到期不影响落库记录，在线核验会标 TRUST_EXPIRED。
        report = verify_trust_bundle(package, now=at)
    except TrustBundleError as exc:
        return {"imported": False, "code": exc.code,
                "message": str(exc), "problems": exc.problems}
    body = package["body"]
    code = body["institution_code"]
    serial = body["bundle_serial"]
    blob = json.dumps(package, ensure_ascii=False, default=str,
                      sort_keys=True)
    with tx() as conn:
        prev = conn.execute(
            "SELECT bundle_json FROM relay_trust_import WHERE "
            "institution_code=? AND bundle_serial=?", (code, serial)).fetchone()
        if prev:
            old = json.dumps(json.loads(prev["bundle_json"]),
                             ensure_ascii=False, sort_keys=True)
            if old != blob:
                raise TrustError(
                    f"机构 {code} 信任包序号 {serial} 已绑定不同内容（回滚/伪造）",
                    "TRUST_SERIAL_CONFLICT", 409,
                    {"bundle_serial": serial})
            return {"replayed": True, "imported": True,
                    "institution_code": code, "bundle_serial": serial,
                    "active_epoch": report["active_epoch"],
                    "revocation_version": report["revocation_version"]}
        conn.execute(
            "INSERT INTO relay_trust_import(institution_code,bundle_serial,"
            "bundle_json,active_epoch,revocation_version,imported_at)"
            " VALUES(?,?,?,?,?,?)",
            (code, serial, json.dumps(package, ensure_ascii=False, default=str),
             report["active_epoch"], report["revocation_version"], now_iso()))
        audit(conn, "TRUST_BUNDLE_IMPORT", detail={
            "institution": code, "bundle_serial": serial,
            "active_epoch": report["active_epoch"],
            "revocation_version": report["revocation_version"]})
        return {"replayed": False, "imported": True,
                "institution_code": code, "bundle_serial": serial,
                "active_epoch": report["active_epoch"],
                "revocation_version": report["revocation_version"]}


def list_trust_imports(code: str | None = None) -> dict:
    with tx() as conn:
        sql = ("SELECT institution_code,bundle_serial,active_epoch,"
               "revocation_version,imported_at FROM relay_trust_import")
        args = ()
        if code:
            sql += " WHERE institution_code=?"
            args = (code,)
        sql += " ORDER BY institution_code,bundle_serial"
        return {"imports": [dict(r) for r in conn.execute(sql, args)]}


def init_db():
    from .store import init_relay_db
    init_relay_db()


# ---------------------------------------------------------------------------
# 回执状态定位（在线：本地信任根或已导入信任包）
# ---------------------------------------------------------------------------

def receipt_status(package: dict, *, at: str | None = None,
                   institution_code: str | None = None) -> dict:
    """按机构当前/导入信任根定位单张回执：VALID/REVOKED/过期/断链均可定位。"""
    from .verifier import (verify_receipt_package, verify_trust_bundle,
                           ReceiptError, TrustBundleError,
                           check_receipt_against_trust)
    # 先做回执自身离线核验（签章按包内嵌公钥、链、有效期）
    try:
        verify_receipt_package(package, now=at)
        standalone = True
        problems = []
    except ReceiptError as exc:
        standalone = False
        problems = exc.problems
        # 过期包仍继续做撤销/信任判定（状态要可定位），结构性错误直接返回
        if not all(p.get("code") in ("RECEIPT_EXPIRED",) for p in problems):
            return {"status": "INVALID", "code": exc.code,
                    "problems": problems}

    body = package["body"]
    code = institution_code or body.get("institution_code")
    bundle = _latest_bundle(code)
    if bundle is None:
        # 无可用信任包：退回独立核验结论
        return {"status": "EXPIRED" if not standalone else "VALID",
                "trust_anchor": "SELF_EMBEDDED",
                "institution_code": code,
                "problems": problems,
                "note": "本地无该机构信任包，仅按回执内嵌公钥独立核验"}

    try:
        trust = verify_trust_bundle(bundle, now=at)
    except TrustBundleError as exc:
        return {"status": "TRUST_INVALID", "code": exc.code,
                "problems": exc.problems,
                "institution_code": code}
    decision = check_receipt_against_trust(package, bundle, now=at)
    decision["trust_anchor"] = "TRUST_BUNDLE"
    decision["trust_bundle_serial"] = bundle["body"]["bundle_serial"]
    decision["standalone_verify"] = standalone
    return decision


def _latest_bundle(code: str) -> dict | None:
    with tx() as conn:
        row = conn.execute(
            "SELECT bundle_json FROM relay_trust_import WHERE institution_code=?"
            " ORDER BY bundle_serial DESC LIMIT 1", (code,)).fetchone()
        if row:
            return json.loads(row["bundle_json"])
        # 本机构自己导出的信任包（未经过 import 通道）
        own = conn.execute(
            "SELECT package_json FROM relay_trust_export WHERE "
            "institution_code=? ORDER BY rowid DESC LIMIT 1",
            (code,)).fetchone()
        if own:
            return json.loads(own["package_json"])
    return None
