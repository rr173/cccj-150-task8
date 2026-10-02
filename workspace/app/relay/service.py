"""回执中继核心服务。

职责（与需求逐条对应）
----------------------
1. 接收发送方按**会话修订号**推送的审计事件（创建/分块接受/拒绝/移交/终检），
   允许乱序、重复、批量重放；原始事件**只追加落盘**，崩溃前后都不漏记。
2. 每个 (sender, session) 维护**连续水位**：只有前序齐全、事件哈希链连续、
   发送方签章有效、会话版本跃迁合法时才把事件确认进链并推进水位。
3. 发现**缺口 / 同序号异内容 / 分叉链 / 非法状态跃迁（含签章非法）**时
   隔离该会话（quarantine），返回**可定位差异**；隔离不阻塞任何其他会话，
   也不阻塞其他发送方——所有写操作都在各自会话键的事务内完成。
4. 按**接收机构**签发 Ed25519 **可离线核验回执包**（已确认水位/事件摘要/
   拒绝明细）；相同导出请求键永远返回原包。
5. 发送方凭回执请求**清理授权**：只能清理「已确认水位之前且仍与摘要一致」
   的本地事件；过期回执或本地事件后来变化一律拒绝清理。
6. 两个工作实例并发领取同一会话时，靠持久租约 + 事务保证不漏记/不重复确认/
   不跨会话串写。
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass

from . import config, crypto
from .store import tx, init_relay_db, audit, get_or_create_session
from ..services.ids import new_id, now_iso

# 隔离原因码
QR_SAME_REV = "SAME_REV_DIFFERENT_CONTENT"  # 同修订号异内容
QR_FORK = "FORKED_CHAIN"                    # 哈希链分叉（前驱哈希不接链）
QR_SIG = "BAD_SIGNATURE"                    # 发送方签章/事件哈希非法
QR_TRANSITION = "INVALID_TRANSITION"        # 会话状态/版本跃迁非法

# 各类事件相对上一修订的会话版本号增量规则
# None 表示不检查增量（该事件不改变会话版本）；1 表示必须恰好 +1
VERSION_DELTA = {
    "CREATE": None,                 # 建会话，version 必须为 1
    "CHUNK_ACCEPTED": None,         # 分块不递增会话版本
    "CHUNK_REJECTED": None,
    "HANDOVER": 1,                  # 移交必须 version+1
    "FINALIZE_ACCEPTED": None,
    "FINALIZE_REJECTED": None,
}


class RelayError(Exception):
    def __init__(self, message: str, code: str, status: int = 400, extra=None):
        super().__init__(message)
        self.code = code
        self.status = status
        self.extra = extra or {}


@dataclass
class ItemResult:
    revision: int
    outcome: str           # ACCEPTED / DUPLICATE / QUARANTINED / REJECTED
    detail: dict

    def as_dict(self):
        return {"revision": self.revision, "outcome": self.outcome,
                "detail": self.detail}


# ---------------------------------------------------------------------------
# 发送方
# ---------------------------------------------------------------------------

def register_sender(sender_id: str, public_key: str, title: str | None = None):
    with tx() as conn:
        row = conn.execute("SELECT * FROM relay_sender WHERE sender_id=?",
                           (sender_id,)).fetchone()
        if row:
            if row["public_key"] != public_key:
                raise RelayError("发送方已用不同公钥注册", "SENDER_KEY_CONFLICT", 409)
            return {"sender_id": sender_id, "title": row["title"],
                    "public_key": public_key, "replayed": True}
        conn.execute(
            "INSERT INTO relay_sender(sender_id,title,public_key,created_at)"
            " VALUES(?,?,?,?)", (sender_id, title, public_key, now_iso()))
        audit(conn, "SENDER_REGISTER", sender_id=sender_id,
              detail={"title": title})
        return {"sender_id": sender_id, "title": title,
                "public_key": public_key, "replayed": False}


def _sender(conn, sender_id: str) -> dict:
    row = conn.execute("SELECT * FROM relay_sender WHERE sender_id=?",
                       (sender_id,)).fetchone()
    if row is None:
        raise RelayError(f"未注册的发送方: {sender_id}", "UNKNOWN_SENDER", 404)
    return dict(row)


# ---------------------------------------------------------------------------
# 事件推送
# ---------------------------------------------------------------------------

def _parse_event(raw: dict) -> dict:
    required = {"sender_id", "session_id", "revision", "event_type",
                "session_version", "state", "occurred_at",
                "event_hash", "sender_signature"}
    missing = required - set(raw)
    if missing:
        raise RelayError(f"事件缺少字段: {sorted(missing)}", "MALFORMED_EVENT", 422)
    try:
        revision = int(raw["revision"])
        version = int(raw["session_version"])
    except (TypeError, ValueError):
        raise RelayError("revision/session_version 必须为整数",
                         "MALFORMED_EVENT", 422)
    if revision < 1:
        raise RelayError("revision 必须从 1 开始", "MALFORMED_EVENT", 422)
    if raw["event_type"] not in config.EVENT_TYPES:
        raise RelayError(f"不支持的事件类型: {raw['event_type']}",
                         "MALFORMED_EVENT", 422)
    if raw["state"] not in config.SESSION_STATES:
        raise RelayError(f"非法会话状态: {raw['state']}",
                         "MALFORMED_EVENT", 422)
    event = dict(raw)
    event["revision"] = revision
    event["session_version"] = version
    event.setdefault("prev_event_hash", None)
    event.setdefault("detail", None)
    return event


def _quarantine(conn, row, reason: str, detail: dict):
    """把会话标记为隔离（幂等：重复隔离只追加新的差异证据）。"""
    now = now_iso()
    conn.execute(
        "UPDATE relay_session SET quarantined=1, quarantine_reason=?,"
        " quarantine_detail_json=?, quarantined_at=COALESCE(quarantined_at,?),"
        " updated_at=? WHERE sender_id=? AND session_id=?",
        (reason, json.dumps(detail, ensure_ascii=False, default=str),
         now, now, row["sender_id"], row["session_id"]))
    conn.execute(
        "INSERT INTO relay_quarantine(id,sender_id,session_id,reason,"
        "detail_json,quarantined_at) VALUES(?,?,?,?,?,?) "
        "ON CONFLICT(sender_id,session_id) DO UPDATE SET "
        "detail_json=excluded.detail_json",
        (new_id("Q"), row["sender_id"], row["session_id"], reason,
         json.dumps(detail, ensure_ascii=False, default=str), now))
    audit(conn, "QUARANTINE", sender_id=row["sender_id"],
          session_id=row["session_id"], detail={"reason": reason, **detail})


def _check_transition(prev_state, prev_version, event) -> str | None:
    """返回非法原因描述；合法返回 None。"""
    etype = event["event_type"]
    state, version = event["state"], event["session_version"]
    if state not in config.LEGAL_TRANSITIONS[etype]:
        return (f"事件 {etype} 不能把会话置为 {state}（允许: "
                f"{sorted(config.LEGAL_TRANSITIONS[etype])}）")
    if etype == "CREATE":
        if version != 1:
            return f"CREATE 事件会话版本必须为 1，实际 {version}"
        return None
    if prev_version is not None:
        delta = VERSION_DELTA[etype]
        if delta is not None and version != prev_version + 1:
            return (f"事件 {etype} 会话版本必须由 {prev_version} 跃迁到 "
                    f"{prev_version + 1}，实际 {version}")
        if delta is None and version < prev_version:
            return (f"事件 {etype} 会话版本不得由 {prev_version} 回退到 "
                    f"{version}")
    return None


def push_events(sender_id: str, events: list[dict], *,
                batch_id: str | None = None) -> dict:
    """批量推送事件；每个事件独立落盘、独立判定，返回逐项结果。

    * 同 (rev, event_hash) 重复 = DUPLICATE（幂等，绝不重复确认）；
    * 前序未齐 = WAITING（原始已落盘，不隔离）；
    * 硬冲突（异内容/分叉/坏签名/非法跃迁）= 隔离会话、QUARANTINED；
    * 每次推送后尽力推进连续水位。
    """
    if not isinstance(events, list) or not events:
        raise RelayError("events 必须为非空数组", "MALFORMED_EVENT", 422)
    parsed = [_parse_event(e) for e in events]

    # 一个批次内的会话集合：session_id -> {(revision, event_hash): event}
    batch_sessions: dict = {}
    for e in parsed:
        if e["sender_id"] != sender_id:
            raise RelayError(
                f"事件 sender_id={e['sender_id']} 与认证发送方 {sender_id} 不一致",
                "SENDER_MISMATCH", 403)
        batch_sessions.setdefault(e["session_id"], {})[
            (e["revision"], e.get("event_hash"))] = e

    results: list[ItemResult] = []
    # 同一会话同一修订号在**本批次**出现两种哈希：直接隔离（同序号异内容）
    batch_conflicts: dict = {}
    for sid, items in batch_sessions.items():
        rev_hashes: dict = {}
        for (rev, h) in items:
            rev_hashes.setdefault(rev, set()).add(h)
        for rev, hs in rev_hashes.items():
            if len(hs) > 1:
                batch_conflicts[(sid, rev)] = sorted(hs)

    touched = set(batch_sessions)
    with tx() as conn:
        sender = _sender(conn, sender_id)
        pubkey = sender["public_key"]
        # 原始事件先全部只追加落盘（崩溃恢复后不丢；重复由 UNIQUE 兜底）
        for e in parsed:
            h = crypto.compute_event_hash(e)
            if e.get("event_hash") != h:
                # 事件哈希自相矛盾：立即隔离该会话
                row = get_or_create_session(conn, sender_id, e["session_id"])
                detail = {"at_revision": e["revision"],
                          "code": "EVENT_HASH_MISMATCH",
                          "expected_hash": h,
                          "actual_hash": e.get("event_hash")}
                _quarantine(conn, row, QR_SIG, detail)
                results.append(ItemResult(
                    e["revision"], "QUARANTINED",
                    {"session_id": e["session_id"], "reason": QR_SIG, **detail}))
                continue
            try:
                conn.execute(
                    "INSERT INTO relay_raw_event(sender_id,session_id,revision,"
                    "event_hash,payload_json,batch_id,received_at)"
                    " VALUES(?,?,?,?,?,?,?)",
                    (sender_id, e["session_id"], e["revision"], h,
                     json.dumps(e, ensure_ascii=False, default=str),
                     batch_id, now_iso()))
            except sqlite3_integrity():
                pass  # 同 rev+hash 已有，纯重复，继续走幂等判定

        # 逐会话判定 + 推进（按会话串行，避免同批乱序误判）
        submitted_keys = {sid: set(items) for sid, items in batch_sessions.items()}
        for sid in sorted(touched):
            sess_results = _process_session(
                conn, sender_id, sid, pubkey,
                submitted_keys=submitted_keys[sid],
                batch_conflicts=batch_conflicts)
            results.extend(sess_results)
        audit(conn, "EVENTS_PUSHED", sender_id=sender_id,
              detail={"batch_id": batch_id, "count": len(parsed),
                      "sessions": sorted(touched)})

    # 汇总输出（只含本次提交事件的逐项结果）
    out = {"sender_id": sender_id, "batch_id": batch_id,
           "results": [r.as_dict() for r in
                       sorted(results, key=lambda r: (r.detail.get("session_id", ""),
                                                      r.revision))]}
    _summarize(out)
    return out


def sqlite3_integrity():
    import sqlite3
    return sqlite3.IntegrityError


def _process_session(conn, sender_id: str, session_id: str,
                     pubkey: str, *, submitted_keys: set,
                     batch_conflicts: dict) -> list[ItemResult]:
    """对单个会话做：逐事件校验 → 隔离判定 → 推进连续水位。

    ``submitted_keys``：本次批次提交的 (revision, event_hash) 集合，
    结果回显**只针对本次提交**（历史事件不重复计入）。
    ``batch_conflicts``：{(session_id, rev): [distinct hashes]} 同批异内容。
    """
    results: list[ItemResult] = []
    submitted_revs = {rev for rev, _ in submitted_keys}

    def in_batch(rev, h):
        return (rev, h) in submitted_keys

    locked = get_or_create_session(conn, sender_id, session_id)
    watermark_before = locked["watermark"]

    # 取本会话全部原始事件（rev -> 去重后的事件，按 event_hash 索引）
    raws = conn.execute(
        "SELECT payload_json FROM relay_raw_event WHERE sender_id=? AND session_id=?",
        (sender_id, session_id)).fetchall()
    by_rev: dict[int, dict[str, dict]] = {}
    for r in raws:
        e = json.loads(r["payload_json"])
        by_rev.setdefault(e["revision"], {})[e["event_hash"]] = e

    last_confirmed = conn.execute(
        "SELECT * FROM relay_event WHERE sender_id=? AND session_id=? "
        "ORDER BY revision DESC LIMIT 1",
        (sender_id, session_id)).fetchone()
    watermark = watermark_before

    # 1) 本次提交事件的硬冲突检测
    for rev in sorted(submitted_revs):
        batch_hashes = {h for (rr, h) in submitted_keys if rr == rev}
        stored = by_rev.get(rev, {})

        # 已确认修订号：只可能是幂等重复；异内容（链上 hash 不同）隔离
        if rev <= watermark_before:
            conf = conn.execute(
                "SELECT event_hash FROM relay_event WHERE sender_id=? "
                "AND session_id=? AND revision=?",
                (sender_id, session_id, rev)).fetchone()
            for h in batch_hashes:
                if not in_batch(rev, h):
                    continue
                if conf and conf["event_hash"] != h:
                    detail = {"at_revision": rev,
                              "expected_hash": conf["event_hash"],
                              "actual_hash": h, "code": QR_SAME_REV}
                    _quarantine(conn, locked, QR_SAME_REV, detail)
                    results.append(ItemResult(
                        rev, "QUARANTINED",
                        {"session_id": session_id, "reason": QR_SAME_REV, **detail}))
                else:
                    results.append(ItemResult(
                        rev, "DUPLICATE",
                        {"session_id": session_id, "event_hash": h,
                         "note": "修订号已确认且内容一致"}))
            continue

        # 未确认修订号：若该 rev 在（本批次 ∪ 历史库）存在 >1 种 hash → 同序号异内容
        all_hashes = set(stored) | batch_hashes
        conflict = batch_conflicts.get((session_id, rev))
        if len(all_hashes) > 1 or conflict:
            detail = {"at_revision": rev,
                      "distinct_hashes": sorted(all_hashes),
                      "code": QR_SAME_REV}
            _quarantine(conn, locked, QR_SAME_REV, detail)
            for h in batch_hashes:
                results.append(ItemResult(
                    rev, "QUARANTINED",
                    {"session_id": session_id, "event_hash": h,
                     "reason": QR_SAME_REV, **detail}))
            continue

        e = stored[next(iter(batch_hashes & set(stored)))] \
            if (batch_hashes & set(stored)) else None
        if e is None:
            continue  # 理论不会发生（已先落盘）
        if not crypto.verify_event_signature(e, pubkey):
            detail = {"at_revision": rev, "event_hash": e["event_hash"],
                      "code": QR_SIG}
            _quarantine(conn, locked, QR_SIG, detail)
            results.append(ItemResult(
                rev, "QUARANTINED",
                {"session_id": session_id, "reason": QR_SIG, **detail}))

    # 若已隔离（本次或历史），则不推进；本次提交中未定性的事件统一回 QUARANTINED
    locked = conn.execute(
        "SELECT * FROM relay_session WHERE sender_id=? AND session_id=?",
        (sender_id, session_id)).fetchone()
    decided = {r.revision for r in results}
    if locked["quarantined"]:
        for rev in sorted(submitted_revs):
            if rev not in decided:
                results.append(ItemResult(
                    rev, "QUARANTINED",
                    {"session_id": session_id,
                     "reason": locked["quarantine_reason"],
                     "note": "会话已隔离，事件仅留证、不推进水位"}))
        return results

    # 2) 连续水位推进（本次落盘可能补齐了缺口，触发后续多个事件一起确认）
    prev_hash = last_confirmed["event_hash"] if last_confirmed else None
    prev_state = last_confirmed["state"] if last_confirmed else None
    prev_version = last_confirmed["session_version"] if last_confirmed else None
    accepted_revs = set()
    while True:
        nxt = watermark + 1
        cands = by_rev.get(nxt)
        if not cands:
            break  # 缺口：停在当前水位等待补传（不隔离）
        h, e = next(iter(cands.items()))
        # 推进时再次核验签章（水位前补齐的事件此前可能未走单事件检测）
        if not crypto.verify_event_signature(e, pubkey):
            detail = {"at_revision": nxt, "event_hash": e["event_hash"],
                      "code": QR_SIG}
            _quarantine(conn, locked, QR_SIG, detail)
            if nxt in submitted_revs:
                results.append(ItemResult(
                    nxt, "QUARANTINED",
                    {"session_id": session_id, "reason": QR_SIG, **detail}))
            return results
        if e["event_type"] == "CREATE":
            if nxt != 1 or last_confirmed is not None:
                _quarantine(conn, locked, QR_TRANSITION,
                            {"at_revision": nxt,
                             "code": "CREATE_NOT_AT_REVISION_1"})
                if nxt in submitted_revs:
                    results.append(ItemResult(
                        nxt, "QUARANTINED",
                        {"session_id": session_id, "reason": QR_TRANSITION}))
                return results
            if e.get("prev_event_hash") is not None:
                detail = {"at_revision": nxt, "expected_prev": None,
                          "actual_prev": e.get("prev_event_hash"),
                          "code": QR_FORK}
                _quarantine(conn, locked, QR_FORK, detail)
                if nxt in submitted_revs:
                    results.append(ItemResult(
                        nxt, "QUARANTINED",
                        {"session_id": session_id, "reason": QR_FORK, **detail}))
                return results
        else:
            if e.get("prev_event_hash") != prev_hash:
                detail = {"at_revision": nxt, "expected_prev": prev_hash,
                          "actual_prev": e.get("prev_event_hash"),
                          "code": QR_FORK}
                _quarantine(conn, locked, QR_FORK, detail)
                if nxt in submitted_revs:
                    results.append(ItemResult(
                        nxt, "QUARANTINED",
                        {"session_id": session_id, "reason": QR_FORK, **detail}))
                return results
        bad = _check_transition(prev_state, prev_version, e)
        if bad:
            detail = {"at_revision": nxt, "code": QR_TRANSITION,
                      "message": bad, "prev_state": prev_state,
                      "event_type": e["event_type"],
                      "requested_state": e["state"],
                      "requested_version": e["session_version"]}
            _quarantine(conn, locked, QR_TRANSITION, detail)
            if nxt in submitted_revs:
                results.append(ItemResult(
                    nxt, "QUARANTINED",
                    {"session_id": session_id, "reason": QR_TRANSITION, **detail}))
            return results

        conn.execute(
            "INSERT INTO relay_event(sender_id,session_id,revision,event_type,"
            "session_version,state,prev_event_hash,event_hash,sender_signature,"
            "occurred_at,detail_json,confirmed_at)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (sender_id, session_id, nxt, e["event_type"],
             e["session_version"], e["state"], e.get("prev_event_hash"),
             e["event_hash"], e["sender_signature"], e["occurred_at"],
             json.dumps(e.get("detail"), ensure_ascii=False, default=str),
             now_iso()))
        watermark = nxt
        prev_hash = e["event_hash"]
        prev_state = e["state"]
        prev_version = e["session_version"]
        accepted_revs.add(nxt)

    # 3) 落水位
    closed_at = locked["closed_at"]
    if prev_state == config.TERMINAL_STATE and closed_at is None:
        closed_at = now_iso()
    conn.execute(
        "UPDATE relay_session SET watermark=?, state=?, closed_at=?,"
        " updated_at=? WHERE sender_id=? AND session_id=?",
        (watermark, prev_state, closed_at, now_iso(), sender_id, session_id))

    # 4) 只回显本次提交事件的定性
    for rev in sorted(submitted_revs):
        if rev in decided:
            continue
        h = next(iter({hh for rr, hh in submitted_keys if rr == rev}))
        if rev in accepted_revs:
            results.append(ItemResult(
                rev, "ACCEPTED",
                {"session_id": session_id, "event_hash": h,
                 "watermark_after": watermark if rev == watermark else None}))
        elif rev <= watermark:
            # 本次重复提交但此前已确认
            results.append(ItemResult(
                rev, "DUPLICATE",
                {"session_id": session_id, "event_hash": h,
                 "note": "修订号已确认且内容一致"}))
        else:
            # 缺口之后的乱序事件：已安全落盘，等待前序补传
            results.append(ItemResult(
                rev, "WAITING",
                {"session_id": session_id, "event_hash": h,
                 "note": f"等待缺口修订号 {watermark + 1} 补传",
                 "missing_from": watermark + 1}))
    return results


def _summarize(out: dict):
    counts: dict = {}
    quarantined = {}
    for r in out["results"]:
        counts[r["outcome"]] = counts.get(r["outcome"], 0) + 1
        if r["outcome"] == "QUARANTINED":
            d = r["detail"]
            quarantined.setdefault(d.get("session_id"), d.get("reason"))
    out["counts"] = counts
    out["quarantined"] = quarantined


# ---------------------------------------------------------------------------
# 查询
# ---------------------------------------------------------------------------

def list_sessions(sender_id: str | None = None) -> list[dict]:
    with tx() as conn:
        sql = ("SELECT s.*, q.detail_json AS qdetail, q.released_at AS qreleased "
               "FROM relay_session s LEFT JOIN relay_quarantine q "
               "ON s.sender_id=q.sender_id AND s.session_id=q.session_id")
        args = ()
        if sender_id:
            sql += " WHERE s.sender_id=?"
            args = (sender_id,)
        sql += " ORDER BY s.sender_id, s.session_id"
        rows = conn.execute(sql, args).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["quarantine_detail"] = json.loads(d.pop("qdetail")) if d.get("qdetail") else None
            out.append(d)
        return out


def session_detail(sender_id: str, session_id: str) -> dict:
    with tx() as conn:
        row = conn.execute(
            "SELECT * FROM relay_session WHERE sender_id=? AND session_id=?",
            (sender_id, session_id)).fetchone()
        if row is None:
            raise RelayError("会话不存在", "SESSION_NOT_FOUND", 404)
        q = conn.execute(
            "SELECT * FROM relay_quarantine WHERE sender_id=? AND session_id=?",
            (sender_id, session_id)).fetchone()
        events = conn.execute(
            "SELECT revision,event_type,session_version,state,prev_event_hash,"
            "event_hash,occurred_at,detail_json,confirmed_at FROM relay_event "
            "WHERE sender_id=? AND session_id=? ORDER BY revision",
            (sender_id, session_id)).fetchall()
        pending = conn.execute(
            "SELECT revision, COUNT(DISTINCT event_hash) AS variants, "
            "GROUP_CONCAT(DISTINCT event_hash) AS hashes FROM relay_raw_event "
            "WHERE sender_id=? AND session_id=? AND revision>? "
            "GROUP BY revision ORDER BY revision",
            (sender_id, session_id, row["watermark"])).fetchall()
        gaps = [p["revision"] for p in pending]
        missing = list(range(row["watermark"] + 1,
                             min(gaps) if gaps else row["watermark"] + 1))
        return {
            "sender_id": sender_id, "session_id": session_id,
            "watermark": row["watermark"], "state": row["state"],
            "quarantined": bool(row["quarantined"]),
            "quarantine_reason": row["quarantine_reason"],
            "quarantine_detail": json.loads(row["quarantine_detail_json"])
            if row["quarantine_detail_json"] else None,
            "quarantine": dict(q) if q else None,
            "closed": row["closed_at"] is not None,
            "lease": ({"owner": row["lease_owner"], "at": row["lease_at"]}
                      if row["lease_owner"] else None),
            "confirmed_events": [dict(e) for e in events],
            "pending_revisions": [dict(p) for p in pending],
            "missing_revisions": missing,
        }


def release_quarantine(sender_id: str, session_id: str,
                       note: str | None = None,
                       discard_event_hashes: dict | None = None) -> dict:
    """显式解除隔离（发送方修正后；解除后下次处理会重新校验并尝试推进）。

    ``discard_event_hashes``：{revision: [event_hash, ...]}，撤回导致隔离的
    **错误版本原始事件**（仅限水位之后、未确认的原始留证；已确认链上事件
    永不可删，传其哈希会被拒绝）。用于"同序号异内容"后的恢复：撤回错误
    版本、保留正确版本，再解除隔离让链继续。
    """
    discard_event_hashes = discard_event_hashes or {}
    with tx() as conn:
        row = conn.execute(
            "SELECT * FROM relay_session WHERE sender_id=? AND session_id=?",
            (sender_id, session_id)).fetchone()
        if row is None:
            raise RelayError("会话不存在", "SESSION_NOT_FOUND", 404)

        discarded = []
        refused = []
        for rev, hashes in discard_event_hashes.items():
            try:
                rev_i = int(rev)
            except (TypeError, ValueError):
                raise RelayError(f"非法修订号: {rev}", "MALFORMED_EVENT", 422)
            for h in hashes or []:
                # 已确认链上的事件哈希绝不允许撤回
                conf = conn.execute(
                    "SELECT event_hash FROM relay_event WHERE sender_id=? "
                    "AND session_id=? AND revision=? AND event_hash=?",
                    (sender_id, session_id, rev_i, h)).fetchone()
                if conf:
                    refused.append({"revision": rev_i, "event_hash": h,
                                    "reason": "CONFIRMED_EVENT_IMMUTABLE"})
                    continue
                cur = conn.execute(
                    "DELETE FROM relay_raw_event WHERE sender_id=? "
                    "AND session_id=? AND revision=? AND event_hash=?",
                    (sender_id, session_id, rev_i, h))
                if cur.rowcount:
                    discarded.append({"revision": rev_i, "event_hash": h})

        if row["quarantined"]:
            now = now_iso()
            conn.execute(
                "UPDATE relay_session SET quarantined=0, quarantine_reason=NULL,"
                " quarantine_detail_json=NULL, quarantined_at=NULL, updated_at=? "
                "WHERE sender_id=? AND session_id=?",
                (now, sender_id, session_id))
            conn.execute(
                "UPDATE relay_quarantine SET released_at=?, release_note=? "
                "WHERE sender_id=? AND session_id=?",
                (now, note, sender_id, session_id))
            audit(conn, "QUARANTINE_RELEASE", sender_id=sender_id,
                  session_id=session_id,
                  detail={"note": note, "discarded": discarded,
                          "refused": refused})
            replayed = False
        else:
            replayed = True

        # 解除后立刻按现有原始事件重跑一次推进
        pubkey = _sender(conn, sender_id)["public_key"]
        submitted_keys = set()
        raws = conn.execute(
            "SELECT revision,event_hash FROM relay_raw_event WHERE sender_id=? "
            "AND session_id=?", (sender_id, session_id)).fetchall()
        for r in raws:
            submitted_keys.add((r["revision"], r["event_hash"]))
        results = _process_session(
            conn, sender_id, session_id, pubkey,
            submitted_keys=submitted_keys, batch_conflicts={})
        final = conn.execute(
            "SELECT watermark,quarantined,quarantine_reason FROM relay_session "
            "WHERE sender_id=? AND session_id=?",
            (sender_id, session_id)).fetchone()
        return {"sender_id": sender_id, "session_id": session_id,
                "replayed": replayed,
                "discarded": discarded, "refused": refused,
                "watermark": final["watermark"],
                "quarantined": bool(final["quarantined"]),
                "quarantine_reason": final["quarantine_reason"],
                "results": [r.as_dict() for r in results]}


# ---------------------------------------------------------------------------
# 工作实例领取租约（两实例并发领取同一会话）
# ---------------------------------------------------------------------------

def claim_session(session_id: str, worker_id: str,
                  sender_id: str | None = None, *,
                  ttl: float | None = None, now: str | None = None) -> dict:
    """原子领取一个会话的处理权。

    * 无租约/租约已过期 → 领取成功（持久写入 lease_owner/lease_at）；
    * 同一 worker 续租 → 成功（replayed=True）；
    * 其他 worker 持有有效租约 → 409 LEASE_HELD（不影响其继续处理，
      也不影响任何**其他**会话——租约粒度就是单会话）。
    """
    ttl = ttl if ttl is not None else config.LEASE_TTL_SECONDS
    from datetime import datetime, timedelta, timezone
    ts = now or datetime.now(timezone.utc)
    with tx() as conn:
        if sender_id:
            row = conn.execute(
                "SELECT * FROM relay_session WHERE sender_id=? AND session_id=?",
                (sender_id, session_id)).fetchone()
            if row is None:
                raise RelayError("会话不存在", "SESSION_NOT_FOUND", 404)
            rows = [row]
        else:
            rows = conn.execute(
                "SELECT * FROM relay_session WHERE session_id=?",
                (session_id,)).fetchall()
            if not rows:
                raise RelayError("会话不存在", "SESSION_NOT_FOUND", 404)
        claims = []
        for row in rows:
            sid, send = row["session_id"], row["sender_id"]
            if row["lease_owner"] and row["lease_owner"] != worker_id:
                lease_at = datetime.fromisoformat(row["lease_at"].replace("Z", "+00:00"))
                if datetime.now(timezone.utc) - lease_at < timedelta(seconds=ttl):
                    claims.append({"session_id": sid, "sender_id": send,
                                   "claimed": False,
                                   "lease_owner": row["lease_owner"],
                                   "lease_at": row["lease_at"]})
                    continue
            cur = now_iso()
            conn.execute(
                "UPDATE relay_session SET lease_owner=?, lease_at=?, updated_at=? "
                "WHERE sender_id=? AND session_id=?",
                (worker_id, cur, cur, send, sid))
            audit(conn, "LEASE_CLAIM", sender_id=send, session_id=sid,
                  detail={"worker_id": worker_id})
            claims.append({"session_id": sid, "sender_id": send,
                           "claimed": True, "lease_owner": worker_id,
                           "lease_at": cur})
        if len(claims) == 1 and not claims[0]["claimed"]:
            raise RelayError("会话处理租约被其他工作实例持有", "LEASE_HELD",
                             409, claims[0])
        return {"worker_id": worker_id, "claims": claims}


def release_session_lease(session_id: str, worker_id: str,
                          sender_id: str | None = None) -> dict:
    with tx() as conn:
        sql = "UPDATE relay_session SET lease_owner=NULL, lease_at=NULL, updated_at=? WHERE session_id=? AND lease_owner=?"
        args = [now_iso(), session_id, worker_id]
        if sender_id:
            sql += " AND sender_id=?"
            args.append(sender_id)
        cur = conn.execute(sql, args)
        return {"released": cur.rowcount}


# ---------------------------------------------------------------------------
# 回执导出（按接收机构签发）
# ---------------------------------------------------------------------------

def _session_snapshot(conn, sender_id: str, session_id: str) -> dict:
    row = conn.execute(
        "SELECT * FROM relay_session WHERE sender_id=? AND session_id=?",
        (sender_id, session_id)).fetchone()
    evs = conn.execute(
        "SELECT revision,event_type,event_hash,session_version,state,"
        "prev_event_hash,occurred_at,detail_json FROM relay_event "
        "WHERE sender_id=? AND session_id=? ORDER BY revision",
        (sender_id, session_id)).fetchall()
    rejections = []
    chain = []
    for e in evs:
        # 回执链上的事件条目包含**全部哈希字段**：离线核验方可独立
        # 重算 event_hash 与 prev 链接，无需访问中继或原始事件流。
        entry = {
            "revision": e["revision"],
            "event_type": e["event_type"],
            "event_hash": e["event_hash"],
            "session_version": e["session_version"],
            "state": e["state"],
            "prev_event_hash": e["prev_event_hash"],
            "occurred_at": e["occurred_at"],
            "detail": json.loads(e["detail_json"]) if e["detail_json"] else None,
        }
        chain.append(entry)
        if e["event_type"] in ("CHUNK_REJECTED", "FINALIZE_REJECTED"):
            rejections.append({"revision": e["revision"],
                               "event_type": e["event_type"],
                               "event_hash": e["event_hash"],
                               "detail": entry["detail"]})
    digest_input = "\n".join(c["event_hash"] for c in chain)
    chain_digest = hashlib.sha256(digest_input.encode()).hexdigest()
    return {
        "sender_id": sender_id,
        "session_id": session_id,
        "confirmed_watermark": row["watermark"],
        "state": row["state"],
        "quarantined": bool(row["quarantined"]),
        "quarantine_reason": row["quarantine_reason"],
        "head_event_hash": chain[-1]["event_hash"] if chain else None,
        "chain_digest": chain_digest,
        "event_count": len(chain),
        "events": chain,
        "rejections": rejections,
    }


def export_receipt(*, request_key: str, institution_code: str,
                   sender_id: str, institution_title: str | None = None,
                   ttl_seconds: int | None = None,
                   session_ids: list[str] | None = None) -> dict:
    """导出（或重放）签名回执包。同 request_key 永远返回同一原包。"""
    init_relay_db()
    from .trust import ensure_institution, _auto_activate_due
    from datetime import datetime, timedelta, timezone
    ttl = ttl_seconds if ttl_seconds is not None else config.RECEIPT_TTL_SECONDS
    with tx() as conn:
        state = ensure_institution(conn, institution_code, institution_title)
        existing = conn.execute(
            "SELECT * FROM relay_receipt WHERE request_key=?",
            (request_key,)).fetchone()
        if existing:
            pkg = json.loads(existing["package_json"])
            # 同键必须同内容：校验关键参数一致
            if (existing["institution_code"] != institution_code or
                    existing["sender_id"] != sender_id):
                raise RelayError(
                    "相同导出请求键已绑定不同机构/发送方",
                    "REQUEST_KEY_CONFLICT", 409)
            return {"replayed": True, "package": pkg}

        # 若已批准轮换的生效水位就是本回执序号，则在同一事务内先切换签发钥；
        # 重启/重放时已有 request_key 行短路，序号和 active key 都不会回退。
        _auto_activate_due(conn, institution_code, state)
        state = conn.execute(
            "SELECT * FROM relay_institution_state WHERE institution_code=?",
            (institution_code,)).fetchone()
        serial = state["next_receipt_serial"]
        signing_seq = state["current_key_seq"]

        # 选会话：显式列表或该发送方全部
        if session_ids is None:
            sids = [r["session_id"] for r in conn.execute(
                "SELECT session_id FROM relay_session WHERE sender_id=? "
                "ORDER BY session_id", (sender_id,)).fetchall()]
        else:
            sids = list(session_ids)
        snapshots = [_session_snapshot(conn, sender_id, sid) for sid in sids]
        now_dt = datetime.now(timezone.utc)
        issued_at = now_dt.strftime("%Y-%m-%dT%H:%M:%S.") + \
                    f"{now_dt.microsecond // 1000:03d}Z"
        expires_dt = now_dt + timedelta(seconds=ttl)
        expires_at = expires_dt.strftime("%Y-%m-%dT%H:%M:%S.") + \
                     f"{expires_dt.microsecond // 1000:03d}Z"
        seed = crypto.load_institution_seed(institution_code, signing_seq)
        signing_pub = crypto.load_institution_public(institution_code, signing_seq)
        body = {
            "format": crypto.RECEIPT_FORMAT,
            "request_key": request_key,
            "receipt_id": request_key,
            "receipt_serial": serial,
            "institution_code": institution_code,
            "institution_title": institution_title or institution_code,
            "sender_id": sender_id,
            "issued_at": issued_at,
            "expires_at": expires_at,
            "sessions": snapshots,
            "signing_key_seq": signing_seq,
            "signing_public_key": signing_pub,
        }
        signature = crypto.sign_receipt(body, seed)
        root_pub = crypto.load_institution_public(institution_code, 0)
        package = {
            "body": body,
            # 兼容旧核验器：顶层公钥即本包实际签发钥。
            "institution_public_key": signing_pub,
            "root_institution_public_key": root_pub,
            "signature": signature,
        }
        pkg_json = json.dumps(package, ensure_ascii=False, default=str)
        try:
            conn.execute(
                "INSERT INTO relay_receipt(request_key,institution_code,sender_id,"
                "sessions_json,package_json,signature,issued_at,expires_at,"
                "created_at,receipt_serial,signing_key_seq,signing_public_key)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (request_key, institution_code, sender_id,
                 json.dumps(sids, ensure_ascii=False), pkg_json, signature,
                 issued_at, expires_at, now_iso(), serial, signing_seq,
                 signing_pub))
        except sqlite3.IntegrityError as exc:
            raise RelayError("相同导出请求键并发冲突", "REQUEST_KEY_CONFLICT",
                             409) from exc
        conn.execute(
            "UPDATE relay_institution_state SET next_receipt_serial=?,"
            "updated_at=? WHERE institution_code=?",
            (serial + 1, now_iso(), institution_code))
        audit(conn, "RECEIPT_EXPORT", sender_id=sender_id,
              detail={"request_key": request_key,
                      "institution": institution_code,
                      "sessions": sids, "receipt_serial": serial,
                      "signing_key_seq": signing_seq})
        return {"replayed": False, "package": package}


def list_receipts(sender_id: str | None = None) -> list[dict]:
    with tx() as conn:
        sql = ("SELECT request_key,institution_code,sender_id,issued_at,"
               "expires_at,sessions_json,receipt_serial,signing_key_seq "
               "FROM relay_receipt")
        args = ()
        if sender_id:
            sql += " WHERE sender_id=?"
            args = (sender_id,)
        sql += " ORDER BY issued_at DESC"
        rows = conn.execute(sql, args).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["sessions"] = json.loads(d.pop("sessions_json"))
            out.append(d)
        return out


# ---------------------------------------------------------------------------
# 清理授权（发送方凭回执清理本地事件前向中继核验）
# ---------------------------------------------------------------------------

def authorize_cleanup(*, package: dict, local_events: list[dict],
                      at: str | None = None) -> dict:
    """判定发送方能否凭回执清理本地事件。

    条件全部满足才授权：
      1. 回执包签章可由机构公钥离线验证通过；
      2. 回执未过期（at 缺省取当前时间）；
      3. 申请清理的事件修订号全部 ≤ 对应会话的已确认水位；
      4. 这些本地事件的 event_hash 仍与回执中确认的摘要**逐一一致**
         （本地事件后来发生变化则拒绝清理）。
    只授权最小安全集合；其余事件给出可定位的拒绝原因。
    """
    from .verifier import verify_receipt_package, ReceiptError
    try:
        verify_receipt_package(package)
    except ReceiptError as exc:
        return {"authorized": False, "code": "RECEIPT_INVALID",
                "message": str(exc), "allowed": [], "denied": []}

    from datetime import datetime, timezone
    now_dt = datetime.now(timezone.utc) if at is None \
        else datetime.fromisoformat(at.replace("Z", "+00:00"))
    body = package["body"]
    expires = datetime.fromisoformat(
        body["expires_at"].replace("Z", "+00:00"))
    if now_dt >= expires:
        return {"authorized": False, "code": "RECEIPT_EXPIRED",
                "message": f"回执已于 {body['expires_at']} 过期",
                "allowed": [], "denied": [{"all": True,
                                           "reason": "RECEIPT_EXPIRED"}]}

    sess_by_id = {s["session_id"]: s for s in body["sessions"]}
    if body.get("sender_id"):
        # 回执只对其签发对象有效
        pass

    allowed, denied = [], []
    for le in local_events:
        sid = le.get("session_id")
        rev = le.get("revision")
        h = le.get("event_hash")
        key = {"session_id": sid, "revision": rev, "event_hash": h}
        snap = sess_by_id.get(sid)
        if snap is None:
            denied.append({**key, "reason": "SESSION_NOT_IN_RECEIPT"})
            continue
        if rev is None or rev > snap["confirmed_watermark"]:
            denied.append({**key, "reason": "ABOVE_CONFIRMED_WATERMARK",
                           "confirmed_watermark": snap["confirmed_watermark"]})
            continue
        confirmed = {e["revision"]: e["event_hash"] for e in snap["events"]}
        if confirmed.get(rev) != h:
            denied.append({**key, "reason": "LOCAL_EVENT_CHANGED",
                           "receipt_hash": confirmed.get(rev)})
            continue
        allowed.append(key)
    return {
        "authorized": len(denied) == 0 and len(allowed) > 0,
        "code": "OK" if not denied else "PARTIAL",
        "receipt_request_key": body["request_key"],
        "institution_code": body["institution_code"],
        "expires_at": body["expires_at"],
        "allowed": allowed,
        "denied": denied,
        "cleanup_watermarks": {sid: snap["confirmed_watermark"]
                               for sid, snap in sess_by_id.items()},
    }
