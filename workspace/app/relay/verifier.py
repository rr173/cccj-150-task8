"""回执包独立离线核验器。

仅凭**回执包本身**（内含机构公钥）即可完成全部核验，不访问中继、
不访问任何数据库：

1. 包结构 / 版本格式；
2. 机构 Ed25519 签章（对规范化正文重算）；
3. 有效期（可注入核验时刻）；
4. 每个会话的**事件哈希链**：逐事件重算 event_hash、校验
   prev_event_hash 连续、链顶摘要与 sessions[].chain_digest 一致；
5. 水位一致性（链长 == confirmed_watermark，修订号 1..N 连续）；
6. 拒绝明细中的 event_hash 与链上对应事件一致（拒绝明细无法被偷改）。

核验器也提供命令行入口：``python -m app.relay.verifier <package.json>``。
"""
from __future__ import annotations

import hashlib
import json
import sys
from datetime import datetime, timezone

from . import crypto


class ReceiptError(Exception):
    def __init__(self, message: str, code: str, problems=None):
        super().__init__(message)
        self.code = code
        self.problems = problems or []


def _iso(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def verify_receipt_package(package: dict, *, now: str | None = None,
                           min_watermark: dict | None = None) -> dict:
    """完整离线核验；通过返回核验报告 dict，任一不过抛 :class:`ReceiptError`。"""
    problems = []
    if not isinstance(package, dict):
        raise ReceiptError("回执包不是 JSON 对象", "MALFORMED_PACKAGE")
    body = package.get("body")
    sig = package.get("signature")
    pub = package.get("institution_public_key")
    if not isinstance(body, dict) or not sig or not pub:
        raise ReceiptError("回执包缺少 body/signature/institution_public_key",
                           "MALFORMED_PACKAGE")

    # 1. 格式
    if body.get("format") != crypto.RECEIPT_FORMAT:
        problems.append({"code": "UNSUPPORTED_FORMAT",
                         "actual": body.get("format")})

    # 2. 签章（完全离线）
    if not crypto.verify_receipt_signature(body, sig, pub):
        problems.append({"code": "BAD_SIGNATURE"})

    # 3. 有效期
    now_dt = _iso(now) if now else datetime.now(timezone.utc)
    expires_at = None
    expired = False
    try:
        expires_at = _iso(body["expires_at"])
        issued_at = _iso(body["issued_at"])
        if expires_at <= issued_at:
            problems.append({"code": "BAD_VALIDITY_WINDOW",
                             "issued_at": body.get("issued_at"),
                             "expires_at": body.get("expires_at")})
        if now_dt >= expires_at:
            expired = True
            problems.append({"code": "RECEIPT_EXPIRED",
                             "expires_at": body["expires_at"],
                             "checked_at": now_dt.strftime("%Y-%m-%dT%H:%M:%SZ")})
    except (KeyError, ValueError):
        problems.append({"code": "BAD_VALIDITY_WINDOW"})

    # 4/5. 逐会话链核验
    sessions_report = []
    for snap in body.get("sessions", []):
        r = _verify_session(snap)
        sessions_report.append(r)
        problems.extend({"session_id": snap.get("session_id"), **p}
                        for p in r["problems"])

    # 6. 调用方可选最低水位要求（发送方/审计场景）
    if min_watermark:
        by = {s["session_id"]: s["confirmed_watermark"]
              for s in body.get("sessions", [])}
        for sid, need in min_watermark.items():
            if by.get(sid, 0) < need:
                problems.append({"code": "WATERMARK_BELOW_REQUIRED",
                                 "session_id": sid, "required": need,
                                 "actual": by.get(sid, 0)})

    if problems:
        raise ReceiptError(f"回执核验发现 {len(problems)} 个问题",
                           "VERIFY_FAILED", problems)

    return {
        "valid": True,
        "institution_code": body.get("institution_code"),
        "institution_public_key": pub,
        "sender_id": body.get("sender_id"),
        "request_key": body.get("request_key"),
        "issued_at": body.get("issued_at"),
        "expires_at": body.get("expires_at"),
        "expired": expired,
        "sessions": sessions_report,
    }


def _verify_session(snap: dict) -> dict:
    problems = []
    sid = snap.get("session_id")
    events = snap.get("events", [])
    wm = snap.get("confirmed_watermark")

    if wm != len(events):
        problems.append({"code": "WATERMARK_LENGTH_MISMATCH",
                         "watermark": wm, "chain_length": len(events)})

    prev_hash = None
    digest_parts = []
    rejection_index = {r.get("revision"): r for r in snap.get("rejections", [])}
    for i, e in enumerate(events, start=1):
        rev = e.get("revision")
        if rev != i:
            problems.append({"code": "NON_CONTIGUOUS_REVISION",
                             "at_index": i, "revision": rev})
        # 离线重算 event_hash：回执链条目含全部哈希字段
        reconstructed = {
            "sender_id": snap.get("sender_id"),
            "session_id": sid,
            "revision": rev,
            "event_type": e.get("event_type"),
            "session_version": e.get("session_version"),
            "state": e.get("state"),
            "prev_event_hash": e.get("prev_event_hash"),
            "occurred_at": e.get("occurred_at"),
            "detail": e.get("detail"),
        }
        # prev 链接连续（首事件 prev 必须为 null）
        if e.get("prev_event_hash") != prev_hash:
            problems.append({"code": "BROKEN_PREV_LINK", "revision": rev,
                             "expected_prev": prev_hash,
                             "actual_prev": e.get("prev_event_hash")})
        if "event_hash" not in e:
            problems.append({"code": "MISSING_EVENT_HASH", "revision": rev})
        else:
            recomputed = crypto.sha256_hex(
                crypto.canonical({k: reconstructed.get(k)
                                  for k in crypto.EVENT_HASH_FIELDS}))
            if recomputed != e["event_hash"]:
                problems.append({"code": "EVENT_HASH_MISMATCH", "revision": rev,
                                 "expected": recomputed,
                                 "actual": e["event_hash"]})
            digest_parts.append(e["event_hash"])
            prev_hash = e["event_hash"]
        # 拒绝明细一致性
        if rev in rejection_index:
            rj = rejection_index[rev]
            if rj.get("event_hash") != e.get("event_hash"):
                problems.append({"code": "REJECTION_HASH_MISMATCH",
                                 "revision": rev})
            if rj.get("event_type") != e.get("event_type"):
                problems.append({"code": "REJECTION_TYPE_MISMATCH",
                                 "revision": rev})

    digest = hashlib.sha256("\n".join(digest_parts).encode()).hexdigest()
    if digest_parts and snap.get("chain_digest") != digest:
        problems.append({"code": "CHAIN_DIGEST_MISMATCH",
                         "expected": snap.get("chain_digest"),
                         "actual": digest})
    head = events[-1]["event_hash"] if events else None
    if snap.get("head_event_hash") != head:
        problems.append({"code": "HEAD_HASH_MISMATCH",
                         "expected": snap.get("head_event_hash"),
                         "actual": head})
    return {"session_id": sid, "sender_id": snap.get("sender_id"),
            "confirmed_watermark": wm, "state": snap.get("state"),
            "head_event_hash": head, "chain_digest": digest,
            "event_count": len(events),
            "quarantined": snap.get("quarantined", False),
            "problems": problems}


def main(argv=None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    if not argv:
        print("用法: python -m app.relay.verifier <receipt-package.json> [--at ISO]",
              file=sys.stderr)
        return 2
    path = argv[0]
    at = None
    if "--at" in argv:
        at = argv[argv.index("--at") + 1]
    with open(path, "r", encoding="utf-8") as f:
        package = json.load(f)
    try:
        report = verify_receipt_package(package, now=at)
    except ReceiptError as exc:
        print(json.dumps({"valid": False, "code": exc.code,
                          "message": str(exc), "problems": exc.problems},
                         ensure_ascii=False, indent=2))
        return 1
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
