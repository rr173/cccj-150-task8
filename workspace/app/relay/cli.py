"""命令行发送端模拟器（快照接收服务 → 回执中继）。

不依赖 HTTP 服务运行，直连中继库（同进程）演示真实发送方行为：
注册公钥、构造带哈希链与 Ed25519 签章的事件、乱序/重复/批量重放推送、
补传缺口、制造隔离、导出回执、请求清理授权。

用法示例
--------

::

    # 完整正向演示：建会话→乱序推送→补传→回执→离线核验→清理授权
    python -m app.relay.cli demo --sender site-A

    # 单独推事件（事件 JSON 文件，支持乱序/重复）
    python -m app.relay.cli push --sender site-A events.json

    # 导出回执包（相同 request-key 永远得到原包）
    python -m app.relay.cli receipt --sender site-A --institution DEMO-IN \\
        --request-key REQ-1 --out receipt.json

    # 隔离恢复演示：制造同序号异内容→隔离→重开正确链→解除隔离→补齐
    python -m app.relay.cli recovery --sender site-A
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import config, crypto, ed25519, service
from .store import init_relay_db
from .verifier import verify_receipt_package, ReceiptError


def sender_key_path(sender_id: str) -> Path:
    return config.data_dir() / f"sender-{sender_id}.key"


def load_or_create_sender(sender_id: str, title: str | None = None) -> tuple[bytes, str]:
    """返回 (seed_bytes, public_hex)；首次自动生成并向中继注册。"""
    p = sender_key_path(sender_id)
    if p.exists():
        seed = bytes.fromhex(p.read_text(encoding="ascii").strip())
    else:
        seed, _ = ed25519.keypair()
        config.ensure_dirs()
        p.write_text(seed.hex(), encoding="ascii")
        p.chmod(0o600)
    pubhex = ed25519.public_key_from_seed(seed).hex()
    service.register_sender(sender_id, pubhex, title or f"模拟器-{sender_id}")
    return seed, pubhex


def make_event(seed: bytes, *, sender_id: str, session_id: str, revision: int,
               event_type: str, session_version: int, state: str,
               prev_event_hash: str | None, occurred_at: str,
               detail: dict | None = None) -> dict:
    e = {
        "sender_id": sender_id, "session_id": session_id, "revision": revision,
        "event_type": event_type, "session_version": session_version,
        "state": state, "prev_event_hash": prev_event_hash,
        "occurred_at": occurred_at, "detail": detail,
    }
    e["event_hash"] = crypto.compute_event_hash(e)
    e["sender_signature"] = crypto.sign_event_hash(e["event_hash"], seed)
    return e


def _print(obj):
    print(json.dumps(obj, ensure_ascii=False, indent=2))


def cmd_demo(args) -> int:
    init_relay_db()
    crypto.create_institution_keys(args.institution, overwrite=False)
    seed, _ = load_or_create_sender(args.sender)
    sid = args.session

    # 一条合法链：CREATE → 分块接受 → 分块拒绝 → 移交 → 终检通过
    spec = [
        ("CREATE", 1, "UPLOADING", None),
        ("CHUNK_ACCEPTED", 1, "UPLOADING", {"seq": 1, "sha256": "aa" * 8}),
        ("CHUNK_ACCEPTED", 1, "READY", {"seq": 2, "sha256": "bb" * 8}),
        ("CHUNK_REJECTED", 1, "UPLOADING",
         {"seq": 3, "code": "CHUNK_CONTENT_MISMATCH", "expected": "cc" * 8}),
        ("HANDOVER", 2, "UPLOADING", {"from": "alice", "to": "bob"}),
        ("FINALIZE_ACCEPTED", 3, "IMPORTED", {"imported_versions": 4}),
    ]
    events, prev = [], None
    for i, (et, ver, st, det) in enumerate(spec, start=1):
        events.append(make_event(
            seed, sender_id=args.sender, session_id=sid, revision=i,
            event_type=et, session_version=ver, state=st,
            prev_event_hash=prev,
            occurred_at=f"2026-10-02T10:00:{i:02d}Z", detail=det))
        prev = events[-1]["event_hash"]

    print("== 1) 乱序推送 rev 1,3（rev 2 缺失，rev 3 应 WAITING）==")
    _print(service.push_events(args.sender, [events[0], events[2]],
                               batch_id="batch-1"))
    print("== 2) 重复推送 rev 1（幂等 DUPLICATE，不重复确认）==")
    _print(service.push_events(args.sender, [events[0]], batch_id="batch-1-replay"))
    print("== 3) 补传缺口 rev 2（自动连带确认 rev 3，水位→3）==")
    _print(service.push_events(args.sender, [events[1]], batch_id="batch-2"))
    print("== 4) 批量重放 rev 4,5,6（水位→6，终态 IMPORTED 闭合）==")
    _print(service.push_events(args.sender, events[3:], batch_id="batch-3"))
    print("== 5) 会话水位视图 ==")
    _print(service.session_detail(args.sender, sid))

    print("== 6) 导出签名回执包 ==")
    rp = service.export_receipt(
        request_key=args.request_key, institution_code=args.institution,
        sender_id=args.sender, ttl_seconds=args.ttl)
    Path(args.out).write_text(
        json.dumps(rp["package"], ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"回执包写入 {args.out}（replayed={rp['replayed']}）")
    print("== 7) 相同请求键重放 → 必须得到原包 ==")
    rp2 = service.export_receipt(
        request_key=args.request_key, institution_code=args.institution,
        sender_id=args.sender)
    print("原包一致:", rp2["package"] == rp["package"],
          "replayed:", rp2["replayed"])

    print("== 8) 独立离线核验（不访问中继库）==")
    try:
        _print(verify_receipt_package(rp["package"]))
    except ReceiptError as exc:
        _print({"valid": False, "problems": exc.problems})
        return 1

    print("== 9) 凭回执清理本地事件（水位前且摘要一致→授权）==")
    local = [{"session_id": sid, "revision": i,
              "event_hash": events[i - 1]["event_hash"]} for i in range(1, 5)]
    _print(service.authorize_cleanup(package=rp["package"], local_events=local))
    print("== 10) 本地 rev 2 事后变化 → 拒绝清理该事件 ==")
    local_bad = [{"session_id": sid, "revision": 2, "event_hash": "ff" * 32}]
    _print(service.authorize_cleanup(package=rp["package"], local_events=local_bad))
    return 0


def cmd_push(args) -> int:
    init_relay_db()
    seed, _ = load_or_create_sender(args.sender)
    events = json.loads(Path(args.file).read_text(encoding="utf-8"))
    if isinstance(events, dict):
        events = events.get("events", [])
    _print(service.push_events(args.sender, events, batch_id=args.batch_id))
    return 0


def cmd_receipt(args) -> int:
    init_relay_db()
    rp = service.export_receipt(
        request_key=args.request_key, institution_code=args.institution,
        sender_id=args.sender, ttl_seconds=args.ttl,
        session_ids=args.sessions or None)
    Path(args.out).write_text(
        json.dumps(rp["package"], ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"{'重放' if rp['replayed'] else '签发'}回执包 -> {args.out}")
    return 0


def cmd_recovery(args) -> int:
    """演示：同序号异内容 → 隔离 → 其他会话不受影响 → 修正 → 解除隔离 → 补齐。"""
    init_relay_db()
    crypto.create_institution_keys(args.institution, overwrite=False)
    seed, _ = load_or_create_sender(args.sender)
    good_sid, bad_sid, other_sid = "RCV-GOOD", "RCV-BAD", "RCV-OTHER"

    def chain(session, spec):
        out, prev = [], None
        for i, (et, ver, st, det) in enumerate(spec, 1):
            out.append(make_event(
                seed, sender_id=args.sender, session_id=session, revision=i,
                event_type=et, session_version=ver, state=st,
                prev_event_hash=prev, occurred_at=f"2026-10-02T11:00:{i:02d}Z",
                detail=det))
            prev = out[-1]["event_hash"]
        return out

    base = [("CREATE", 1, "UPLOADING", None),
            ("CHUNK_ACCEPTED", 1, "UPLOADING", {"seq": 1})]
    good = chain(good_sid, base)
    other = chain(other_sid, base)
    # 错误链：rev1 先发了一份与后来不同的 CREATE（同序号异内容）
    bad1_v1 = make_event(seed, sender_id=args.sender, session_id=bad_sid,
                         revision=1, event_type="CREATE", session_version=1,
                         state="UPLOADING", prev_event_hash=None,
                         occurred_at="2026-10-02T09:00:00Z",
                         detail={"note": "错误的第一版"})
    bad1_v2 = make_event(seed, sender_id=args.sender, session_id=bad_sid,
                         revision=1, event_type="CREATE", session_version=1,
                         state="READY", prev_event_hash=None,
                         occurred_at="2026-10-02T09:05:00Z",
                         detail={"note": "冲突的第二版"})

    print("== 1) 推送同会话同修订号的两种内容 → 隔离 RCV-BAD ==")
    r = service.push_events(args.sender, [bad1_v1, bad1_v2], batch_id="bad-1")
    _print(r)
    print("== 2) 隔离原因与可定位差异 ==")
    _print(service.session_detail(args.sender, bad_sid)["quarantine"])
    print("== 3) RCV-GOOD / RCV-OTHER 同时正常推进（隔离不波及其他会话）==")
    _print(service.push_events(args.sender, good, batch_id="good-1")["counts"])
    _print(service.push_events(args.sender, other, batch_id="other-1")["counts"])
    print("== 4) 隔离会话继续补传也被拒绝（只留证）==")
    rev2 = make_event(seed, sender_id=args.sender, session_id=bad_sid,
                      revision=2, event_type="CHUNK_ACCEPTED",
                      session_version=1, state="UPLOADING",
                      prev_event_hash=bad1_v2["event_hash"],
                      occurred_at="2026-10-02T09:10:00Z", detail={"seq": 1})
    _print(service.push_events(args.sender, [rev2], batch_id="bad-2"))
    print("== 5) 运维确认差异：撤回错误版本（保留 READY 正确版）并解除隔离 ==")
    rel = service.release_quarantine(
        args.sender, bad_sid, note="确认以 READY 版本为准，撤回 UPLOADING 误版",
        discard_event_hashes={1: [bad1_v1["event_hash"]]})
    _print(rel)
    print("== 6) 解除后正确 rev1 已确认，补齐 rev2（链继续推进）==")
    _print(service.push_events(args.sender, [rev2], batch_id="bad-fix"))
    print("== 7) 最终会话视图 ==")
    _print(service.session_detail(args.sender, bad_sid))
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="app.relay.cli",
        description="交换包交付回执中继 —— 命令行发送端模拟器")
    parser.add_argument("--sender", default="site-A", help="发送方标识")
    parser.add_argument("--institution", default="DEMO-IN", help="接收机构代码")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_demo = sub.add_parser("demo", help="完整正向端到端演示")
    p_demo.add_argument("--session", default="DEMO-PKG")
    p_demo.add_argument("--request-key", default="DEMO-REQ-1")
    p_demo.add_argument("--ttl", type=int, default=3600)
    p_demo.add_argument("--out", default="/tmp/relay-demo-receipt.json")
    p_demo.set_defaults(func=cmd_demo)

    p_push = sub.add_parser("push", help="从 JSON 文件推送事件（可乱序/重复）")
    p_push.add_argument("file")
    p_push.add_argument("--batch-id")
    p_push.set_defaults(func=cmd_push)

    p_rec = sub.add_parser("receipt", help="导出/重放签名回执包")
    p_rec.add_argument("--request-key", required=True)
    p_rec.add_argument("--sessions", nargs="*")
    p_rec.add_argument("--ttl", type=int)
    p_rec.add_argument("--out", required=True)
    p_rec.set_defaults(func=cmd_receipt)

    p_recov = sub.add_parser("recovery", help="隔离与恢复演示")
    p_recov.set_defaults(func=cmd_recovery)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
