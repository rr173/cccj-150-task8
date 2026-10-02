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

    # 机构签发密钥轮换 → 撤销 → 离线信任包全流程（含离线核验与旧回执可验）
    python -m app.relay.cli rotate-demo --institution DEMO-IN --sender site-A
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import config, crypto, ed25519, service
from . import trust as trust_svc
from .store import init_relay_db
from .verifier import (verify_receipt_package, ReceiptError,
                       verify_trust_bundle, TrustBundleError,
                       check_receipt_against_trust)


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


def _trust(args) -> int:
    """只读信任视图：轮换链 / 撤销版本。"""
    if args.trust_action == "rotations":
        _print(trust_svc.list_rotations(args.institution))
    else:
        _print(trust_svc.list_revocations(args.institution))
    return 0


def cmd_rotation(args) -> int:
    init_relay_db()
    if args.rot_action == "preview":
        _print(trust_svc.rotation_preview(
            args.institution,
            activate_serial=args.activate_serial,
            next_public_key=args.next_public_key))
        return 0
    if args.rot_action == "propose":
        _print(trust_svc.propose_rotation(
            args.institution, request_key=args.request_key,
            proposed_by=args.proposed_by,
            activate_serial=args.activate_serial,
            next_public_key=args.next_public_key,
            next_seed_hex=args.next_seed_hex,
            pop_signature=args.pop_signature))
        return 0
    if args.rot_action == "approve":
        _print(trust_svc.approve_rotation(
            args.institution, request_key=args.request_key,
            approved_by=args.approved_by, epoch=args.epoch))
        return 0
    if args.rot_action == "activate":
        _print(trust_svc.activate_rotation(args.institution, epoch=args.epoch))
        return 0
    _print(trust_svc.list_rotations(args.institution))
    return 0


def cmd_revocation(args) -> int:
    init_relay_db()
    if args.rev_action == "publish":
        entries = None
        if args.entries_file:
            entries = json.loads(Path(args.entries_file).read_text("utf-8"))
        time_range = None
        if args.issued_from or args.issued_to:
            time_range = {"issued_from": args.issued_from,
                          "issued_to": args.issued_to}
        _print(trust_svc.publish_revocation(
            args.institution, request_key=args.request_key,
            receipts=args.receipts or None, entries=entries,
            time_range=time_range, note=args.note))
        return 0
    _print(trust_svc.list_revocations(args.institution))
    return 0


def cmd_trust_bundle(args) -> int:
    init_relay_db()
    if args.bundle_action == "export":
        rp = trust_svc.export_trust_bundle(
            args.institution, request_key=args.request_key,
            ttl_seconds=args.ttl)
        Path(args.out).write_text(
            json.dumps(rp["package"], ensure_ascii=False, indent=2),
            encoding="utf-8")
        print(f"{'重放' if rp['replayed'] else '导出'}离线信任包 -> {args.out}")
        return 0
    if args.bundle_action == "verify":
        pkg = json.loads(Path(args.file).read_text("utf-8"))
        try:
            _print(verify_trust_bundle(pkg, now=args.at))
            return 0
        except TrustBundleError as exc:
            _print({"valid": False, "code": exc.code,
                    "problems": exc.problems})
            return 1
    if args.bundle_action == "import":
        pkg = json.loads(Path(args.file).read_text("utf-8"))
        r = trust_svc.import_trust_bundle(pkg, at=args.at)
        _print(r)
        return 0 if r.get("imported") else 1
    # check：以信任包为根定位回执（离线）
    bundle = json.loads(Path(args.trust).read_text("utf-8"))
    receipt = json.loads(Path(args.file).read_text("utf-8"))
    try:
        verify_trust_bundle(bundle, now=args.at)
    except TrustBundleError as exc:
        _print({"valid": False, "stage": "TRUST_BUNDLE",
                "problems": exc.problems})
        return 1
    d = check_receipt_against_trust(receipt, bundle, now=args.at)
    _print(d)
    return 0 if d["status"] == "VALID" else 1


def cmd_rotate_demo(args) -> int:
    """全流程：旧钥签回执→登记/批准新钥→水位生效→新旧钥各自可验→
    撤销旧回执→导出/导入信任包→离线核验定位（含断链/回滚拒绝）。"""
    init_relay_db()
    inst = args.institution
    crypto.create_institution_keys(inst, overwrite=False)
    seed, _ = load_or_create_sender(args.sender)
    sid = args.session

    def push_chain(spec, session):
        events, prev = [], None
        for i, (et, ver, st, det) in enumerate(spec, start=1):
            events.append(make_event(
                seed, sender_id=args.sender, session_id=session, revision=i,
                event_type=et, session_version=ver, state=st,
                prev_event_hash=prev,
                occurred_at=f"2026-10-02T20:00:{i:02d}Z", detail=det))
            prev = events[-1]["event_hash"]
        service.push_events(args.sender, events, batch_id=f"{session}-chain")
        return events

    spec = [
        ("CREATE", 1, "UPLOADING", None),
        ("CHUNK_ACCEPTED", 1, "UPLOADING", {"seq": 1}),
        ("FINALIZE_ACCEPTED", 2, "IMPORTED", {"imported_versions": 1}),
    ]
    events = push_chain(spec, sid)

    print("== 1) 轮换预演（只读，不改状态）==")
    preview = trust_svc.rotation_preview(inst)
    _print(preview)
    assert preview["active_epoch"] == 0
    assert preview["next_serial"] == 1

    print("== 2) 旧钥签发回执 serial=1（轮换前的历史回执）==")
    old = service.export_receipt(
        request_key="ROTDEMO-R1", institution_code=inst,
        sender_id=args.sender, ttl_seconds=3600)["package"]
    assert old["body"]["serial_no"] == 1 and old["body"]["signer_epoch"] == 0
    Path(f"{args.out_prefix}.old.json").write_text(
        json.dumps(old, ensure_ascii=False, indent=2), encoding="utf-8")

    print("== 3) 管理员 A 登记下一把公钥，生效水位=3（同键重放幂等）==")
    prop = trust_svc.propose_rotation(
        inst, request_key="ROTDEMO-PROP-1", proposed_by="admin-A",
        activate_serial=3)
    _print({"epoch": prop["rotation"]["epoch"],
            "status": prop["rotation"]["status"],
            "activate_serial": prop["rotation"]["activate_serial"]})
    prop_again = trust_svc.propose_rotation(
        inst, request_key="ROTDEMO-PROP-1", proposed_by="admin-A",
        activate_serial=3)
    assert prop_again["replayed"] is True
    new_epoch = prop["rotation"]["epoch"]

    print("== 4) 同一管理员不能自批；管理员 B 批准（不同键并发只一个生效）==")
    try:
        trust_svc.approve_rotation(
            inst, request_key="ROTDEMO-APPR-SELF", approved_by="admin-A")
        raise AssertionError("自批必须被拒绝")
    except trust_svc.TrustError as e:
        print("自批拒绝:", e.code)
    appr = trust_svc.approve_rotation(
        inst, request_key="ROTDEMO-APPR-1", approved_by="admin-B")
    _print({"epoch": appr["rotation"]["epoch"],
            "status": appr["rotation"]["status"]})
    # 管理员 C 用不同批准键并发批准：必须落败，首个结果保持生效
    try:
        trust_svc.approve_rotation(
            inst, request_key="ROTDEMO-APPR-2", approved_by="admin-C")
        raise AssertionError("并发批准必须只有一个生效")
    except trust_svc.TrustError as e:
        print("并发批准拒绝:", e.code, "→ 胜出:", e.extra.get("approved_by"))
        assert e.code == "APPROVAL_RACE"
    # 管理员 B 用同一批准键重放：返回首次结果（幂等）
    appr_replay = trust_svc.approve_rotation(
        inst, request_key="ROTDEMO-APPR-1", approved_by="admin-B")
    assert appr_replay["replayed"] is True

    print("== 5) serial=2 仍由旧钥（epoch0）签发；serial=3 起强制新钥 ==")
    mid = service.export_receipt(
        request_key="ROTDEMO-R2", institution_code=inst,
        sender_id=args.sender, ttl_seconds=3600)["package"]
    assert mid["body"]["serial_no"] == 2 and mid["body"]["signer_epoch"] == 0
    new = service.export_receipt(
        request_key="ROTDEMO-R3", institution_code=inst,
        sender_id=args.sender, ttl_seconds=3600)["package"]
    assert new["body"]["serial_no"] == 3 and \
        new["body"]["signer_epoch"] == new_epoch
    Path(f"{args.out_prefix}.new.json").write_text(
        json.dumps(new, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"旧钥回执 serial=1/2 继续可独立验证；新钥 serial=3 epoch={new_epoch}")

    print("== 6) 重启模拟：重新打开库，链状态不回退、不重复切换 ==")
    view = trust_svc.list_rotations(inst)
    _print({"active_epoch": view["active_epoch"],
            "next_serial": view["next_serial"],
            "statuses": [(r["epoch"], r["status"]) for r in view["rotations"]]})
    assert view["active_epoch"] == new_epoch

    print("== 7) 按回执标识撤销 serial=1 的旧回执（撤销清单 v2）==")
    rev = trust_svc.publish_revocation(
        inst, request_key="ROTDEMO-REV-1",
        receipts=["ROTDEMO-R1"], note="误签回执撤销")
    _print({"version": rev["revocation"]["version"],
            "total_entries": rev["total_entries"],
            "added": len(rev["added_entries"])})

    print("== 8) 导出离线信任包（公钥链+撤销版本+单调包序号）==")
    bundle = trust_svc.export_trust_bundle(
        inst, request_key="ROTDEMO-BUNDLE-1")["package"]
    bp = Path(f"{args.out_prefix}.trust.json")
    bp.write_text(json.dumps(bundle, ensure_ascii=False, indent=2),
                  encoding="utf-8")
    report = verify_trust_bundle(bundle)
    _print({"active_epoch": report["active_epoch"],
            "revocation_version": report["revocation_version"],
            "bundle_serial": report["bundle_serial"]})

    print("== 9) 导入信任包（幂等）+ 完全离线核验：旧回执已撤销 ==")
    _print(trust_svc.import_trust_bundle(bundle))
    d_old = check_receipt_against_trust(old, bundle)
    _print({"old_receipt": d_old["status"], "code": d_old["code"],
            "revocations": d_old["revocations"]})
    assert d_old["status"] == "REVOKED"

    print("== 10) 未撤销的历史回执 serial=2 与新钥回执 serial=3 仍 VALID ==")
    d_mid = check_receipt_against_trust(mid, bundle)
    d_new = check_receipt_against_trust(new, bundle)
    _print({"serial2": d_mid["status"], "serial3": d_new["status"]})
    assert d_mid["status"] == "VALID" and d_new["status"] == "VALID"

    print("== 11) 篡改轮换链（断链）→ 离线核验可定位拒绝 ==")
    bad = json.loads(json.dumps(bundle))
    bad["body"]["key_chain"][1]["prev_record_hash"] = "00" * 32
    try:
        verify_trust_bundle(bad)
        raise AssertionError("断链必须被拒绝")
    except TrustBundleError as e:
        codes = {p["code"] for p in e.problems}
        print("断链拒绝:", codes)
        assert "ROTATION_CHAIN_BROKEN" in codes

    print("== 12) 撤销摘要回滚检测（逐版签名合法但新版是旧版子集）==")
    # 信任包整体签名覆盖全部内容，任何篡改都先表现为 BAD_TRUST_SIGNATURE；
    # 真正的"回滚"威胁是机构侧（或其历史签名钥被滥用）重新发布一个
    # **逐版签名都合法**却更短的版本序列——离线超集检查在此定位。
    rb = json.loads(json.dumps(bundle))
    new_seed = bytes.fromhex(
        crypto.epoch_seed_path(inst, new_epoch).read_text().strip())
    versions = rb["body"]["revocation_versions"]
    # 构造 v1(空) -> v2(真实撤销) -> v3(伪造空集)：每版摘要/签名都合法，
    # 但 v3 是 v2 的真子集，超集单调检查必须定位 REVOCATION_ROLLBACK。
    forged = [dict(versions[0]), dict(versions[1])]
    rollback_obj = {
        "institution_code": inst, "version": 3,
        "prev_digest": forged[-1]["digest"], "entries": [],
        "published_at": "2026-10-03T00:00:00.000Z"}
    dg = crypto.revocation_digest(rollback_obj)
    forged.append({"institution_code": inst, "version": 3,
                   "prev_digest": rollback_obj["prev_digest"],
                   "entries": [], "digest": dg,
                   "published_at": rollback_obj["published_at"],
                   "signer_epoch": new_epoch,
                   "signature": crypto.sign_revocation(dg, new_seed)})
    rb["body"]["revocation_versions"] = forged
    try:
        verify_trust_bundle(rb)
        raise AssertionError("撤销回滚必须被拒绝")
    except TrustBundleError as e:
        codes = {p["code"] for p in e.problems}
        print("回滚拒绝:", codes)
        assert "REVOCATION_ROLLBACK" in codes

    print("== 13) 过期信任包 → 定位拒绝（核验时刻注入未来时间）==")
    r = check_receipt_against_trust(
        new, bundle, now="2099-01-01T00:00:00Z")
    _print({"future_check": r["status"], "code": r["code"]})
    assert r["status"] == "TRUST_EXPIRED"

    print(f"产物: {args.out_prefix}.old.json / .new.json / .trust.json")
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

    # -- 机构签发密钥轮换 --
    p_rot = sub.add_parser("rotation", help="签发密钥轮换：预演/登记/批准/生效")
    rot_sub = p_rot.add_subparsers(dest="rot_action", required=True)
    rp = rot_sub.add_parser("preview")
    rp.add_argument("--activate-serial", type=int)
    rp.add_argument("--next-public-key")
    rp.set_defaults(func=cmd_rotation)
    rp = rot_sub.add_parser("propose")
    rp.add_argument("--request-key", required=True)
    rp.add_argument("--proposed-by", required=True)
    rp.add_argument("--activate-serial", type=int, required=True)
    rp.add_argument("--next-public-key")
    rp.add_argument("--next-seed-hex")
    rp.add_argument("--pop-signature")
    rp.set_defaults(func=cmd_rotation)
    rp = rot_sub.add_parser("approve")
    rp.add_argument("--request-key", required=True)
    rp.add_argument("--approved-by", required=True)
    rp.add_argument("--epoch", type=int)
    rp.set_defaults(func=cmd_rotation)
    rp = rot_sub.add_parser("activate")
    rp.add_argument("--epoch", type=int)
    rp.set_defaults(func=cmd_rotation)
    rp = rot_sub.add_parser("list")
    rp.set_defaults(func=cmd_rotation)

    # -- 回执撤销 --
    p_rev = sub.add_parser("revocation", help="版本化撤销清单：发布/列表")
    rev_sub = p_rev.add_subparsers(dest="rev_action", required=True)
    rp = rev_sub.add_parser("publish")
    rp.add_argument("--request-key", required=True)
    rp.add_argument("--receipts", nargs="*", help="按回执请求键撤销")
    rp.add_argument("--entries-file", help="显式撤销条目 JSON 数组")
    rp.add_argument("--issued-from")
    rp.add_argument("--issued-to")
    rp.add_argument("--note")
    rp.set_defaults(func=cmd_revocation)
    rp = rev_sub.add_parser("list")
    rp.set_defaults(func=cmd_revocation)

    # -- 离线信任包 --
    p_tb = sub.add_parser("trust", help="离线信任包：导出/导入/核验/对照回执")
    tb_sub = p_tb.add_subparsers(dest="bundle_action", required=True)
    rp = tb_sub.add_parser("export")
    rp.add_argument("--request-key", required=True)
    rp.add_argument("--ttl", type=int)
    rp.add_argument("--out", required=True)
    rp.set_defaults(func=cmd_trust_bundle)
    rp = tb_sub.add_parser("verify")
    rp.add_argument("file")
    rp.add_argument("--at")
    rp.set_defaults(func=cmd_trust_bundle)
    rp = tb_sub.add_parser("import")
    rp.add_argument("file")
    rp.add_argument("--at")
    rp.set_defaults(func=cmd_trust_bundle)
    rp = tb_sub.add_parser("check", help="信任包为根离线定位回执")
    rp.add_argument("--trust", required=True)
    rp.add_argument("file")
    rp.add_argument("--at")
    rp.set_defaults(func=cmd_trust_bundle)

    p_rdemo = sub.add_parser("rotate-demo",
                             help="密钥轮换→撤销→信任包全流程离线演示")
    p_rdemo.add_argument("--session", default="PKG-ROT")
    p_rdemo.add_argument("--out-prefix", default="/tmp/relay-rotate")
    p_rdemo.set_defaults(func=cmd_rotate_demo)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
