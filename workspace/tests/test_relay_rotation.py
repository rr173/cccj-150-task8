"""机构签发密钥轮换：登记/批准/生效水位/签名链/并发/崩溃恢复。"""
from __future__ import annotations

import threading

import pytest

from app.relay import trust as trust_svc
from app.relay.store import tx
from app.relay.verifier import verify_trust_bundle, TrustBundleError


def _receipt(relay_env, request_key, *, session="PKG-1", ttl=3600):
    seed = relay_env["seed"]
    events = relay_env["chain"](seed, [
        ("CREATE", 1, "UPLOADING", None),
        ("FINALIZE_ACCEPTED", 2, "IMPORTED", None),
    ], session=session)
    relay_env["service"].push_events("site-A", events)
    return relay_env["service"].export_receipt(
        request_key=request_key, institution_code=relay_env["institution"],
        sender_id="site-A", ttl_seconds=ttl, session_ids=[session])["package"]


def test_bootstrap_creates_genesis_epoch_and_empty_revocation(relay_env):
    v = trust_svc.list_rotations(relay_env["institution"])
    assert v["active_epoch"] == 0 and v["next_serial"] == 1
    assert [r["epoch"] for r in v["rotations"]] == [0]
    assert v["rotations"][0]["status"] == "ACTIVE"
    revs = trust_svc.list_revocations(relay_env["institution"])
    assert revs["latest_version"] == 1
    assert revs["versions"][0]["entries"] == []


def test_preview_is_read_only(relay_env):
    p1 = trust_svc.rotation_preview(relay_env["institution"])
    p2 = trust_svc.rotation_preview(relay_env["institution"])
    assert p1 == p2
    assert p1["active_epoch"] == 0 and p1["next_serial"] == 1


def test_old_key_signs_before_watermark_new_key_after(relay_env):
    code = relay_env["institution"]
    r1 = _receipt(relay_env, "K-A", session="S-A")
    assert (r1["body"]["serial_no"], r1["body"]["signer_epoch"]) == (1, 0)

    trust_svc.propose_rotation(
        code, request_key="P1", proposed_by="alice", activate_serial=3)
    trust_svc.approve_rotation(
        code, request_key="A1", approved_by="bob")

    # 水位 3：serial 2 仍旧钥；serial 3 强制新钥（自动生效）
    r2 = _receipt(relay_env, "K-B", session="S-B")
    assert (r2["body"]["serial_no"], r2["body"]["signer_epoch"]) == (2, 0)
    r3 = _receipt(relay_env, "K-C", session="S-C")
    assert (r3["body"]["serial_no"], r3["body"]["signer_epoch"]) == (3, 1)
    # 新钥回执的内嵌公钥 != 旧钥
    assert r3["institution_public_key"] != r1["institution_public_key"]


def test_history_receipt_signed_by_old_key_verifies_after_rotation(relay_env):
    code = relay_env["institution"]
    old = _receipt(relay_env, "OLD", session="S-OLD")
    trust_svc.propose_rotation(
        code, request_key="P1", proposed_by="alice", activate_serial=2)
    trust_svc.approve_rotation(
        code, request_key="A1", approved_by="bob")
    new = _receipt(relay_env, "NEW", session="S-NEW")
    # 独立（内嵌公钥）核验：轮换前的历史回执继续按旧钥验证
    from app.relay.verifier import verify_receipt_package
    assert verify_receipt_package(old)["valid"] is True
    assert verify_receipt_package(new)["valid"] is True


def test_propose_idempotent_request_key(relay_env):
    code = relay_env["institution"]
    a = trust_svc.propose_rotation(
        code, request_key="DUP", proposed_by="alice", activate_serial=5)
    b = trust_svc.propose_rotation(
        code, request_key="DUP", proposed_by="alice", activate_serial=5)
    assert a["rotation"]["record_hash"] == b["rotation"]["record_hash"]
    assert b["replayed"] is True


def test_only_one_pending_rotation_concurrent_propose(relay_env):
    code = relay_env["institution"]
    errors = []

    def worker(key, by, serial):
        try:
            trust_svc.propose_rotation(
                code, request_key=key, proposed_by=by,
                activate_serial=serial)
        except trust_svc.TrustError as e:
            errors.append(e.code)

    threads = [threading.Thread(target=worker, args=(f"P{i}", f"admin{i}", 10))
               for i in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == ["PENDING_ROTATION_EXISTS"]
    with tx() as conn:
        n = conn.execute(
            "SELECT COUNT(*) c FROM relay_key_rotation WHERE "
            "institution_code=? AND status='PROPOSED'",
            (code,)).fetchone()["c"]
    assert n == 1


def test_approver_must_differ_from_proposer(relay_env):
    code = relay_env["institution"]
    trust_svc.propose_rotation(
        code, request_key="P1", proposed_by="alice", activate_serial=10)
    with pytest.raises(trust_svc.TrustError) as ei:
        trust_svc.approve_rotation(
            code, request_key="A1", approved_by="alice")
    assert ei.value.code == "APPROVER_MUST_DIFFER"


def test_concurrent_approval_only_one_takes_effect(relay_env):
    code = relay_env["institution"]
    trust_svc.propose_rotation(
        code, request_key="P1", proposed_by="alice", activate_serial=1)
    errors = []
    winners = []

    def approve(key, by):
        try:
            r = trust_svc.approve_rotation(
                code, request_key=key, approved_by=by)
            winners.append((by, r["rotation"]["status"]))
        except trust_svc.TrustError as e:
            errors.append((e.code, e.extra.get("approved_by")))

    threads = [threading.Thread(target=approve, args=(k, b))
               for k, b in [("A1", "bob"), ("A2", "carol")]]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(winners) == 1 and len(errors) == 1
    assert errors[0][0] == "APPROVAL_RACE"
    winner_by = winners[0][0]
    assert errors[0][1] == winner_by


def test_approve_request_key_replay_returns_first_result(relay_env):
    code = relay_env["institution"]
    trust_svc.propose_rotation(
        code, request_key="P1", proposed_by="alice", activate_serial=10)
    a = trust_svc.approve_rotation(
        code, request_key="A1", approved_by="bob")
    b = trust_svc.approve_rotation(
        code, request_key="A1", approved_by="bob")
    assert b["replayed"] is True
    assert a["rotation"]["record_hash"] == b["rotation"]["record_hash"]


def test_activate_serial_in_past_rejected(relay_env):
    code = relay_env["institution"]
    _receipt(relay_env, "X1", session="X1")  # next_serial -> 2
    trust_svc.propose_rotation(
        code, request_key="P1", proposed_by="alice", activate_serial=2)
    trust_svc.approve_rotation(
        code, request_key="A1", approved_by="bob")
    _receipt(relay_env, "X2", session="X2")  # 触发生效，next_serial -> 3
    # serial 1/2 已用旧钥签发；新轮换不得再把水位设到过去
    with pytest.raises(trust_svc.TrustError) as ei:
        trust_svc.propose_rotation(
            code, request_key="P2", proposed_by="alice", activate_serial=2)
    assert ei.value.code == "ACTIVATE_SERIAL_IN_PAST"


def test_key_chain_in_bundle_is_signed_and_verifies_offline(relay_env):
    code = relay_env["institution"]
    _receipt(relay_env, "K1", session="K1")
    trust_svc.propose_rotation(
        code, request_key="P1", proposed_by="alice", activate_serial=2)
    trust_svc.approve_rotation(
        code, request_key="A1", approved_by="bob")
    _receipt(relay_env, "K2", session="K2")
    b = trust_svc.export_trust_bundle(
        code, request_key="B1")["package"]
    report = verify_trust_bundle(b)
    assert report["active_epoch"] == 1
    assert list(report["epoch_public_keys"]) == [0, 1]
    assert report["activation"] == {0: 1, 1: 2}


def test_restart_does_not_rollback_or_switch_twice(relay_env):
    """重启后状态持久：active_epoch 不回退；已激活记录不会二次切换。"""
    code = relay_env["institution"]
    trust_svc.propose_rotation(
        code, request_key="P1", proposed_by="alice", activate_serial=1)
    trust_svc.approve_rotation(
        code, request_key="A1", approved_by="bob")
    _receipt(relay_env, "K1", session="K1")  # 触发自动生效
    before = trust_svc.list_rotations(code)
    assert before["active_epoch"] == 1

    # 模拟重启：重新初始化（新连接、无内存状态）
    from app.relay.store import init_relay_db
    init_relay_db()
    after = trust_svc.list_rotations(code)
    assert after["active_epoch"] == 1
    assert after["next_serial"] == before["next_serial"]
    statuses = [(r["epoch"], r["status"], r["activated_at"])
                for r in after["rotations"]]
    assert statuses[0][1] == "ACTIVE" and statuses[1][1] == "ACTIVE"
    # activated_at 未被重启重写
    assert statuses[1][2] == before["rotations"][1]["activated_at"]


def test_approved_but_watermark_not_reached_stays_old_key(relay_env):
    code = relay_env["institution"]
    _receipt(relay_env, "K1", session="K1")  # serial 1
    trust_svc.propose_rotation(
        code, request_key="P1", proposed_by="alice", activate_serial=5)
    trust_svc.approve_rotation(
        code, request_key="A1", approved_by="bob")
    r2 = _receipt(relay_env, "K2", session="K2")  # serial 2 < 5
    assert r2["body"]["signer_epoch"] == 0
    view = trust_svc.list_rotations(code)
    assert view["active_epoch"] == 0
    assert any(r["status"] == "APPROVED" for r in view["rotations"])


def test_external_public_key_requires_valid_pop(relay_env):
    code = relay_env["institution"]
    from app.relay import ed25519
    ext_seed, ext_pub = ed25519.keypair()
    with pytest.raises(trust_svc.TrustError) as ei:
        trust_svc.propose_rotation(
            code, request_key="P1", proposed_by="alice",
            activate_serial=10, next_public_key=ext_pub.hex())
    assert ei.value.code == "POP_SIGNATURE_INVALID"
    pop = __import__("app.relay.crypto", fromlist=["crypto"]).sign_pop(
        ext_seed, code, 1, ext_pub.hex(), 10)
    r = trust_svc.propose_rotation(
        code, request_key="P2", proposed_by="alice",
        activate_serial=10, next_public_key=ext_pub.hex(),
        pop_signature=pop)
    assert r["rotation"]["public_key"] == ext_pub.hex()


def test_broken_rotation_chain_detected_offline(relay_env):
    import copy
    code = relay_env["institution"]
    trust_svc.propose_rotation(
        code, request_key="P1", proposed_by="alice", activate_serial=1)
    trust_svc.approve_rotation(
        code, request_key="A1", approved_by="bob")
    b = trust_svc.export_trust_bundle(code, request_key="B1")["package"]
    bad = copy.deepcopy(b)
    bad["body"]["key_chain"][1]["prev_record_hash"] = "00" * 32
    with pytest.raises(TrustBundleError) as ei:
        verify_trust_bundle(bad)
    codes = {p["code"] for p in ei.value.problems}
    assert "ROTATION_CHAIN_BROKEN" in codes
    # 可定位到具体纪元
    prob = next(p for p in ei.value.problems
                if p["code"] == "ROTATION_CHAIN_BROKEN")
    assert prob["epoch"] == 1


def test_forged_approval_signature_detected(relay_env):
    """旧钥批准签名被替换 → 离线定位 ROTATION_APPROVAL_SIGNATURE_INVALID。"""
    import copy
    code = relay_env["institution"]
    trust_svc.propose_rotation(
        code, request_key="P1", proposed_by="alice", activate_serial=1)
    trust_svc.approve_rotation(
        code, request_key="A1", approved_by="bob")
    b = trust_svc.export_trust_bundle(code, request_key="B1")["package"]
    bad = copy.deepcopy(b)
    bad["body"]["key_chain"][1]["approval_signature"] = "11" * 64
    with pytest.raises(TrustBundleError) as ei:
        verify_trust_bundle(bad)
    assert "ROTATION_APPROVAL_SIGNATURE_INVALID" in \
        {p["code"] for p in ei.value.problems}


def test_bundle_serial_monotonic_and_export_replay(relay_env):
    code = relay_env["institution"]
    b1 = trust_svc.export_trust_bundle(
        code, request_key="B1")["package"]
    b2 = trust_svc.export_trust_bundle(
        code, request_key="B2")["package"]
    assert b2["body"]["bundle_serial"] == b1["body"]["bundle_serial"] + 1
    b1_replay = trust_svc.export_trust_bundle(
        code, request_key="B1")["package"]
    assert b1_replay == b1


def test_concurrent_receipt_issue_across_watermark_serial_monotonic(
        relay_env):
    """多线程在轮换水位边界并发签发：序号不重复，纪元切换恰好一次。"""
    code = relay_env["institution"]
    seed = relay_env["seed"]
    # 先建 8 个独立会话
    sessions = [f"CC-{i}" for i in range(8)]
    for sid in sessions:
        events = relay_env["chain"](seed, [
            ("CREATE", 1, "UPLOADING", None),
            ("FINALIZE_ACCEPTED", 2, "IMPORTED", None)], session=sid)
        relay_env["service"].push_events("site-A", events)
    # 水位 = 5：前 4 张（serial1..4）旧钥，之后新钥
    trust_svc.propose_rotation(
        code, request_key="P1", proposed_by="alice", activate_serial=5)
    trust_svc.approve_rotation(
        code, request_key="A1", approved_by="bob")

    errors, pkgs = [], []

    def issue(i):
        try:
            pkgs.append(relay_env["service"].export_receipt(
                request_key=f"C-{i}", institution_code=code,
                sender_id="site-A", ttl_seconds=3600,
                session_ids=[sessions[i]])["package"])
        except Exception as e:  # noqa: BLE001
            errors.append(e)

    threads = [threading.Thread(target=issue, args=(i,))
               for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors, errors
    serials = sorted(p["body"]["serial_no"] for p in pkgs)
    assert serials == list(range(1, 9))          # 单调、不重号
    epochs = {p["body"]["serial_no"]: p["body"]["signer_epoch"]
              for p in pkgs}
    assert {epochs[i] for i in (1, 2, 3, 4)} == {0}
    assert {epochs[i] for i in (5, 6, 7, 8)} == {1}
    view = trust_svc.list_rotations(code)
    assert view["active_epoch"] == 1 and view["next_serial"] == 9
