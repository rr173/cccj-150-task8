"""机构密钥轮换、版本化撤销与离线信任包测试。"""
from __future__ import annotations

import json
import threading

import pytest

from app.relay import crypto, service, trust
from app.relay.verifier import (
    ReceiptError, verify_receipt_package, verify_trust_package)


def _events(env, count=1):
    spec = [("CREATE", 1, "UPLOADING", None),
            ("CHUNK_ACCEPTED", 1, "READY", {"seq": 1}),
            ("FINALIZE_ACCEPTED", 2, "IMPORTED", None)]
    return env["chain"](env["seed"], spec[:count],
                        sender="site-A", session="TRUST-PKG")


def _receipt(env, key, ttl=3600):
    return service.export_receipt(
        request_key=key, institution_code=env["institution"],
        sender_id="site-A", ttl_seconds=ttl)["package"]


def test_rotation_preview_register_approve_and_watermark_cutover(relay_env):
    svc = relay_env["service"]
    code = relay_env["institution"]
    svc.push_events("site-A", _events(relay_env, 3))
    r1_pkg = _receipt(relay_env, "R-OLD-1")
    assert r1_pkg["body"]["receipt_serial"] == 1
    assert r1_pkg["body"]["signing_key_seq"] == 0

    preview = trust.rotation_preview(code, effective_watermark=3)
    assert preview["current_key_seq"] == 0
    assert preview["next_receipt_serial"] == 2
    assert preview["new_key_signs"] == "serial >= 3"

    reg = trust.register_rotation(
        institution_code=code, request_key="REG-1",
        effective_watermark=3, registered_by="admin-a")
    assert reg["replayed"] is False
    assert reg["rotation"]["key_seq"] == 1

    replay = trust.register_rotation(
        institution_code=code, request_key="REG-1",
        effective_watermark=3, registered_by="admin-a")
    assert replay["replayed"] is True
    assert replay["rotation"] == reg["rotation"]

    appr = trust.approve_rotation(
        institution_code=code, key_seq=1, approver="admin-a",
        request_key="APP-1")
    assert appr["status"] == "APPROVED"
    assert appr["replayed"] is False

    old2 = _receipt(relay_env, "R-OLD-2")
    assert old2["body"]["receipt_serial"] == 2
    assert old2["body"]["signing_key_seq"] == 0

    new3 = _receipt(relay_env, "R-NEW-3")
    assert new3["body"]["receipt_serial"] == 3
    assert new3["body"]["signing_key_seq"] == 1

    # 模拟服务重启：持久状态不回退；显式生效/回执导出重放都不重复切换。
    relay_env["store"].init_relay_db()
    again = trust.activate_rotation(
        institution_code=code, key_seq=1, request_key="ACT-REPLAY")
    assert again["status"] == "ACTIVE" and again.get("already_active") is True
    replay_new3 = service.export_receipt(
        request_key="R-NEW-3", institution_code=code,
        sender_id="site-A")["package"]
    assert replay_new3 == new3

    status = trust.institution_trust_status(code)
    assert status["current_key_seq"] == 1
    assert [r["key_seq"] for r in status["rotation_chain"]] == [0, 1]


def test_concurrent_registration_and_approval_have_single_effect(relay_env):
    code = relay_env["institution"]

    errors, results = [], []
    barrier = threading.Barrier(2)

    def register(request_key, wm):
        barrier.wait()
        try:
            results.append(trust.register_rotation(
                institution_code=code, request_key=request_key,
                effective_watermark=wm, registered_by="admin"))
        except trust.TrustError as exc:
            errors.append(exc.code)

    t1 = threading.Thread(target=register, args=("REG-A", 5))
    t2 = threading.Thread(target=register, args=("REG-B", 6))
    t1.start(); t2.start(); t1.join(); t2.join()
    assert len(results) == 1
    assert errors == ["ROTATION_OPEN_EXISTS"]
    seq = results[0]["rotation"]["key_seq"]

    errors.clear(); results.clear()
    barrier2 = threading.Barrier(2)

    def approve(request_key, approver):
        barrier2.wait()
        try:
            results.append(trust.approve_rotation(
                institution_code=code, key_seq=seq, approver=approver,
                request_key=request_key))
        except trust.TrustError as exc:
            errors.append(exc.code)

    t1 = threading.Thread(target=approve, args=("APP-A", "admin-a"))
    t2 = threading.Thread(target=approve, args=("APP-B", "admin-b"))
    t1.start(); t2.start(); t1.join(); t2.join()
    assert len(results) == 1
    assert results[0]["approved_by"] == "admin-a" or \
        results[0]["approved_by"] == "admin-b"
    assert errors == ["ROTATION_NOT_PROPOSED"]

    # 两个请求键各自重放：A 得到首次成功，B 首次拒绝终局仍拒绝；不重复切换。
    replay_a = trust.approve_rotation(
        institution_code=code, key_seq=seq, approver="admin-a",
        request_key="APP-A")
    assert replay_a["replayed"] is True
    with pytest.raises(trust.TrustError) as ei:
        trust.approve_rotation(
            institution_code=code, key_seq=seq, approver="admin-b",
            request_key="APP-B")
    assert ei.value.code == "ROTATION_NOT_PROPOSED"


def test_revocation_by_id_and_time_range_versions_and_trust_verification(relay_env):
    svc = relay_env["service"]
    code = relay_env["institution"]
    svc.push_events("site-A", _events(relay_env, 1))

    pkg1 = _receipt(relay_env, "R1")
    pkg2 = _receipt(relay_env, "R2")

    v1 = trust.publish_revocation(
        institution_code=code, request_key="REV-1", receipt_ids=["R1"],
        reason="MISISSUED", published_by="admin")
    assert v1["version"] == 1
    assert [e["receipt_id"] for e in v1["added"]] == ["R1"]

    # 时间区间撤销匹配 R2；新清单包含 R1/R2，版本和 previous hash 单调。
    v2 = trust.publish_revocation(
        institution_code=code, request_key="REV-2",
        issued_from=pkg1["body"]["issued_at"],
        issued_to=pkg2["body"]["issued_at"],
        reason="KEY_COMPROMISE", published_by="admin")
    assert v2["version"] == 2
    assert v2["previous_list_hash"] == v1["list_hash"]
    assert len(v2["entries"]) == 2

    tp = trust.export_trust_package(
        institution_code=code, request_key="TRUST-1",
        ttl_seconds=3600)["package"]
    report = verify_trust_package(tp)
    assert report["valid"] is True
    assert report["latest_revocation_version"] == 2

    with pytest.raises(ReceiptError) as ei:
        verify_receipt_package(pkg1, trust_package=tp)
    assert "RECEIPT_REVOKED" in [p["code"] for p in ei.value.problems]
    with pytest.raises(ReceiptError) as ei:
        verify_receipt_package(pkg2, trust_package=tp)
    assert "RECEIPT_REVOKED_BY_TIME_RANGE" in [
        p["code"] for p in ei.value.problems]

    assert trust.receipt_status(code, "R1")["status"] == "REVOKED"


def test_unrevoked_historical_receipt_still_verifies_after_rotation(relay_env):
    svc = relay_env["service"]
    code = relay_env["institution"]
    svc.push_events("site-A", _events(relay_env, 3))
    old_pkg = _receipt(relay_env, "OLD")
    trust.register_rotation(institution_code=code, request_key="REG",
                            effective_watermark=3, registered_by="a")
    trust.approve_rotation(institution_code=code, key_seq=1,
                           approver="a", request_key="APP")
    _receipt(relay_env, "GAP")
    new_pkg = _receipt(relay_env, "NEW")
    tp = trust.export_trust_package(
        institution_code=code, request_key="TRUST",
        ttl_seconds=3600)["package"]
    # 旧钥历史回执和新钥当前回执都未撤销，均可验证。
    assert verify_receipt_package(old_pkg, trust_package=tp)["valid"]
    assert verify_receipt_package(new_pkg, trust_package=tp)["valid"]


def test_offline_trust_package_detects_expiry_broken_chain_and_rollback(relay_env):
    code = relay_env["institution"]
    tp = trust.export_trust_package(
        institution_code=code, request_key="TRUST",
        ttl_seconds=3600)["package"]

    with pytest.raises(ReceiptError) as ei:
        verify_trust_package(tp, now="2099-01-01T00:00:00Z")
    assert "TRUST_PACKAGE_EXPIRED" in [p["code"] for p in ei.value.problems]

    broken = json.loads(json.dumps(tp))
    broken["body"]["rotation_records"][0]["record_hash"] = "00" * 32
    with pytest.raises(ReceiptError) as ei:
        verify_trust_package(broken)
    assert "ROTATION_GENESIS_SIGNATURE_INVALID" in [
        p["code"] for p in ei.value.problems]
    with pytest.raises(ReceiptError) as ei:
        verify_trust_package(tp, min_trust_version=999)
    assert "TRUST_VERSION_ROLLED_BACK" in [
        p["code"] for p in ei.value.problems]



def test_offline_verifier_detects_revocation_set_rollback(relay_env):
    svc = relay_env["service"]
    code = relay_env["institution"]
    svc.push_events("site-A", _events(relay_env, 1))
    _receipt(relay_env, "R1")
    trust.publish_revocation(institution_code=code, request_key="V1",
                             receipt_ids=["R1"], published_by="a")
    _receipt(relay_env, "R2")
    trust.publish_revocation(institution_code=code, request_key="V2",
                             receipt_ids=["R2"], published_by="a")
    pkg = trust.export_trust_package(
        institution_code=code, request_key="TRUST-2",
        ttl_seconds=3600)["package"]
    # 最新清单必须是 V2（包含 R1,R2）。
    latest = pkg["body"]["revocation_lists"][-1]
    assert len(latest["entries"]) == 2
    latest["entries"] = [e for e in latest["entries"]
                         if e["receipt_id"] != "R2"]
    with pytest.raises(ReceiptError) as ei:
        verify_trust_package(pkg)
    codes = [p["code"] for p in ei.value.problems]
    assert "REVOCATION_ENTRIES_ROLLED_BACK" in codes
    assert "REVOCATION_ENTRIES_DIGEST_MISMATCH" in codes


def test_trust_import_rejects_lower_version_and_is_idempotent(relay_env):
    code = relay_env["institution"]
    p1 = trust.export_trust_package(
        institution_code=code, request_key="T1", ttl_seconds=3600)["package"]
    assert trust.import_trust_package(p1, request_key="I1")["replayed"] is False
    assert trust.import_trust_package(p1, request_key="I2")["replayed"] is True

    # 手工构造同机构低版本包：离线签名虽可验，但本地版本水位拒绝覆盖。
    p0 = json.loads(json.dumps(p1))
    p0["body"]["trust_version"] = 0
    digest = crypto.sha256_hex(crypto.canonical(p0["body"]))
    p0["trust_digest"] = digest
    seed = crypto.load_institution_seed(code, 0)
    p0["signature"] = crypto.sign_trust_body(p0["body"], seed)
    # 离线格式本身先拒绝坏版本；这正是导入端的第一道防线。
    with pytest.raises(ReceiptError):
        trust.import_trust_package(p0)
