"""版本化撤销清单 / 离线信任包 / 核验器定位拒绝。"""
from __future__ import annotations

import copy

import pytest

from app.relay import crypto, trust as trust_svc
from app.relay.verifier import (verify_trust_bundle, TrustBundleError,
                                check_receipt_against_trust)


def _chain_receipt(relay_env, request_key, session, *, ttl=3600,
                   event_detail=None):
    seed = relay_env["seed"]
    events = relay_env["chain"](seed, [
        ("CREATE", 1, "UPLOADING", None),
        ("CHUNK_ACCEPTED", 1, "UPLOADING", event_detail),
        ("FINALIZE_ACCEPTED", 2, "IMPORTED", {"imported_versions": 1}),
    ], session=session)
    relay_env["service"].push_events("site-A", events)
    return relay_env["service"].export_receipt(
        request_key=request_key, institution_code=relay_env["institution"],
        sender_id="site-A", ttl_seconds=ttl,
        session_ids=[session])["package"]


def _rotate(relay_env, activate_serial):
    code = relay_env["institution"]
    trust_svc.propose_rotation(
        code, request_key=f"P-{activate_serial}", proposed_by="alice",
        activate_serial=activate_serial)
    trust_svc.approve_rotation(
        code, request_key=f"A-{activate_serial}", approved_by="bob")


def test_publish_revocation_by_receipt_key_versioned(relay_env):
    code = relay_env["institution"]
    r = trust_svc.publish_revocation(
        code, request_key="REV1", receipts=["R-X"])
    assert r["replayed"] is False
    assert r["revocation"]["version"] == 2          # v1 是 genesis 空集
    assert r["total_entries"] == 1
    lst = trust_svc.list_revocations(code)
    assert [v["version"] for v in lst["versions"]] == [1, 2]
    # 摘要链：v2.prev_digest == v1.digest
    assert lst["versions"][1]["prev_digest"] == \
        lst["versions"][0]["digest"]


def test_revocation_request_key_replay_returns_same_version(relay_env):
    code = relay_env["institution"]
    a = trust_svc.publish_revocation(
        code, request_key="DUP", receipts=["R-1"])
    b = trust_svc.publish_revocation(
        code, request_key="DUP", receipts=["R-999"])  # 不同内容也回放
    assert b["replayed"] is True
    assert b["revocation"]["version"] == a["revocation"]["version"]
    assert b["revocation"]["digest"] == a["revocation"]["digest"]


def test_revocation_versions_are_accumulating_superset(relay_env):
    code = relay_env["institution"]
    trust_svc.publish_revocation(code, request_key="V1", receipts=["R1"])
    r = trust_svc.publish_revocation(
        code, request_key="V1", receipts=["R1"])
    trust_svc.publish_revocation(code, request_key="V2", receipts=["R2"])
    # 每版都是全量并集，历史撤销不丢
    lst = trust_svc.list_revocations(code)
    latest = {e["receipt_request_key"]
              for e in lst["versions"][-1]["entries"]}
    assert latest == {"R1", "R2"}


def test_revoke_by_time_range(relay_env):
    code = relay_env["institution"]
    p1 = _chain_receipt(relay_env, "EARLY", "S1")
    # 保证两张回执签发时间严格可区分
    import time as _time
    _time.sleep(0.012)
    p2 = _chain_receipt(relay_env, "LATER", "S2")
    i1 = p1["body"]["issued_at"]
    i2 = p2["body"]["issued_at"]
    assert i1 < i2
    trust_svc.publish_revocation(
        code, request_key="RANGE1",
        time_range={"issued_from": i1, "issued_to": i1})
    latest = trust_svc.list_revocations(code)["versions"][-1]["entries"]
    keys = {e["receipt_request_key"] for e in latest}
    # 毫秒级边界恰好只命中 EARLY
    assert keys == {"EARLY"}


def test_revoke_session_revision_entry(relay_env):
    code = relay_env["institution"]
    pkg = _chain_receipt(relay_env, "RR", "S9")
    r = trust_svc.publish_revocation(
        code, request_key="E1",
        entries=[{"sender_id": "site-A", "session_id": "S9",
                  "revision": 2}])
    bundle = trust_svc.export_trust_bundle(
        code, request_key="B1")["package"]
    d = check_receipt_against_trust(pkg, bundle)
    assert d["status"] == "REVOKED"
    assert d["revocations"][0]["match"] == "SESSION_REVISION"
    assert d["revocations"][0]["revision"] == 2


def test_unrevoked_history_receipt_still_valid_after_revocation(relay_env):
    code = relay_env["institution"]
    keep = _chain_receipt(relay_env, "KEEP", "KEEP")
    gone = _chain_receipt(relay_env, "GONE", "GONE")
    trust_svc.publish_revocation(code, request_key="R1", receipts=["GONE"])
    bundle = trust_svc.export_trust_bundle(
        code, request_key="B1")["package"]
    assert check_receipt_against_trust(gone, bundle)["status"] == "REVOKED"
    assert check_receipt_against_trust(keep, bundle)["status"] == "VALID"


def test_receipt_signed_after_watermark_with_old_key_is_denied(relay_env):
    """伪造回执：序号已到新钥水位却仍挂旧纪元/旧公钥 → 定位拒绝。"""
    code = relay_env["institution"]
    _chain_receipt(relay_env, "R1", "R1")
    _rotate(relay_env, activate_serial=2)
    new_pkg = _chain_receipt(relay_env, "R2", "R2")  # serial2 新钥
    bundle = trust_svc.export_trust_bundle(
        code, request_key="B1")["package"]

    forged = copy.deepcopy(new_pkg)
    # 完整伪装成旧钥产物：改纪元、换回旧公钥、旧钥重签
    forged["body"]["signer_epoch"] = 0
    forged["institution_public_key"] = \
        bundle["body"]["key_chain"][0]["public_key"]
    old_seed = crypto.load_institution_seed(code)
    forged["signature"] = crypto.sign_receipt(forged["body"], old_seed)
    d = check_receipt_against_trust(forged, bundle)
    assert d["status"] == "DENIED"
    assert d["code"] == "SIGNED_AFTER_WATERMARK_WITH_OLD_KEY"


def test_embedded_key_not_in_chain_denied(relay_env):
    code = relay_env["institution"]
    pkg = _chain_receipt(relay_env, "R1", "R1")
    bundle = trust_svc.export_trust_bundle(
        code, request_key="B1")["package"]
    bad = copy.deepcopy(pkg)
    from app.relay import ed25519
    rogue_seed, rogue_pub = ed25519.keypair()
    bad["institution_public_key"] = rogue_pub.hex()
    bad["signature"] = crypto.sign_receipt(bad["body"], rogue_seed)
    d = check_receipt_against_trust(bad, bundle)
    assert d["status"] == "DENIED"
    assert "SIGNING_KEY_NOT_IN_CHAIN" in {p["code"] for p in d["problems"]}


def test_trust_bundle_expired_is_localizable(relay_env):
    code = relay_env["institution"]
    pkg = _chain_receipt(relay_env, "R1", "R1")
    bundle = trust_svc.export_trust_bundle(
        code, request_key="B1", ttl_seconds=10)["package"]
    d = check_receipt_against_trust(
        pkg, bundle, now="2099-01-01T00:00:00Z")
    assert d["status"] == "TRUST_EXPIRED"
    with pytest.raises(TrustBundleError) as ei:
        verify_trust_bundle(bundle, now="2099-01-01T00:00:00Z")
    assert "TRUST_BUNDLE_EXPIRED" in {p["code"] for p in ei.value.problems}


def test_revocation_rollback_detected_offline(relay_env):
    code = relay_env["institution"]
    trust_svc.publish_revocation(code, request_key="V1", receipts=["R1"])
    bundle = trust_svc.export_trust_bundle(
        code, request_key="B1")["package"]
    # 逐版签名合法但回滚：重签一个不含 R1 的最新版（版本号继续递增）
    bad = copy.deepcopy(bundle)
    signer_epoch = bad["body"]["key_chain"][-1]["epoch"]
    seed = crypto.load_institution_seed(code)  # 创世钥仍在
    versions = bad["body"]["revocation_versions"]
    prev_digest = versions[-1]["digest"]
    rollback = {"institution_code": code, "version": 3,
                "prev_digest": prev_digest, "entries": [],
                "published_at": "2026-10-03T00:00:00.000Z"}
    dg = crypto.revocation_digest(rollback)
    versions.append({**rollback, "digest": dg, "signer_epoch": signer_epoch,
                     "signature": crypto.sign_revocation(dg, seed)})
    with pytest.raises(TrustBundleError) as ei:
        verify_trust_bundle(bad)
    codes = {p["code"] for p in ei.value.problems}
    assert "REVOCATION_ROLLBACK" in codes
    prob = next(p for p in ei.value.problems
                if p["code"] == "REVOCATION_ROLLBACK")
    assert prob["removed_entries"][0]["receipt_request_key"] == "R1"


def test_revocation_version_signature_by_wrong_key_detected(relay_env):
    code = relay_env["institution"]
    trust_svc.publish_revocation(code, request_key="V1", receipts=["R1"])
    bundle = trust_svc.export_trust_bundle(
        code, request_key="B1")["package"]
    bad = copy.deepcopy(bundle)
    from app.relay import ed25519
    rogue_seed, _ = ed25519.keypair()
    v = bad["body"]["revocation_versions"][1]
    v["signature"] = crypto.sign_revocation(v["digest"], rogue_seed)
    with pytest.raises(TrustBundleError) as ei:
        verify_trust_bundle(bad)
    assert "REVOCATION_SIGNATURE_INVALID" in \
        {p["code"] for p in ei.value.problems}


def test_bundle_import_idempotent_and_conflict(relay_env):
    code = relay_env["institution"]
    bundle = trust_svc.export_trust_bundle(
        code, request_key="B1")["package"]
    r1 = trust_svc.import_trust_bundle(bundle)
    r2 = trust_svc.import_trust_bundle(bundle)
    assert r1["imported"] and r1["replayed"] is False
    assert r2["replayed"] is True
    # 同序号、内容不同但仍能通过结构核验（篡改机构标题后由链上生效钥重签）
    evil = copy.deepcopy(bundle)
    active_epoch = bundle["signer_epoch"]
    active_seed = bytes.fromhex(
        crypto.epoch_seed_path(code, active_epoch)
        .read_text(encoding="ascii").strip())
    evil["body"]["institution_title"] = "冒名机构"
    evil["signature"] = crypto.sign_trust_bundle(evil["body"], active_seed)
    with pytest.raises(trust_svc.TrustError) as ei:
        trust_svc.import_trust_bundle(evil)
    assert ei.value.code == "TRUST_SERIAL_CONFLICT"


def test_import_rejects_invalid_bundle(relay_env):
    evil = {"body": {"format": "relay-trust-bundle/v1"}, "signature": "00"}
    r = trust_svc.import_trust_bundle(evil)
    assert r["imported"] is False
    assert r["code"] == "TRUST_VERIFY_FAILED"


def test_import_rejects_expired_bundle(relay_env):
    code = relay_env["institution"]
    bundle = trust_svc.export_trust_bundle(
        code, request_key="B1", ttl_seconds=10)["package"]
    r = trust_svc.import_trust_bundle(
        bundle, at="2099-01-01T00:00:00Z")
    assert r["imported"] is False
    assert "TRUST_BUNDLE_EXPIRED" in \
        {p["code"] for p in r["problems"]}


def test_receipt_status_uses_imported_bundle(relay_env):
    code = relay_env["institution"]
    pkg = _chain_receipt(relay_env, "R1", "R1")
    trust_svc.publish_revocation(code, request_key="RV", receipts=["R1"])
    bundle = trust_svc.export_trust_bundle(
        code, request_key="B1")["package"]
    trust_svc.import_trust_bundle(bundle)
    d = trust_svc.receipt_status(pkg)
    assert d["status"] == "REVOKED"
    assert d["trust_anchor"] == "TRUST_BUNDLE"


def test_old_epoch_receipt_validates_against_chain_after_two_rotations(
        relay_env):
    code = relay_env["institution"]
    r1 = _chain_receipt(relay_env, "R1", "R1")      # serial1 epoch0
    _rotate(relay_env, activate_serial=2)
    r2 = _chain_receipt(relay_env, "R2", "R2")      # serial2 epoch1
    _rotate(relay_env, activate_serial=3)
    r3 = _chain_receipt(relay_env, "R3", "R3")      # serial3 epoch2
    bundle = trust_svc.export_trust_bundle(
        code, request_key="B1")["package"]
    report = verify_trust_bundle(bundle)
    assert report["active_epoch"] == 2
    assert [check_receipt_against_trust(p, bundle)["status"]
            for p in (r1, r2, r3)] == ["VALID", "VALID", "VALID"]
