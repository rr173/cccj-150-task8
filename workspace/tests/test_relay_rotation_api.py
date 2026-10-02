"""密钥轮换 / 撤销 / 离线信任包的 HTTP API 集成测试。"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.relay import ed25519, crypto, store as relay_store


@pytest.fixture()
def api(tmp_path, monkeypatch):
    monkeypatch.setenv("RELAY_DATA_DIR", str(tmp_path / "relay"))
    monkeypatch.setenv("RELAY_KEY_DIR", str(tmp_path / "relay" / "keys"))
    monkeypatch.setenv("RELAY_RECEIPT_DIR", str(tmp_path / "relay" / "receipts"))
    monkeypatch.setenv("RELAY_DB", str(tmp_path / "relay" / "relay.db"))
    from app import main
    relay_store.init_relay_db()
    client = TestClient(main.app)
    client.post("/api/relay/institutions",
                json={"institution_code": "API-IN"})
    seed, pub = ed25519.keypair()
    client.post("/api/relay/senders",
                json={"sender_id": "s1", "public_key": pub.hex()})
    return {"client": client, "seed": seed}


def _issue_receipt(c, seed, key, session="S1"):
    events, prev = [], None
    for i, (et, ver, st, det) in enumerate([
            ("CREATE", 1, "UPLOADING", None),
            ("CHUNK_ACCEPTED", 1, "READY", {"seq": 1}),
            ("FINALIZE_ACCEPTED", 2, "IMPORTED", None)], 1):
        e = {"sender_id": "s1", "session_id": session, "revision": i,
             "event_type": et, "session_version": ver, "state": st,
             "prev_event_hash": prev, "occurred_at": f"t{i}", "detail": det}
        e["event_hash"] = crypto.compute_event_hash(e)
        e["sender_signature"] = crypto.sign_event_hash(e["event_hash"], seed)
        events.append(e)
        prev = e["event_hash"]
    c.post("/api/relay/events/s1", json={"events": events})
    return c.post("/api/relay/receipts", json={
        "request_key": key, "institution_code": "API-IN",
        "sender_id": "s1", "ttl_seconds": 3600,
        "session_ids": [session]}).json()["package"]


def test_rotation_preview_propose_approve_activate(api):
    c = api["client"]
    p = c.get("/api/relay/institutions/API-IN/rotations/preview").json()
    assert p["active_epoch"] == 0 and p["next_serial"] == 1

    r = c.post("/api/relay/institutions/API-IN/rotations/propose", json={
        "request_key": "P1", "proposed_by": "alice",
        "activate_serial": 2})
    assert r.status_code == 200
    assert r.json()["rotation"]["status"] == "PROPOSED"

    # 自批 400
    r = c.post("/api/relay/institutions/API-IN/rotations/approve", json={
        "request_key": "A0", "approved_by": "alice"})
    assert r.status_code == 400 and r.json()["error"] == "APPROVER_MUST_DIFFER"

    r = c.post("/api/relay/institutions/API-IN/rotations/approve", json={
        "request_key": "A1", "approved_by": "bob"})
    assert r.status_code == 200
    assert r.json()["rotation"]["status"] in ("APPROVED", "ACTIVE")


def test_concurrent_approval_api_only_one_wins(api):
    c = api["client"]
    c.post("/api/relay/institutions/API-IN/rotations/propose", json={
        "request_key": "P1", "proposed_by": "alice",
        "activate_serial": 10})
    r1 = c.post("/api/relay/institutions/API-IN/rotations/approve", json={
        "request_key": "A1", "approved_by": "bob"})
    r2 = c.post("/api/relay/institutions/API-IN/rotations/approve", json={
        "request_key": "A2", "approved_by": "carol"})
    assert r1.status_code == 200
    assert r2.status_code == 409 and r2.json()["error"] == "APPROVAL_RACE"


def test_watermark_forces_new_key_on_issue(api):
    c = api["client"]
    _issue_receipt(c, api["seed"], "R1", "S1")  # serial1 旧钥
    c.post("/api/relay/institutions/API-IN/rotations/propose", json={
        "request_key": "P1", "proposed_by": "alice",
        "activate_serial": 2})
    c.post("/api/relay/institutions/API-IN/rotations/approve", json={
        "request_key": "A1", "approved_by": "bob"})
    pkg = _issue_receipt(c, api["seed"], "R2", "S2")
    assert pkg["body"]["serial_no"] == 2
    assert pkg["body"]["signer_epoch"] == 1


def test_revocation_publish_and_replay(api):
    c = api["client"]
    r1 = c.post("/api/relay/institutions/API-IN/revocations", json={
        "request_key": "RV1", "receipts": ["R1"]})
    assert r1.status_code == 200
    assert r1.json()["revocation"]["version"] == 2
    r2 = c.post("/api/relay/institutions/API-IN/revocations", json={
        "request_key": "RV1", "receipts": ["OTHER"]})
    assert r2.json()["replayed"] is True
    assert r2.json()["revocation"]["version"] == 2
    lst = c.get("/api/relay/institutions/API-IN/revocations").json()
    assert lst["latest_version"] == 2


def test_trust_bundle_export_verify_import_status(api):
    c = api["client"]
    pkg = _issue_receipt(c, api["seed"], "R1")
    c.post("/api/relay/institutions/API-IN/revocations",
           json={"request_key": "RV", "receipts": ["R1"]})
    b = c.post("/api/relay/trust-bundles", json={
        "institution_code": "API-IN", "request_key": "TB1"}).json()
    assert b["replayed"] is False
    bundle = b["package"]

    # 离线风格核验端点
    v = c.post("/api/relay/trust-bundles/verify",
               json={"package": bundle})
    assert v.status_code == 200 and v.json()["valid"] is True

    # 导入幂等
    i1 = c.post("/api/relay/trust-bundles/import", json={"package": bundle})
    i2 = c.post("/api/relay/trust-bundles/import", json={"package": bundle})
    assert i1.json()["replayed"] is False
    assert i2.json()["replayed"] is True

    # 已撤销回执状态可定位
    s = c.post("/api/relay/receipts/status", json={"package": pkg})
    assert s.json()["status"] == "REVOKED"
    assert s.json()["revocations"][0]["request_key"] == "R1"


def test_unrevoked_receipt_status_valid_with_bundle(api):
    c = api["client"]
    pkg = _issue_receipt(c, api["seed"], "KEEP")
    c.post("/api/relay/trust-bundles", json={
        "institution_code": "API-IN", "request_key": "TB1"})
    bundle = c.post("/api/relay/trust-bundles", json={
        "institution_code": "API-IN", "request_key": "TB1"}).json()["package"]
    c.post("/api/relay/trust-bundles/import", json={"package": bundle})
    s = c.post("/api/relay/receipts/status", json={"package": pkg})
    assert s.json()["status"] == "VALID"


def test_expired_trust_bundle_verify_endpoint(api):
    c = api["client"]
    c.post("/api/relay/trust-bundles", json={
        "institution_code": "API-IN", "request_key": "TB1",
        "ttl_seconds": 1})
    bundle = c.post("/api/relay/trust-bundles", json={
        "institution_code": "API-IN", "request_key": "TB1"}).json()["package"]
    r = c.post("/api/relay/trust-bundles/verify",
               json={"package": bundle, "at": "2099-01-01T00:00:00Z"})
    assert r.status_code == 422
    assert "TRUST_BUNDLE_EXPIRED" in {p["code"] for p in r.json()["problems"]}
