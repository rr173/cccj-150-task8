"""回执中继 HTTP API 集成测试。"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.relay import ed25519, store as relay_store, crypto as relay_crypto


@pytest.fixture()
def api(tmp_path, monkeypatch):
    monkeypatch.setenv("RELAY_DATA_DIR", str(tmp_path / "relay"))
    monkeypatch.setenv("RELAY_KEY_DIR", str(tmp_path / "relay" / "keys"))
    monkeypatch.setenv("RELAY_RECEIPT_DIR", str(tmp_path / "relay" / "receipts"))
    monkeypatch.setenv("RELAY_DB", str(tmp_path / "relay" / "relay.db"))
    from app import main
    # 不触发全局 startup（那会建主库）；手动初始化中继库
    relay_store.init_relay_db()
    client = TestClient(main.app)
    seed, pub = ed25519.keypair()
    inst = client.post("/api/relay/institutions",
                       json={"institution_code": "API-IN"}).json()
    client.post("/api/relay/senders",
                json={"sender_id": "s1", "public_key": pub.hex(),
                      "title": "API 站"})
    return {"client": client, "seed": seed, "pub": pub.hex()}


def _event(seed, *, revision, etype="CREATE", version=1, state="UPLOADING",
           prev=None, session="S1", ts="2026-10-02T10:00:00Z", detail=None,
           sender="s1"):
    e = {"sender_id": sender, "session_id": session, "revision": revision,
         "event_type": etype, "session_version": version, "state": state,
         "prev_event_hash": prev, "occurred_at": ts, "detail": detail}
    e["event_hash"] = relay_crypto.compute_event_hash(e)
    e["sender_signature"] = relay_crypto.sign_event_hash(e["event_hash"], seed)
    return e


def _chain(seed, spec, session="S1"):
    out, prev = [], None
    for i, (et, ver, st, det) in enumerate(spec, 1):
        out.append(_event(seed, revision=i, etype=et, version=ver, state=st,
                          prev=prev, session=session, ts=f"t{i}", detail=det))
        prev = out[-1]["event_hash"]
    return out


def test_health(api):
    r = api["client"].get("/api/relay/health")
    assert r.json()["ok"] is True


def test_push_and_view_watermark(api):
    c = api["client"]
    events = _chain(api["seed"], [
        ("CREATE", 1, "UPLOADING", None),
        ("CHUNK_ACCEPTED", 1, "READY", {"seq": 1}),
        ("FINALIZE_ACCEPTED", 2, "IMPORTED", None),
    ])
    r = c.post("/api/relay/events/s1", json={"events": events, "batch_id": "b1"})
    assert r.status_code == 200
    assert r.json()["counts"] == {"ACCEPTED": 3}
    d = c.get("/api/relay/sessions/s1/S1").json()
    assert d["watermark"] == 3 and d["state"] == "IMPORTED"
    assert len(c.get("/api/relay/sessions").json()["sessions"]) == 1


def test_quarantine_visible_with_reason(api):
    c = api["client"]
    e1 = _event(api["seed"], revision=1, state="UPLOADING", detail={"v": 1})
    e2 = _event(api["seed"], revision=1, state="READY", detail={"v": 2})
    c.post("/api/relay/events/s1", json={"events": [e1, e2]})
    d = c.get("/api/relay/sessions/s1/S1").json()
    assert d["quarantined"] is True
    assert d["quarantine_reason"] == "SAME_REV_DIFFERENT_CONTENT"
    assert d["quarantine_detail"]["at_revision"] == 1


def test_release_quarantine_endpoint(api):
    c = api["client"]
    wrong = _event(api["seed"], revision=1, state="UPLOADING",
                   ts="t1", detail={"v": "wrong"})
    right = _event(api["seed"], revision=1, state="UPLOADING",
                   ts="t2", detail={"v": "right"})
    c.post("/api/relay/events/s1", json={"events": [wrong, right]})
    r = c.post("/api/relay/sessions/s1/S1/release-quarantine",
               json={"note": "ok",
                     "discard_event_hashes": {"1": [wrong["event_hash"]]}})
    assert r.status_code == 200
    assert r.json()["quarantined"] is False
    assert r.json()["watermark"] == 1


def test_receipt_export_download_verify_upload_and_cleanup(api):
    c = api["client"]
    events = _chain(api["seed"], [
        ("CREATE", 1, "UPLOADING", None),
        ("CHUNK_REJECTED", 1, "UPLOADING", {"seq": 1, "code": "X"}),
        ("FINALIZE_ACCEPTED", 2, "IMPORTED", None),
    ])
    c.post("/api/relay/events/s1", json={"events": events})

    r = c.post("/api/relay/receipts", json={
        "request_key": "K1", "institution_code": "API-IN",
        "sender_id": "s1", "ttl_seconds": 3600})
    assert r.status_code == 200
    pkg = r.json()["package"]

    # 重放同键
    r2 = c.post("/api/relay/receipts", json={
        "request_key": "K1", "institution_code": "API-IN", "sender_id": "s1"})
    assert r2.json()["package"] == pkg

    # 上传回执包核验
    rv = c.post("/api/relay/receipts/verify", json={"package": pkg})
    assert rv.status_code == 200 and rv.json()["valid"] is True

    # 篡改后核验失败
    pkg_bad = {**pkg, "signature": "00" * 64}
    rv = c.post("/api/relay/receipts/verify", json={"package": pkg_bad})
    assert rv.status_code == 422 and rv.json()["valid"] is False

    # 清理授权
    au = c.post("/api/relay/cleanup-authorization", json={
        "package": pkg,
        "local_events": [{"session_id": "S1", "revision": i,
                          "event_hash": events[i - 1]["event_hash"]}
                         for i in (1, 2)]})
    assert au.json()["authorized"] is True

    # 回执列表
    lst = c.get("/api/relay/receipts?sender_id=s1").json()["receipts"]
    assert [x["request_key"] for x in lst] == ["K1"]


def test_claim_endpoint_concurrent_view(api):
    c = api["client"]
    events = _chain(api["seed"], [("CREATE", 1, "UPLOADING", None)])
    c.post("/api/relay/events/s1", json={"events": events})
    r1 = c.post("/api/relay/claim",
                json={"session_id": "S1", "worker_id": "w0",
                      "sender_id": "s1"})
    assert r1.json()["claims"][0]["claimed"] is True
    r2 = c.post("/api/relay/claim",
                json={"session_id": "S1", "worker_id": "w1",
                      "sender_id": "s1"})
    assert r2.status_code == 409 and r2.json()["error"] == "LEASE_HELD"


def test_push_unknown_sender_404(api):
    c = api["client"]
    e = _event(api["seed"], revision=1, sender="ghost")
    r = c.post("/api/relay/events/ghost", json={"events": [e]})
    assert r.status_code == 404 and r.json()["error"] == "UNKNOWN_SENDER"


def test_push_sender_mismatch_403(api):
    c = api["client"]
    seed2, pub2 = ed25519.keypair()
    c.post("/api/relay/senders",
           json={"sender_id": "s2", "public_key": pub2.hex()})
    e = _event(api["seed"], revision=1, sender="s1")  # 内容声称 s1，却推给 s2
    r = c.post("/api/relay/events/s2", json={"events": [e]})
    assert r.status_code == 403 and r.json()["error"] == "SENDER_MISMATCH"
