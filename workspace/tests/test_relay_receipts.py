"""回执中继：签名回执包、离线核验、清理授权、请求键重放。"""
from __future__ import annotations

import copy
import json

import pytest

from app.relay import service
from app.relay.verifier import verify_receipt_package, ReceiptError


def _full_chain(relay_env, session="PKG-1", sender="site-A", seed_key="seed"):
    seed = relay_env[seed_key]
    return relay_env["chain"](seed, [
        ("CREATE", 1, "UPLOADING", None),
        ("CHUNK_ACCEPTED", 1, "UPLOADING", {"seq": 1}),
        ("CHUNK_REJECTED", 1, "UPLOADING",
         {"seq": 2, "code": "CHUNK_CONTENT_MISMATCH"}),
        ("HANDOVER", 2, "UPLOADING", {"new_owner": "bob"}),
        ("FINALIZE_ACCEPTED", 3, "IMPORTED", {"imported": 2}),
    ], sender=sender, session=session)


def _issue(relay_env, events, request_key="REQ-1", ttl=3600,
           sender="site-A", sessions=None):
    relay_env["service"].push_events(sender, events)
    return relay_env["service"].export_receipt(
        request_key=request_key, institution_code=relay_env["institution"],
        sender_id=sender, ttl_seconds=ttl, session_ids=sessions)


def test_receipt_contains_watermark_digest_and_rejections(relay_env):
    events = _full_chain(relay_env)
    rp = _issue(relay_env, events)
    body = rp["package"]["body"]
    assert body["format"] == "relay-receipt/v1"
    snap = body["sessions"][0]
    assert snap["confirmed_watermark"] == 5
    assert snap["state"] == "IMPORTED"
    assert len(snap["events"]) == 5
    assert [r["revision"] for r in snap["rejections"]] == [3]
    # 链摘要是逐事件哈希的 SHA256
    import hashlib
    expect = hashlib.sha256(
        "\n".join(e["event_hash"] for e in snap["events"]).encode()).hexdigest()
    assert snap["chain_digest"] == expect
    assert snap["head_event_hash"] == events[-1]["event_hash"]


def test_receipt_offline_verifies(relay_env):
    events = _full_chain(relay_env)
    rp = _issue(relay_env, events)
    report = verify_receipt_package(rp["package"])
    assert report["valid"] is True
    assert report["sessions"][0]["confirmed_watermark"] == 5
    assert report["expired"] is False


def test_receipt_recomputes_every_event_hash_offline(relay_env):
    events = _full_chain(relay_env)
    rp = _issue(relay_env, events)
    # 篡改回执链中任一历史事件的 detail -> 离线核验必须发现 event_hash 不匹配
    pkg = copy.deepcopy(rp["package"])
    pkg["body"]["sessions"][0]["events"][1]["detail"] = {"seq": 999}
    with pytest.raises(ReceiptError) as ei:
        verify_receipt_package(pkg)
    codes = {p["code"] for p in ei.value.problems}
    assert "EVENT_HASH_MISMATCH" in codes


def test_receipt_broken_prev_link_detected_offline(relay_env):
    events = _full_chain(relay_env)
    rp = _issue(relay_env, events)
    pkg = copy.deepcopy(rp["package"])
    # 把 rev3 的 prev 改掉（不改 event_hash，制造链断裂）
    ev3 = pkg["body"]["sessions"][0]["events"][2]
    ev3["prev_event_hash"] = "ff" * 32
    with pytest.raises(ReceiptError) as ei:
        verify_receipt_package(pkg)
    codes = {p["code"] for p in ei.value.problems}
    assert "BROKEN_PREV_LINK" in codes


def test_receipt_signature_tamper_detected(relay_env):
    events = _full_chain(relay_env)
    rp = _issue(relay_env, events)
    pkg = copy.deepcopy(rp["package"])
    pkg["body"]["institution_title"] = "伪造机构"
    with pytest.raises(ReceiptError) as ei:
        verify_receipt_package(pkg)
    assert "BAD_SIGNATURE" in {p["code"] for p in ei.value.problems}


def test_receipt_expiry_detected(relay_env):
    events = _full_chain(relay_env)
    rp = _issue(relay_env, events, ttl=10)
    with pytest.raises(ReceiptError) as ei:
        verify_receipt_package(rp["package"], now="2030-01-01T00:00:00Z")
    assert "RECEIPT_EXPIRED" in {p["code"] for p in ei.value.problems}


def test_request_key_replay_returns_identical_package(relay_env):
    events = _full_chain(relay_env)
    rp1 = _issue(relay_env, events, request_key="DUP-KEY")
    rp2 = relay_env["service"].export_receipt(
        request_key="DUP-KEY", institution_code=relay_env["institution"],
        sender_id="site-A")
    assert rp2["replayed"] is True
    assert rp2["package"] == rp1["package"]


def test_request_key_bound_to_institution_and_sender(relay_env):
    events = _full_chain(relay_env)
    _issue(relay_env, events, request_key="BOUND")
    with pytest.raises(service.RelayError) as ei:
        relay_env["service"].export_receipt(
            request_key="BOUND", institution_code=relay_env["institution"],
            sender_id="site-B")
    assert ei.value.code == "REQUEST_KEY_CONFLICT"


def test_receipt_filters_selected_sessions(relay_env):
    e_a = _full_chain(relay_env, session="PKG-A")
    _issue(relay_env, e_a, request_key="RA", sessions=["PKG-A"])
    e_b = _full_chain(relay_env, session="PKG-B")
    relay_env["service"].push_events("site-A", e_b)
    rp = relay_env["service"].export_receipt(
        request_key="RB", institution_code=relay_env["institution"],
        sender_id="site-A", session_ids=["PKG-B"])
    assert {s["session_id"] for s in rp["package"]["body"]["sessions"]} == {"PKG-B"}


def test_cleanup_authorized_when_before_watermark_and_digest_matches(relay_env):
    events = _full_chain(relay_env)
    rp = _issue(relay_env, events)
    local = [{"session_id": "PKG-1", "revision": i,
              "event_hash": events[i - 1]["event_hash"]} for i in range(1, 5)]
    a = relay_env["service"].authorize_cleanup(
        package=rp["package"], local_events=local)
    assert a["authorized"] is True
    assert len(a["allowed"]) == 4
    assert a["denied"] == []
    assert a["cleanup_watermarks"] == {"PKG-1": 5}


def test_cleanup_denied_above_watermark(relay_env):
    events = _full_chain(relay_env)
    rp = _issue(relay_env, events)
    local = [{"session_id": "PKG-1", "revision": 5,
              "event_hash": events[4]["event_hash"]}]
    # rev5 已确认（在水位上），允许；构造一个超出水位的场景：
    a = relay_env["service"].authorize_cleanup(
        package=rp["package"], local_events=local)
    assert a["authorized"] is True

    # 只导出前 3 个水位的回执（另建会话），然后申请 rev4
    # 用 PKG-PART2 前 3 水位
    part = relay_env["chain"](relay_env["seed"], [
        ("CREATE", 1, "UPLOADING", None),
        ("CHUNK_ACCEPTED", 1, "UPLOADING", None),
        ("CHUNK_ACCEPTED", 1, "READY", None),
    ], session="PKG-PART2")
    relay_env["service"].push_events("site-A", part)
    rpp = relay_env["service"].export_receipt(
        request_key="RP-PART", institution_code=relay_env["institution"],
        sender_id="site-A", session_ids=["PKG-PART2"])
    a = relay_env["service"].authorize_cleanup(
        package=rpp["package"],
        local_events=[{"session_id": "PKG-PART2", "revision": 4,
                       "event_hash": "x" * 64}])
    assert a["authorized"] is False
    assert a["denied"][0]["reason"] == "ABOVE_CONFIRMED_WATERMARK"


def test_cleanup_denied_when_local_event_changed(relay_env):
    events = _full_chain(relay_env)
    rp = _issue(relay_env, events)
    a = relay_env["service"].authorize_cleanup(
        package=rp["package"],
        local_events=[{"session_id": "PKG-1", "revision": 2,
                       "event_hash": "cc" * 32}])
    assert a["authorized"] is False
    assert a["denied"][0]["reason"] == "LOCAL_EVENT_CHANGED"
    assert a["denied"][0]["receipt_hash"] == events[1]["event_hash"]


def test_cleanup_denied_for_session_not_in_receipt(relay_env):
    events = _full_chain(relay_env)
    rp = _issue(relay_env, events)
    a = relay_env["service"].authorize_cleanup(
        package=rp["package"],
        local_events=[{"session_id": "OTHER", "revision": 1,
                       "event_hash": "dd" * 32}])
    assert a["denied"][0]["reason"] == "SESSION_NOT_IN_RECEIPT"


def test_cleanup_denied_for_expired_receipt(relay_env):
    events = _full_chain(relay_env)
    rp = _issue(relay_env, events, ttl=10)
    a = relay_env["service"].authorize_cleanup(
        package=rp["package"],
        local_events=[{"session_id": "PKG-1", "revision": 1,
                       "event_hash": events[0]["event_hash"]}],
        at="2030-01-01T00:00:00Z")
    assert a["code"] == "RECEIPT_EXPIRED"
    assert a["authorized"] is False


def test_cleanup_denied_for_forged_package(relay_env):
    events = _full_chain(relay_env)
    rp = _issue(relay_env, events)
    pkg = copy.deepcopy(rp["package"])
    pkg["signature"] = "00" * 64
    a = relay_env["service"].authorize_cleanup(
        package=pkg,
        local_events=[{"session_id": "PKG-1", "revision": 1,
                       "event_hash": events[0]["event_hash"]}])
    assert a["code"] == "RECEIPT_INVALID"


def test_receipt_package_roundtrip_json(relay_env):
    events = _full_chain(relay_env)
    rp = _issue(relay_env, events)
    # 模拟文件下载/上传：JSON 序列化后再核验
    blob = json.dumps(rp["package"], ensure_ascii=False)
    assert verify_receipt_package(json.loads(blob))["valid"] is True
