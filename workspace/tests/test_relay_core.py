"""回执中继：事件接收、乱序/重复/批量重放、连续水位与隔离。"""
from __future__ import annotations

import pytest

from app.relay import service


def _by_rev(result):
    return {r["revision"]: r for r in result["results"]}


def test_in_order_chain_advances_watermark(relay_env):
    svc, seed = relay_env["service"], relay_env["seed"]
    events = relay_env["chain"](seed, [
        ("CREATE", 1, "UPLOADING", None),
        ("CHUNK_ACCEPTED", 1, "READY", {"seq": 1}),
        ("FINALIZE_ACCEPTED", 2, "IMPORTED", None),
    ])
    r = svc.push_events("site-A", events, batch_id="b1")
    assert r["counts"] == {"ACCEPTED": 3}
    d = svc.session_detail("site-A", "PKG-1")
    assert d["watermark"] == 3
    assert d["state"] == "IMPORTED"
    assert d["closed"] is True
    # 链上 prev 链接连续
    prev = None
    for e in d["confirmed_events"]:
        assert e["prev_event_hash"] == prev
        prev = e["event_hash"]


def test_out_of_order_gap_does_not_quarantine_and_fills_later(relay_env):
    svc, seed = relay_env["service"], relay_env["seed"]
    events = relay_env["chain"](seed, [
        ("CREATE", 1, "UPLOADING", None),
        ("CHUNK_ACCEPTED", 1, "UPLOADING", {"seq": 1}),
        ("CHUNK_ACCEPTED", 1, "READY", {"seq": 2}),
    ])
    r = svc.push_events("site-A", [events[0], events[2]])
    by = _by_rev(r)
    assert by[1]["outcome"] == "ACCEPTED"
    assert by[3]["outcome"] == "WAITING"          # 缺口 rev2
    assert by[3]["detail"]["missing_from"] == 2
    d = svc.session_detail("site-A", "PKG-1")
    assert d["watermark"] == 1                    # 水位不乱跳
    assert d["quarantined"] is False
    assert d["missing_revisions"] == [2]

    r2 = svc.push_events("site-A", [events[1]])   # 补缺口
    assert r2["counts"] == {"ACCEPTED": 1}
    d = svc.session_detail("site-A", "PKG-1")
    assert d["watermark"] == 3                    # 连带把 rev3 确认


def test_duplicate_is_idempotent_no_double_confirm(relay_env):
    svc, seed = relay_env["service"], relay_env["seed"]
    events = relay_env["chain"](seed, [
        ("CREATE", 1, "UPLOADING", None),
        ("CHUNK_ACCEPTED", 1, "UPLOADING", None),
    ])
    svc.push_events("site-A", events, batch_id="b1")
    r = svc.push_events("site-A", events, batch_id="b1-replay")
    assert r["counts"] == {"DUPLICATE": 2}
    d = svc.session_detail("site-A", "PKG-1")
    assert d["watermark"] == 2
    assert len(d["confirmed_events"]) == 2       # 链上无重复行


def test_batch_replay_after_crash_response_loss(relay_env):
    """应答丢失导致整批重发：已确认的 DUPLICATE，未确认的照常推进。"""
    svc, seed = relay_env["service"], relay_env["seed"]
    events = relay_env["chain"](seed, [
        ("CREATE", 1, "UPLOADING", None),
        ("CHUNK_ACCEPTED", 1, "UPLOADING", None),
        ("CHUNK_ACCEPTED", 1, "READY", None),
    ])
    first = svc.push_events("site-A", events[:2], batch_id="batch-x")
    assert first["counts"] == {"ACCEPTED": 2}
    # 客户端没收到响应，把 rev1..3 整体重发
    replay = svc.push_events("site-A", events, batch_id="batch-x-retry")
    by = _by_rev(replay)
    assert by[1]["outcome"] == "DUPLICATE"
    assert by[2]["outcome"] == "DUPLICATE"
    assert by[3]["outcome"] == "ACCEPTED"
    assert svc.session_detail("site-A", "PKG-1")["watermark"] == 3


def test_same_revision_different_content_quarantines_with_locator(relay_env):
    svc, seed = relay_env["service"], relay_env["seed"]
    e1 = relay_env["make"](seed, revision=1, etype="CREATE", state="UPLOADING",
                           ts="t1", detail={"v": 1})
    e2 = relay_env["make"](seed, revision=1, etype="CREATE", state="READY",
                           ts="t2", detail={"v": 2})
    r = svc.push_events("site-A", [e1, e2])
    assert r["counts"] == {"QUARANTINED": 2}
    d = svc.session_detail("site-A", "PKG-1")
    assert d["quarantined"] is True
    assert d["quarantine_reason"] == "SAME_REV_DIFFERENT_CONTENT"
    loc = d["quarantine_detail"]
    assert loc["at_revision"] == 1
    assert set(loc["distinct_hashes"]) == {e1["event_hash"], e2["event_hash"]}
    assert d["watermark"] == 0


def test_forked_chain_quarantines_and_locates_prev_diff(relay_env):
    svc, seed = relay_env["service"], relay_env["seed"]
    e1 = relay_env["make"](seed, revision=1, etype="CREATE")
    # rev2 的 prev 指向一个不存在的哈希
    e2 = relay_env["make"](seed, revision=2, etype="CHUNK_ACCEPTED",
                           prev="00" * 32)
    svc.push_events("site-A", [e1])
    r = svc.push_events("site-A", [e2])
    assert r["results"][0]["outcome"] == "QUARANTINED"
    d = r["results"][0]["detail"]
    assert d["reason"] == "FORKED_CHAIN"
    assert d["at_revision"] == 2
    assert d["expected_prev"] == e1["event_hash"]
    assert d["actual_prev"] == "00" * 32
    assert svc.session_detail("site-A", "PKG-1")["watermark"] == 1


def test_bad_signature_quarantines(relay_env):
    svc, seed, seed_b = relay_env["service"], relay_env["seed"], relay_env["seed_b"]
    # 用 site-B 的私钥签 site-A 的事件
    e = relay_env["make"](seed_b, revision=1, etype="CREATE", sender="site-A")
    r = svc.push_events("site-A", [e])
    assert r["results"][0]["detail"]["reason"] == "BAD_SIGNATURE"
    assert svc.session_detail("site-A", "PKG-1")["quarantined"] is True


def test_tampered_event_hash_quarantines(relay_env):
    svc, seed = relay_env["service"], relay_env["seed"]
    e = relay_env["make"](seed, revision=1, etype="CREATE")
    e["event_hash"] = "ab" * 32  # 与内容不符
    r = svc.push_events("site-A", [e])
    assert r["results"][0]["detail"]["code"] == "EVENT_HASH_MISMATCH"
    assert svc.session_detail("site-A", "PKG-1")["quarantined"] is True


def test_illegal_version_transition_handover_must_increment(relay_env):
    svc, seed = relay_env["service"], relay_env["seed"]
    e1 = relay_env["make"](seed, revision=1, etype="CREATE", version=1)
    # HANDOVER 必须 version 1->2，这里仍报 1
    e2 = relay_env["make"](seed, revision=2, etype="HANDOVER", version=1,
                           prev=e1["event_hash"])
    svc.push_events("site-A", [e1])
    r = svc.push_events("site-A", [e2])
    assert r["results"][0]["detail"]["reason"] == "INVALID_TRANSITION"
    assert svc.session_detail("site-A", "PKG-1")["quarantined"] is True


def test_illegal_state_transition_rejected(relay_env):
    svc, seed = relay_env["service"], relay_env["seed"]
    e1 = relay_env["make"](seed, revision=1, etype="CREATE", state="UPLOADING")
    # CHUNK_ACCEPTED 不允许直接把状态置为 IMPORTED
    e2 = relay_env["make"](seed, revision=2, etype="CHUNK_ACCEPTED",
                           state="IMPORTED", prev=e1["event_hash"])
    svc.push_events("site-A", [e1])
    r = svc.push_events("site-A", [e2])
    assert r["results"][0]["detail"]["reason"] == "INVALID_TRANSITION"


def test_create_not_at_revision_one_quarantines(relay_env):
    svc, seed = relay_env["service"], relay_env["seed"]
    e1 = relay_env["make"](seed, revision=1, etype="CREATE")
    e2 = relay_env["make"](seed, revision=2, etype="CREATE",
                           prev=e1["event_hash"])
    svc.push_events("site-A", [e1])
    r = svc.push_events("site-A", [e2])
    assert r["results"][0]["detail"]["reason"] == "INVALID_TRANSITION"


def test_quarantine_does_not_block_other_sessions_or_senders(relay_env):
    svc, seed = relay_env["service"], relay_env["seed"]
    # site-A 的 PKG-BAD 隔离
    bad1 = relay_env["make"](seed, session="PKG-BAD", revision=1,
                             etype="CREATE", state="UPLOADING", ts="t1")
    bad2 = relay_env["make"](seed, session="PKG-BAD", revision=1,
                             etype="CREATE", state="READY", ts="t2")
    svc.push_events("site-A", [bad1, bad2])

    # 同发送方另一个会话正常
    good = relay_env["chain"](seed, [("CREATE", 1, "UPLOADING", None)],
                              session="PKG-GOOD")
    r = svc.push_events("site-A", good)
    assert r["counts"] == {"ACCEPTED": 1}

    # 另一个发送方的会话也正常
    other = relay_env["chain"](relay_env["seed_b"],
                               [("CREATE", 1, "UPLOADING", None)],
                               sender="site-B", session="PKG-X")
    r = svc.push_events("site-B", other)
    assert r["counts"] == {"ACCEPTED": 1}

    # 隔离会话后续推送只留证、不推进
    nxt = relay_env["make"](seed, session="PKG-BAD", revision=2,
                            etype="CHUNK_ACCEPTED", prev=bad2["event_hash"])
    r = svc.push_events("site-A", [nxt])
    assert r["results"][0]["outcome"] == "QUARANTINED"
    assert svc.session_detail("site-A", "PKG-BAD")["watermark"] == 0


def test_quarantine_recovery_by_discarding_wrong_variant(relay_env):
    svc, seed = relay_env["service"], relay_env["seed"]
    wrong = relay_env["make"](seed, revision=1, etype="CREATE", state="UPLOADING",
                              ts="t1", detail={"v": "wrong"})
    right = relay_env["make"](seed, revision=1, etype="CREATE", state="UPLOADING",
                              ts="t2", detail={"v": "right"})
    svc.push_events("site-A", [wrong, right])
    assert svc.session_detail("site-A", "PKG-1")["quarantined"] is True

    rel = svc.release_quarantine(
        "site-A", "PKG-1", note="撤回误版",
        discard_event_hashes={1: [wrong["event_hash"]]})
    assert rel["quarantined"] is False
    assert rel["watermark"] == 1
    assert rel["discarded"][0]["event_hash"] == wrong["event_hash"]

    e2 = relay_env["make"](seed, revision=2, etype="CHUNK_ACCEPTED",
                           prev=right["event_hash"])
    r = svc.push_events("site-A", [e2])
    assert r["counts"] == {"ACCEPTED": 1}
    assert svc.session_detail("site-A", "PKG-1")["watermark"] == 2


def test_cannot_discard_confirmed_event(relay_env):
    svc, seed = relay_env["service"], relay_env["seed"]
    e1 = relay_env["make"](seed, revision=1, etype="CREATE")
    svc.push_events("site-A", [e1])
    rel = svc.release_quarantine(
        "site-A", "PKG-1",
        discard_event_hashes={1: [e1["event_hash"]]})
    assert rel["refused"][0]["reason"] == "CONFIRMED_EVENT_IMMUTABLE"
    assert svc.session_detail("site-A", "PKG-1")["watermark"] == 1


def test_malformed_events_rejected(relay_env):
    svc = relay_env["service"]
    with pytest.raises(svc.RelayError) as ei:
        svc.push_events("site-A", [{"revision": 1}])
    assert ei.value.code == "MALFORMED_EVENT"
    with pytest.raises(svc.RelayError):
        svc.push_events("site-A", [])
    with pytest.raises(svc.RelayError) as ei:
        svc.push_events("site-A", [{"revision": 0, "session_id": "x",
                                    "event_type": "CREATE", "session_version": 1,
                                    "state": "UPLOADING", "occurred_at": "t",
                                    "event_hash": "a", "sender_signature": "b"}])
    assert ei.value.code == "MALFORMED_EVENT"


def test_sender_mismatch_and_unknown_sender(relay_env):
    svc, seed = relay_env["service"], relay_env["seed"]
    e = relay_env["make"](seed, sender="site-B")  # 内容声称 site-B
    with pytest.raises(svc.RelayError) as ei:
        svc.push_events("site-A", [e])
    assert ei.value.code == "SENDER_MISMATCH"
    ghost_event = relay_env["make"](seed, sender="ghost")
    with pytest.raises(svc.RelayError) as ei:
        svc.push_events("ghost", [ghost_event])
    assert ei.value.code == "UNKNOWN_SENDER"


def test_register_sender_replay_and_key_conflict(relay_env):
    svc, seed, pub_b = relay_env["service"], relay_env["seed"], relay_env["pub_b"]
    r = svc.register_sender("site-A", relay_env["pub"])
    assert r["replayed"] is True
    with pytest.raises(svc.RelayError) as ei:
        svc.register_sender("site-A", pub_b)
    assert ei.value.code == "SENDER_KEY_CONFLICT"


def test_unknown_session_detail_404(relay_env):
    with pytest.raises(relay_env["service"].RelayError) as ei:
        relay_env["service"].session_detail("site-A", "NOPE")
    assert ei.value.status == 404
