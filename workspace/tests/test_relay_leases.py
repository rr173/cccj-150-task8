"""回执中继：工作实例领取租约（并发/TTL/跨会话不阻塞）。"""
from __future__ import annotations

import threading

import pytest


def _session(relay_env, sid):
    e = relay_env["make"](relay_env["seed"], session=sid, revision=1,
                          etype="CREATE")
    relay_env["service"].push_events("site-A", [e])
    return e


def test_concurrent_claims_only_one_wins(relay_env):
    svc = relay_env["service"]
    _session(relay_env, "L1")
    outcomes = []

    def claim(worker):
        try:
            svc.claim_session("L1", worker, "site-A")
            outcomes.append((worker, "won"))
        except svc.RelayError as exc:
            outcomes.append((worker, exc.code))

    threads = [threading.Thread(target=claim, args=(f"w{i}",)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    wins = [w for w, o in outcomes if o == "won"]
    holds = [o for _, o in outcomes if o == "LEASE_HELD"]
    assert len(wins) == 1
    assert len(holds) == 7


def test_same_worker_can_renew_lease(relay_env):
    svc = relay_env["service"]
    _session(relay_env, "L1")
    svc.claim_session("L1", "w0", "site-A")
    r = svc.claim_session("L1", "w0", "site-A")
    assert r["claims"][0]["claimed"] is True


def test_lease_takeover_after_ttl(relay_env):
    svc = relay_env["service"]
    _session(relay_env, "L1")
    svc.claim_session("L1", "w0", "site-A")
    import time
    time.sleep(0.05)
    r = svc.claim_session("L1", "w1", "site-A", ttl=0.01)
    assert r["claims"][0]["claimed"] is True
    assert r["claims"][0]["lease_owner"] == "w1"


def test_lease_is_per_session_not_global(relay_env):
    svc = relay_env["service"]
    _session(relay_env, "L1")
    _session(relay_env, "L2")
    svc.claim_session("L1", "w0", "site-A")
    # 另一个会话可被其他 worker 立即领取（租约不跨会话）
    r = svc.claim_session("L2", "w1", "site-A")
    assert r["claims"][0]["claimed"] is True


def test_release_lease_allows_takeover(relay_env):
    svc = relay_env["service"]
    _session(relay_env, "L1")
    svc.claim_session("L1", "w0", "site-A")
    svc.release_session_lease("L1", "w0", "site-A")
    r = svc.claim_session("L1", "w1", "site-A")
    assert r["claims"][0]["claimed"] is True


def test_claim_unknown_session(relay_env):
    with pytest.raises(relay_env["service"].RelayError) as ei:
        relay_env["service"].claim_session("GHOST", "w0", "site-A")
    assert ei.value.code == "SESSION_NOT_FOUND"
