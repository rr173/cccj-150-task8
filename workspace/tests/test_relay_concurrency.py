"""回执中继：并发/崩溃一致性（不漏记、不重复确认、不跨会话串写）。"""
from __future__ import annotations

import json
import threading

from app.relay.store import tx


def test_concurrent_push_same_session_no_loss_no_double_confirm(relay_env):
    """10 个线程各自推一条不同 rev + 重复重放，最终水位必须精确到 10。"""
    svc, seed = relay_env["service"], relay_env["seed"]
    make = relay_env["make"]

    # 先建 rev1
    e1 = make(seed, session="CC", revision=1, etype="CREATE", ts="t1")
    svc.push_events("site-A", [e1])

    # rev2..10 事件
    events = []
    prev = e1["event_hash"]
    for i in range(2, 11):
        e = make(seed, session="CC", revision=i, etype="CHUNK_ACCEPTED",
                 state="READY" if i == 10 else "UPLOADING", prev=prev,
                 ts=f"t{i}")
        events.append(e)
        prev = e["event_hash"]

    errors = []

    def worker(e):
        try:
            # 每个事件推两次（模拟应答丢失后的重放）
            svc.push_events("site-A", [e], batch_id=f"cc-{e['revision']}")
            svc.push_events("site-A", [e], batch_id=f"cc-{e['revision']}-retry")
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(e,)) for e in events]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors, errors

    d = svc.session_detail("site-A", "CC")
    # 乱序推送时缺口会让高 rev 停在 WAITING，但所有 rev 都已只追加落盘；
    # 最后补推任意一个批次触发全量推进后水位必须到 10
    svc.push_events("site-A", events, batch_id="cc-final-replay")
    d = svc.session_detail("site-A", "CC")
    assert d["watermark"] == 10
    assert len(d["confirmed_events"]) == 10           # 无重复确认
    assert [e["revision"] for e in d["confirmed_events"]] == list(range(1, 11))
    # 链哈希连续
    prev = None
    for e in d["confirmed_events"]:
        assert e["prev_event_hash"] == prev
        prev = e["event_hash"]


def test_concurrent_push_different_sessions_no_cross_write(relay_env):
    svc, seed, seed_b = relay_env["service"], relay_env["seed"], relay_env["seed_b"]
    make = relay_env["make"]

    # 两个发送方各自一条链（事件按序构造），推送在两个线程中并发进行
    def chain_for(sender, sd, s):
        out, prev = [], None
        for i in range(1, 6):
            out.append(make(s, sender=sender, session=sd, revision=i,
                            etype="CREATE" if i == 1 else "CHUNK_ACCEPTED",
                            prev=prev, ts=f"{sender}{i}"))
            prev = out[-1]["event_hash"]
        return out

    ca = chain_for("site-A", "XA", seed)
    cb = chain_for("site-B", "XB", seed_b)

    def worker(events, sender):
        for e in events:
            svc.push_events(sender, [e])

    t1 = threading.Thread(target=worker, args=(ca, "site-A"))
    t2 = threading.Thread(target=worker, args=(cb, "site-B"))
    t1.start(); t2.start(); t1.join(); t2.join()
    # 乱序导致部分 WAITING；补推触发推进
    svc.push_events("site-A", ca)
    svc.push_events("site-B", cb)
    assert svc.session_detail("site-A", "XA")["watermark"] == 5
    assert svc.session_detail("site-B", "XB")["watermark"] == 5
    # 跨会话串写检查：各自链顶属于各自会话
    with tx() as conn:
        na = conn.execute(
            "SELECT COUNT(*) c FROM relay_event WHERE sender_id='site-A' "
            "AND session_id='XA'").fetchone()["c"]
        nb = conn.execute(
            "SELECT COUNT(*) c FROM relay_event WHERE sender_id='site-B' "
            "AND session_id='XB'").fetchone()["c"]
        cross = conn.execute(
            "SELECT COUNT(*) c FROM relay_event WHERE "
            "(sender_id='site-A' AND session_id='XB') OR "
            "(sender_id='site-B' AND session_id='XA')").fetchone()["c"]
    assert na == 5 and nb == 5 and cross == 0


def _hash(svc, sender, session, rev):
    return svc.session_detail(sender, session)["confirmed_events"][rev - 1]["event_hash"]


def test_raw_events_persist_even_when_gap_blocks_watermark(relay_env):
    """缺口后的乱序事件必须落盘留证（崩溃/重启后不丢），只是水位不推进。"""
    svc, seed = relay_env["service"], relay_env["seed"]
    make = relay_env["make"]
    e1 = make(seed, session="PERS", revision=1, etype="CREATE")
    # rev5（前序大量缺失）
    e5 = make(seed, session="PERS", revision=5, etype="CHUNK_ACCEPTED",
              prev="11" * 32, ts="t5")
    svc.push_events("site-A", [e1])
    r = svc.push_events("site-A", [e5])
    assert r["results"][0]["outcome"] == "WAITING"

    # 直接查原始事件表：rev5 已持久化
    with tx() as conn:
        row = conn.execute(
            "SELECT COUNT(*) c FROM relay_raw_event WHERE sender_id='site-A' "
            "AND session_id='PERS' AND revision=5").fetchone()
    assert row["c"] == 1

    # 水位仍只到 1
    assert svc.session_detail("site-A", "PERS")["watermark"] == 1
