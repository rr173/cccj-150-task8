"""网页/联调演示支持：内置模拟发送方。

真实部署中发送方在自己的站点对事件哈希签名后推送到中继；网页界面为
零外部依赖（不内置 JS 版 Ed25519），由这些演示端点持有一把**演示用
发送方私钥**，按页面输入对事件签名，再走与真实完全相同的
``service.push_events`` 管线。生产环境不应暴露这些端点。
"""
from __future__ import annotations

from . import service
from .cli import load_or_create_sender, make_event

DEMO_INSTITUTION = "DEMO-IN"
HAPPY_SENDER = "demo-site"
HAPPY_SESSION = "PKG-HAPPY"
CONFLICT_SESSION = "PKG-CONFLICT"
HEALTHY_SESSION = "PKG-HEALTHY"

# 完整正向链（与 cli demo 一致）
HAPPY_SPEC = [
    ("CREATE", 1, "UPLOADING", None),
    ("CHUNK_ACCEPTED", 1, "UPLOADING",
     {"seq": 1, "sha256": "aa" * 8}),
    ("CHUNK_ACCEPTED", 1, "READY",
     {"seq": 2, "sha256": "bb" * 8}),
    ("CHUNK_REJECTED", 1, "UPLOADING",
     {"seq": 3, "code": "CHUNK_CONTENT_MISMATCH", "expected": "cc" * 8}),
    ("HANDOVER", 2, "UPLOADING", {"from": "alice", "to": "bob"}),
    ("FINALIZE_ACCEPTED", 3, "IMPORTED", {"imported_versions": 4}),
]

CONFLICT_SPEC = [
    ("CREATE", 1, "UPLOADING", {"note": "正确版本"}),
    ("CHUNK_ACCEPTED", 1, "READY", {"seq": 1}),
    ("FINALIZE_ACCEPTED", 2, "IMPORTED", {"imported_versions": 1}),
]


def ensure_demo_institution():
    from . import crypto
    try:
        crypto.create_institution_keys(DEMO_INSTITUTION, overwrite=False)
    except crypto.KeyExistsError:
        pass


def ensure_demo_sender(sender_id: str = HAPPY_SENDER) -> dict:
    ensure_demo_institution()
    seed, pubhex = load_or_create_sender(sender_id, f"网页模拟发送方-{sender_id}")
    return {"seed": seed, "public_key": pubhex, "sender_id": sender_id}


def _chain(seed, sender, session, spec, *, ts_prefix="2026-10-02T12:00"):
    out, prev = [], None
    for i, (et, ver, st, det) in enumerate(spec, 1):
        out.append(make_event(
            seed, sender_id=sender, session_id=session, revision=i,
            event_type=et, session_version=ver, state=st,
            prev_event_hash=prev, occurred_at=f"{ts_prefix}:{i:02d}Z",
            detail=det))
        prev = out[-1]["event_hash"]
    return out


# ---- 正向场景：乱序缺口 -> 补传 -> 完成 ----------------------------------

def happy_init(sender_id=HAPPY_SENDER, session=HAPPY_SESSION):
    ctx = ensure_demo_sender(sender_id)
    events = _chain(ctx["seed"], sender_id, session, HAPPY_SPEC)
    # 只推 rev 1 与 rev 3：rev2 缺口、rev3 WAITING
    r = service.push_events(sender_id, [events[0], events[2]],
                            batch_id="demo-happy-init")
    return {"pushed_revisions": [1, 3], "result": r,
            "chain_head_hint": None}


def happy_fill_gap(revision: int = 2, sender_id=HAPPY_SENDER,
                   session=HAPPY_SESSION):
    ctx = ensure_demo_sender(sender_id)
    events = _chain(ctx["seed"], sender_id, session, HAPPY_SPEC)
    r = service.push_events(sender_id, [events[revision - 1]],
                            batch_id=f"demo-happy-fill-{revision}")
    return {"pushed_revisions": [revision], "result": r}


def happy_finish(sender_id=HAPPY_SENDER, session=HAPPY_SESSION):
    ctx = ensure_demo_sender(sender_id)
    events = _chain(ctx["seed"], sender_id, session, HAPPY_SPEC)
    r = service.push_events(sender_id, events[3:], batch_id="demo-happy-finish")
    return {"pushed_revisions": [4, 5, 6], "result": r}


# ---- 隔离场景：同序号异内容 -> 隔离 -> 撤回误版恢复 -----------------------

def conflict_init(sender_id=HAPPY_SENDER, session=CONFLICT_SESSION):
    ctx = ensure_demo_sender(sender_id)
    seed = ctx["seed"]
    # 误版 rev1 与正确 rev1 **同批**推送：同序号异内容，两者都只留证、
    # 均不确认（水位停 0），恢复时撤回误版即可让正确版进链。
    bad = make_event(
        seed, sender_id=sender_id, session_id=session, revision=1,
        event_type="CREATE", session_version=1, state="UPLOADING",
        prev_event_hash=None, occurred_at="2026-10-02T12:59:59Z",
        detail={"note": "误版", "bogus": True})
    good = make_event(
        seed, sender_id=sender_id, session_id=session, revision=1,
        event_type="CREATE", session_version=1, state="UPLOADING",
        prev_event_hash=None, occurred_at="2026-10-02T13:00:01Z",
        detail={"note": "正确版本"})
    r = service.push_events(sender_id, [bad, good],
                            batch_id="demo-conf-batch")
    # 另一会话保持健康，证明隔离不跨会话
    healthy = _chain(seed, sender_id, HEALTHY_SESSION,
                     [("CREATE", 1, "UPLOADING", None),
                      ("CHUNK_ACCEPTED", 1, "READY", {"seq": 1})])
    r_health = service.push_events(sender_id, healthy,
                                   batch_id="demo-healthy")
    return {"bad_event_hash": bad["event_hash"],
            "good_event_hash": good["event_hash"],
            "conflict_result": r, "healthy_result": r_health}


def conflict_recover(sender_id=HAPPY_SENDER, session=CONFLICT_SESSION):
    ctx = ensure_demo_sender(sender_id)
    seed = ctx["seed"]
    d = service.session_detail(sender_id, session)
    detail = d.get("quarantine_detail") or {}
    hashes = detail.get("distinct_hashes")
    good = make_event(
        seed, sender_id=sender_id, session_id=session, revision=1,
        event_type="CREATE", session_version=1, state="UPLOADING",
        prev_event_hash=None, occurred_at="2026-10-02T13:00:01Z",
        detail={"note": "正确版本"})
    if not hashes:
        return {"error": "会话未处于同序号异内容隔离状态，无法执行演示恢复",
                "quarantine_reason": d.get("quarantine_reason"),
                "watermark": d["watermark"]}
    discard = [h for h in hashes if h != good["event_hash"]]
    rel = service.release_quarantine(
        sender_id, session, note="演示：确认正确版本、撤回误版",
        discard_event_hashes={1: discard})
    # 推送续链 rev2、rev3（prev 必须锚定已确认的正确 rev1 哈希）
    rev2 = make_event(
        seed, sender_id=sender_id, session_id=session, revision=2,
        event_type="CHUNK_ACCEPTED", session_version=1, state="READY",
        prev_event_hash=good["event_hash"],
        occurred_at="2026-10-02T13:00:02Z", detail={"seq": 1})
    rev3 = make_event(
        seed, sender_id=sender_id, session_id=session, revision=3,
        event_type="FINALIZE_ACCEPTED", session_version=2,
        state="IMPORTED", prev_event_hash=rev2["event_hash"],
        occurred_at="2026-10-02T13:00:03Z",
        detail={"imported_versions": 1})
    r = service.push_events(sender_id, [rev2, rev3],
                            batch_id="demo-conf-fix")
    return {"discard_event_hashes": discard, "release": rel,
            "continuation_result": r}


# ---- 自由事件（带签名） ---------------------------------------------------

def signed_push(*, sender_id: str, session_id: str, revision: int,
                event_type: str, session_version: int, state: str,
                prev: str | None, occurred_at: str, detail,
                batch_id: str | None = None):
    """prev: "auto" 取该会话当前链顶；None 显式空链；hex 字符串显式指定。"""
    ctx = ensure_demo_sender(sender_id)
    if prev == "auto":
        try:
            d = service.session_detail(sender_id, session_id)
            prev_hash = (d["confirmed_events"][-1]["event_hash"]
                         if d["confirmed_events"] else None)
        except service.RelayError:
            prev_hash = None
    else:
        prev_hash = prev
    e = make_event(
        ctx["seed"], sender_id=sender_id, session_id=session_id,
        revision=revision, event_type=event_type,
        session_version=session_version, state=state,
        prev_event_hash=prev_hash, occurred_at=occurred_at, detail=detail)
    r = service.push_events(sender_id, [e], batch_id=batch_id)
    return {"event": e, "result": r, "resolved_prev": prev_hash}
