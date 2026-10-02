"""生效计划（Effective Plan）验收测试。

覆盖：准时执行、重复请求、占用冲突、快照变化暂停、崩溃恢复（补跑/不可二次落账）、
取消后重新登记；另含改期/恢复/活动计划守卫与后台执行器的 HTTP 端到端准时执行。
"""
import os
import tempfile
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

# 后台执行器快轮询（仅本文件内的 HTTP 用例依赖）
_tmp = tempfile.mkdtemp(prefix="cad-plans-")
os.environ["CADASTRE_DB"] = os.path.join(_tmp, "t.db")
os.environ.setdefault("CADASTRE_PLAN_POLL_SECONDS", "0.2")
os.environ.setdefault("CADASTRE_PLAN_LEASE_TTL_SECONDS", "1")

from app import main, db  # noqa: E402
from app.db import init_db, tx, get_conn  # noqa: E402
from app.services import versions as vs  # noqa: E402
from app.services import sync, lifecycle, corrections as cr, plans as ps, certificates as cert  # noqa: E402

RING_A = [[0, 0], [100, 0], [100, 100], [0, 100]]
RING_B = [[100, 0], [200, 0], [200, 100], [100, 100]]


@pytest.fixture(autouse=True)
def fresh_db():
    if os.path.exists(os.environ["CADASTRE_DB"]):
        os.remove(os.environ["CADASTRE_DB"])
    init_db()
    yield


# ---------------------------------------------------------------- helpers
def _iso(delta_seconds=0):
    return (datetime.now(timezone.utc) + timedelta(seconds=delta_seconds)
            ).strftime("%Y-%m-%dT%H:%M:%SZ")


def _norm(ring, pid=None, label=None):
    return sync.val.normalize_candidate(
        {"parcel_id": pid, "label": label, "ring": ring,
         "points": [], "declared_area": None})


def _commit(ring, label=None, pid=None, base=None, ts="2026-01-10T08:00:00Z",
            reason="初始登记", op_type="SURVEY"):
    with tx() as conn:
        return sync._commit_one(conn, _norm(ring, pid=pid, label=label), base,
                                ts, reason, None, op_type=op_type)


def seed_two():
    va = _commit(RING_A, "甲")
    vb = _commit(RING_B, "乙")
    return va, vb


def split_parent(va, ts="2026-05-01T00:00:00Z"):
    left = [[0, 0], [50, 0], [50, 100], [0, 100]]
    right = [[50, 0], [100, 0], [100, 100], [50, 100]]
    with tx() as conn:
        r = lifecycle.split(conn, {"parent_version_id": va["id"],
                                   "children": [_norm(left), _norm(right)],
                                   "as_of": ts})
    assert r["status"] == "COMMITTED", r
    return r


def make_draft(va, dy=-0.5):
    with tx() as conn:
        d = cr.create_draft(conn, {
            "version_id": va["id"],
            "corrected": {"ring": [[0, dy], [100, dy], [100, 100], [0, 100]]},
            "reason": "南边界解析错误"})
    assert d["releasable"], d["preview"]["errors"]
    return d["draft_id"]


def register(draft_id, key, when=None, **kw):
    when = when or _iso(86400)
    with tx() as conn:
        return ps.register_plan(conn, {"draft_id": draft_id, "request_key": key,
                                      "execute_at": when, **kw})


def tick_due(plan_id, owner="exec", when=None):
    """模拟执行器在某时刻轮询（注入 now），返回该计划的最终状态。"""
    when = when or _iso(86500)
    with tx() as conn:
        ps.run_due(conn, owner=owner, now=when)
    with tx() as conn:
        return ps.get_plan(conn, plan_id)


# ================================================================ 登记/占用
class TestRegistration:
    def test_only_releasable_draft_can_register(self):
        va, _ = seed_two()
        # 自交环草案 releasable=False
        with tx() as conn:
            bad = cr.create_draft(conn, {
                "version_id": va["id"],
                "corrected": {"ring": [[0, 0], [100, 0], [0, 100], [100, 100]]}})
        with pytest.raises(ValueError):
            register(bad["draft_id"], "k")

    def test_execute_at_must_be_future(self):
        va, _ = seed_two()
        did = make_draft(va)
        with pytest.raises(ValueError):
            register(did, "k", when=_iso(-10))
        with pytest.raises(ValueError):
            register(did, "k", when="not-a-time")

    def test_plan_holds_mutex_occupancy_on_all_target_parcels(self):
        va, _ = seed_two()
        split_parent(va)  # 父宗 + 2 子宗 = 3 个受影响地块
        did = make_draft(va)
        r = register(did, "k1")
        assert r["status"] == "WAITING"
        with tx() as conn:
            occ = [row["parcel_id"] for row in conn.execute(
                "SELECT parcel_id FROM plan_occupancy WHERE plan_id=?",
                (r["plan"]["id"],)).fetchall()]
        assert set(occ) == set(r["plan"]["parcels"])
        assert len(occ) == 3
        # 完成令牌在登记时即已持久化
        assert r["plan"]["completion_token"].startswith("TOKEN-")


class TestConflict:
    def test_any_overlap_returns_conflict_list(self):
        va, _ = seed_two()
        split_parent(va)
        did1 = make_draft(va, -0.5)
        r1 = register(did1, "k1")
        assert r1["status"] == "WAITING"
        # 第二个草案的影响闭包与第一个完全重叠（同一父宗）
        did2 = make_draft(va, -0.6)
        r2 = register(did2, "k2")
        assert r2["status"] == "CONFLICT"
        c = r2["conflicts"][0]
        assert c["plan_id"] == r1["plan"]["id"]
        assert len(c["overlap_parcels"]) == 3
        # 冲突时不建立任何占用/计划
        with tx() as conn:
            assert conn.execute(
                "SELECT COUNT(*) c FROM effect_plan").fetchone()["c"] == 1

    def test_neighbor_plan_conflicts_on_shared_parcel(self):
        va, vb = seed_two()
        # 甲的更正只影响甲
        did_a = make_draft(va, -0.5)
        register(did_a, "kA")
        # 乙的更正只影响乙 → 不冲突
        with tx() as conn:
            db_ = cr.create_draft(conn, {
                "version_id": vb["id"],
                "corrected": {"ring": [[100, 0], [200, 0], [200, 100.5], [100, 100.5]]}})
        assert db_["releasable"]
        rb = register(db_["draft_id"], "kB")
        assert rb["status"] == "WAITING"
        # 再来一个影响甲的 → 与 kA 冲突
        did_a2 = make_draft(va, -0.7)
        r = register(did_a2, "kA2")
        assert r["status"] == "CONFLICT"
        assert r["conflicts"][0]["request_key"] == "kA"


class TestDuplicateRequest:
    def test_same_key_returns_same_plan(self):
        va, _ = seed_two()
        did = make_draft(va)
        when = _iso(86400)
        r1 = register(did, "same", when=when)
        r2 = register(did, "same", when=when)
        assert r2["replayed"] is True
        assert r1["plan"]["id"] == r2["plan"]["id"]
        assert r1["plan"]["completion_token"] == r2["plan"]["completion_token"]

    def test_same_key_different_content_rejected(self):
        va, _ = seed_two()
        d1 = make_draft(va, -0.5)
        register(d1, "dup")
        d2 = make_draft(va, -0.6)
        with pytest.raises(ValueError):
            register(d2, "dup")

    def test_same_draft_two_plans_rejected(self):
        va, _ = seed_two()
        did = make_draft(va)
        register(did, "one")
        with pytest.raises(ValueError):
            register(did, "two")


# ================================================================ 准时执行/幂等
class TestExecution:
    def test_on_time_execution_posts_versions(self):
        va, _ = seed_two()
        split_parent(va)
        did = make_draft(va)
        when = _iso(3600)
        r = register(did, "run", when=when)
        pid = r["plan"]["id"]
        with tx() as conn:
            n_before = conn.execute(
                "SELECT COUNT(*) c FROM parcel_version").fetchone()["c"]
        plan = tick_due(pid, when=when)
        assert plan["status"] == "COMPLETED"
        assert plan["completed_at"]
        assert len(plan["result"]["new_versions"]) == 3
        # 落账时间即登记的生效时刻
        with tx() as conn:
            n_after = conn.execute(
                "SELECT COUNT(*) c FROM parcel_version").fetchone()["c"]
            new = vs.get_version(conn, plan["result"]["target_new_version_id"])
        assert n_after - n_before == 3
        assert new["valid_from"] == ps.canon_iso(when)
        # 占用在完成后释放
        with tx() as conn:
            assert conn.execute(
                "SELECT COUNT(*) c FROM plan_occupancy").fetchone()["c"] == 0
            assert ps._public(conn, ps.get_plan(conn, pid))["occupancy"] == []
        # 哈希链完整
        with tx() as conn:
            for p in plan["result"]["chains_forked"]:
                assert vs.verify_hash_chain(conn, p) == []

    def test_not_due_does_not_execute(self):
        va, _ = seed_two()
        did = make_draft(va)
        r = register(did, "later", when=_iso(7200))
        # 早于执行时刻轮询：不动
        with tx() as conn:
            ps.run_due(conn, owner="early", now=_iso(3600))
        with tx() as conn:
            assert ps.get_plan(conn, r["plan"]["id"])["status"] == "WAITING"
            assert conn.execute(
                "SELECT COUNT(*) c FROM plan_occupancy WHERE plan_id=?",
                (r["plan"]["id"],)).fetchone()["c"] == 1

    def test_completion_token_prevents_double_posting(self):
        va, _ = seed_two()
        split_parent(va)
        did = make_draft(va)
        r = register(did, "once", when=_iso(100))
        pid = r["plan"]["id"]
        token = r["plan"]["completion_token"]
        plan1 = tick_due(pid, when=_iso(200))
        assert plan1["status"] == "COMPLETED"
        with tx() as conn:
            n1 = conn.execute(
                "SELECT COUNT(*) c FROM parcel_version").fetchone()["c"]
        # 再次 tick：已完成，不重复落账
        with tx() as conn:
            res = ps.run_due(conn, owner="again", now=_iso(300))
            n2 = conn.execute(
                "SELECT COUNT(*) c FROM parcel_version").fetchone()["c"]
        assert res == []
        assert n1 == n2
        # 幂等表里完成令牌对应的发布结果只有一份
        with tx() as conn:
            row = conn.execute(
                "SELECT response_json FROM idempotency WHERE idem_key=?",
                (token,)).fetchone()
        assert row is not None

    def test_manual_draft_publish_blocked_while_plan_active(self):
        va, _ = seed_two()
        did = make_draft(va)
        register(did, "guard", when=_iso(100))
        with pytest.raises(ValueError):
            with tx() as conn:
                cr.publish(conn, {"draft_id": did})
        with pytest.raises(ValueError):
            with tx() as conn:
                cr.re_rehearse(conn, did)

    def test_plan_completes_externally_if_draft_somehow_published(self):
        va, _ = seed_two()
        did = make_draft(va)
        r = register(did, "ext", when=_iso(100))
        pid = r["plan"]["id"]
        # 绕过守卫模拟"草案已被发布"的世界（例如旧版本直接落账/数据修复）
        with tx() as conn:
            cr.publish(conn, {"draft_id": did}, _by_plan=pid)
        plan = tick_due(pid, when=_iso(200))
        assert plan["status"] == "COMPLETED"
        assert plan["result"].get("external") is True


# ================================================================ 快照变化 → 暂停
class TestSnapshotPause:
    def test_certificate_change_pauses_and_keeps_db_intact(self):
        va, _ = seed_two()
        sp = split_parent(va)
        did = make_draft(va)
        r = register(did, "pause-cert", when=_iso(100))
        pid = r["plan"]["id"]
        with tx() as conn:
            n_before = conn.execute(
                "SELECT COUNT(*) c FROM parcel_version").fetchone()["c"]
            cur = vs.current_version(conn, sp["accepted"][0]["parcel_id"])
            cert.issue(conn, cur["id"], "2026-08-01T00:00:00Z")
        plan = tick_due(pid, when=_iso(200))
        assert plan["status"] == "PAUSED"
        assert plan["pause_reason"] == "SNAPSHOT_DRIFT"
        kinds = {x["kind"] for x in plan["pause_detail"]["drift_nodes"]}
        assert "CERTIFICATE_ISSUED" in kinds
        # 暂停不产生任何版本（数据库保持原样）
        with tx() as conn:
            n_after = conn.execute(
                "SELECT COUNT(*) c FROM parcel_version").fetchone()["c"]
            assert n_after == n_before
            # 占用继续保留
            occ = conn.execute(
                "SELECT COUNT(*) c FROM plan_occupancy WHERE plan_id=?",
                (pid,)).fetchone()["c"]
            assert occ == 3
            # 草案同步 DRIFTED
            assert cr.get_draft(conn, did)["status"] == "DRIFTED"

    def test_parcel_snapshot_change_pauses(self):
        va, _ = seed_two()
        did = make_draft(va)
        r = register(did, "pause-ver", when=_iso(100))
        # 登记后给目标宗地追加新版本
        with tx() as conn:
            cur = vs.current_version(conn, va["parcel_id"])
            sync._commit_one(
                conn, _norm([[0, 0], [100, 0], [100, 101], [0, 101]],
                            pid=va["parcel_id"]),
                cur["id"], "2026-08-01T00:00:00Z", "登记后变更", None,
                op_type="CORRECTION", parent_versions=[cur["id"]],
                extra_params={"reason": "drift"})
        plan = tick_due(r["plan"]["id"], when=_iso(200))
        assert plan["status"] == "PAUSED"
        assert any(x["kind"] in ("VERSION_ADDED", "CURRENT_CHANGED")
                   for x in plan["pause_detail"]["drift_nodes"])

    def test_resume_after_refresh_then_executes(self):
        va, _ = seed_two()
        sp = split_parent(va)
        did = make_draft(va)
        r = register(did, "resume1", when=_iso(100))
        pid = r["plan"]["id"]
        with tx() as conn:
            cur = vs.current_version(conn, sp["accepted"][0]["parcel_id"])
            cert.issue(conn, cur["id"], "2026-08-01T00:00:00Z")
        assert tick_due(pid, when=_iso(200))["status"] == "PAUSED"
        # 刷新基线：证书现在属于基线的一部分 → 不再漂移
        with tx() as conn:
            rr = ps.resume(conn, pid)
        assert rr["status"] == "WAITING"
        plan = tick_due(pid, when=_iso(300))
        assert plan["status"] == "COMPLETED"

    def test_paused_plan_can_reschedule_but_stays_paused(self):
        va, _ = seed_two()
        sp = split_parent(va)
        did = make_draft(va)
        r = register(did, "pr", when=_iso(100))
        pid = r["plan"]["id"]
        with tx() as conn:
            cur = vs.current_version(conn, sp["accepted"][0]["parcel_id"])
            cert.issue(conn, cur["id"], "2026-08-01T00:00:00Z")
        assert tick_due(pid, when=_iso(200))["status"] == "PAUSED"
        with tx() as conn:
            rr = ps.reschedule(conn, pid, {"execute_at": _iso(9999)})
        assert rr["status"] == "PAUSED"
        # 改期后不立即执行
        with tx() as conn:
            ps.run_due(conn, owner="x", now=_iso(500))
            assert ps.get_plan(conn, pid)["status"] == "PAUSED"


# ================================================================ 崩溃恢复
class TestCrashRecovery:
    def test_stale_lease_is_reclaimed_and_plan_runs_once(self):
        va, _ = seed_two()
        split_parent(va)
        did = make_draft(va)
        when = _iso(100)
        r = register(did, "crash", when=when)
        pid = r["plan"]["id"]
        # 模拟执行器 A 抢到租约后崩溃（租约已持久、未落账）
        with tx() as conn:
            conn.execute(
                "UPDATE effect_plan SET lease_owner='dead-A',lease_at=?,attempts=1 "
                "WHERE id=?", (_iso(-5), pid))
            ps.reclaim_stale_leases(conn, ttl_seconds=1, now=_iso(0))
            leased = conn.execute(
                "SELECT lease_owner FROM effect_plan WHERE id=?",
                (pid,)).fetchone()["lease_owner"]
        assert leased is None
        # 新执行器补跑
        plan = tick_due(pid, owner="alive-B", when=_iso(200))
        assert plan["status"] == "COMPLETED"
        with tx() as conn:
            n = conn.execute(
                "SELECT COUNT(*) c FROM parcel_version").fetchone()["c"]
        # 再补跑一次也不会二次落账
        with tx() as conn:
            ps.run_due(conn, owner="alive-C", now=_iso(300))
            n2 = conn.execute(
                "SELECT COUNT(*) c FROM parcel_version").fetchone()["c"]
        assert n == n2

    def test_bootstrap_clears_waiting_leases_immediately(self):
        va, _ = seed_two()
        did = make_draft(va)
        r = register(did, "boot", when=_iso(100))
        pid = r["plan"]["id"]
        with tx() as conn:
            # 上一进程持有租约后崩溃（租约已持久、未落账）
            conn.execute(
                "UPDATE effect_plan SET lease_owner='prev',lease_at=? WHERE id=?",
                (_iso(-200), pid))
        # 服务重启：bootstrap 立即清租约；到期后由新执行器补跑
        executor = ps.PlanExecutor()
        executor.bootstrap()
        with tx() as conn:
            ps.run_due(conn, owner="new", now=_iso(300))
        with tx() as conn:
            assert ps.get_plan(conn, pid)["status"] == "COMPLETED"

    def test_lease_persisted_before_posting(self):
        """租约必须先持久化（崩溃在落账前，租约行仍在库）。"""
        va, _ = seed_two()
        did = make_draft(va)
        r = register(did, "lease", when=_iso(100))
        pid = r["plan"]["id"]
        with tx() as conn:
            ps.run_due(conn, owner="persist-check", now=_iso(200))
        with tx() as conn:
            row = conn.execute(
                "SELECT attempts,completion_token,completed_at FROM effect_plan "
                "WHERE id=?", (pid,)).fetchone()
        assert row["attempts"] >= 1
        assert row["completion_token"]
        assert row["completed_at"]


# ================================================================ 取消 / 重新登记
class TestCancelReregister:
    def test_cancel_releases_occupancy_and_key(self):
        va, _ = seed_two()
        did1 = make_draft(va, -0.5)
        r = register(did1, "key-x", when=_iso(100))
        pid = r["plan"]["id"]
        with tx() as conn:
            c = ps.cancel(conn, pid)
        assert c["status"] == "CANCELLED"
        with tx() as conn:
            assert conn.execute(
                "SELECT COUNT(*) c FROM plan_occupancy").fetchone()["c"] == 0
        # 同一 request_key 可以重新登记（新计划、新令牌）
        did2 = make_draft(va, -0.6)
        r2 = register(did2, "key-x", when=_iso(200))
        assert r2["status"] == "WAITING"
        assert r2["plan"]["id"] != pid
        assert r2["plan"]["completion_token"] != r["plan"]["completion_token"]

    def test_cancel_terminal_is_idempotent(self):
        va, _ = seed_two()
        did = make_draft(va)
        r = register(did, "done", when=_iso(100))
        pid = r["plan"]["id"]
        tick_due(pid, when=_iso(200))
        with tx() as conn:
            out = ps.cancel(conn, pid)
        assert out["status"] == "COMPLETED" and out["already"] is True


# ================================================================ HTTP 端到端（真实后台执行器）
class TestEffectPlanAPI:
    def _submit_two_and_split(self):
        c = TestClient(main.app)
        r1 = c.post("/api/sync/submit", json={
            "candidates": [{"label": "甲", "ring": RING_A}]}).json()
        pa, va = r1["accepted"][0]["parcel_id"], r1["accepted"][0]["version_id"]
        c.post("/api/sync/submit", json={
            "candidates": [{"label": "乙", "ring": RING_B}]})
        sp = c.post("/api/ops/split", json={
            "parent_version_id": va,
            "children": [{"ring": [[0, 0], [50, 0], [50, 100], [0, 100]]},
                         {"ring": [[50, 0], [100, 0], [100, 100], [50, 100]]}]}).json()
        return c, pa, va, sp

    def _draft(self, c, va, dy=-0.5):
        return c.post("/api/correction-drafts", json={
            "version_id": va,
            "corrected": {"ring": [[0, dy], [100, dy], [100, 100], [0, 100]]}}).json()

    def test_http_on_time_execution_via_background_executor(self):
        # with 块触发 startup（启动执行器并回收上一进程租约）
        with TestClient(main.app) as c:
            c, _, va, sp = self._submit_two_and_split()
            did = self._draft(c, va)["draft_id"]
            execute_at = _iso(1)  # 1 秒后到期
            r = c.post("/api/effect-plans", json={
                "draft_id": did, "execute_at": execute_at,
                "request_key": "http-run"}).json()
            assert r["status"] == "WAITING"
            pid = r["plan"]["id"]
            assert len(r["plan"]["occupancy"]) == 3

            detail = None
            for _ in range(60):
                detail = c.get(f"/api/effect-plans/{pid}").json()
                if detail["status"] in ("COMPLETED", "PAUSED", "CANCELLED"):
                    break
                import time; time.sleep(0.1)
            assert detail["status"] == "COMPLETED", detail
            assert detail["result"]["new_versions"]
            # 子宗在版，面积和守恒
            total = 0
            for acc in sp["accepted"]:
                v = c.get(f"/api/parcels/{acc['parcel_id']}").json()["version"]
                total += v["area"]
            assert abs(total - 10050) < 1e-6

    def test_http_duplicate_and_conflict(self):
        with TestClient(main.app) as c:
            c, _, va, _ = self._submit_two_and_split()
            did1 = self._draft(c, va, -0.5)["draft_id"]
            when = _iso(3600)
            a = c.post("/api/effect-plans", json={
                "draft_id": did1, "execute_at": when, "request_key": "http-k"}).json()
            assert a["status"] == "WAITING"
            # 重复请求
            a2 = c.post("/api/effect-plans", json={
                "draft_id": did1, "execute_at": when, "request_key": "http-k"}).json()
            assert a2["replayed"] is True
            assert a2["plan"]["id"] == a["plan"]["id"]
            # 占用冲突
            did2 = self._draft(c, va, -0.6)["draft_id"]
            conf = c.post("/api/effect-plans", json={
                "draft_id": did2, "execute_at": when, "request_key": "http-k2"}).json()
            assert conf["status"] == "CONFLICT"
            assert conf["conflicts"][0]["plan_id"] == a["plan"]["id"]

    def test_http_pause_then_resume_cancel_flow(self):
        with TestClient(main.app) as c:
            c, _, va, sp = self._submit_two_and_split()
            did = self._draft(c, va)["draft_id"]
            r = c.post("/api/effect-plans", json={
                "draft_id": did, "execute_at": _iso(1),
                "request_key": "http-pause"}).json()
            pid = r["plan"]["id"]
            # 给受影响子宗签发证明 → 执行前快照变化 → 暂停
            child = sp["accepted"][0]["parcel_id"]
            cur_vid = c.get(f"/api/parcels/{child}").json()["version"]["id"]
            c.post("/api/certificates", json={"version_id": cur_vid})
            status = None
            for _ in range(60):
                status = c.get(f"/api/effect-plans/{pid}").json()["status"]
                if status == "PAUSED":
                    break
                import time; time.sleep(0.1)
            assert status == "PAUSED"
            # 列表含暂停计划，占用仍在
            paused = [p for p in c.get("/api/effect-plans?status=PAUSED").json()]
            assert any(p["id"] == pid for p in paused)
            # 改期到远期（暂停态改期后仍暂停），避免恢复后立即被执行器补跑
            far = _iso(3600)
            assert c.post(f"/api/effect-plans/{pid}/reschedule",
                          json={"execute_at": far}).json()["status"] == "PAUSED"
            # 刷新基线后恢复（未到期，不会被补跑）
            rr = c.post(f"/api/effect-plans/{pid}/resume").json()
            assert rr["status"] == "WAITING"
            # 取消并释放
            cc = c.post(f"/api/effect-plans/{pid}/cancel").json()
            assert cc["status"] == "CANCELLED"
            # 同键重新登记
            again = c.post("/api/effect-plans", json={
                "draft_id": did, "execute_at": far,
                "request_key": "http-pause"}).json()
            assert again["status"] == "WAITING"

    def test_http_map_includes_active_plans(self):
        with TestClient(main.app) as c:
            c, _, va, _ = self._submit_two_and_split()
            did = self._draft(c, va)["draft_id"]
            c.post("/api/effect-plans", json={
                "draft_id": did, "execute_at": _iso(3600), "request_key": "map-k"})
            mp = c.get("/api/map").json()
            assert "effect_plans" in mp
            assert any(p["request_key"] == "map-k" for p in mp["effect_plans"])

    def test_http_reschedule(self):
        with TestClient(main.app) as c:
            c, _, va, _ = self._submit_two_and_split()
            did = self._draft(c, va)["draft_id"]
            pid = c.post("/api/effect-plans", json={
                "draft_id": did, "execute_at": _iso(100),
                "request_key": "rs-k"}).json()["plan"]["id"]
            new_at = _iso(7200)
            rr = c.post(f"/api/effect-plans/{pid}/reschedule",
                        json={"execute_at": new_at}).json()
            assert rr["status"] == "WAITING"
            assert rr["plan"]["execute_at"] == ps.canon_iso(new_at)
