"""端到端业务规则测试（每函数独立临时库）。"""
import json
import os
import tempfile

import pytest

_tmp = tempfile.mkdtemp(prefix="cadastre-test-")
os.environ["CADASTRE_DB"] = os.path.join(_tmp, "t.db")

from app import geo, config  # noqa: E402
from app.db import init_db, tx, get_conn  # noqa: E402
from app.services import versions as vs, sync, lifecycle, certificates as cert  # noqa: E402
from app.services import adjudication as adj, validation as val  # noqa: E402

RING_A = [[0, 0], [100, 0], [100, 100], [0, 100]]
RING_B = [[100, 0], [200, 0], [200, 100], [100, 100]]


@pytest.fixture(autouse=True)
def fresh_db():
    if os.path.exists(os.environ["CADASTRE_DB"]):
        os.remove(os.environ["CADASTRE_DB"])
    init_db()
    yield


def _n(ring, **kw):
    c = {"parcel_id": kw.get("parcel_id"), "label": kw.get("label"),
         "ring": ring, "points": kw.get("points", []),
         "declared_area": kw.get("declared_area")}
    return val.normalize_candidate(c)


def _seed_two(ts="2026-01-10T08:00:00.000Z"):
    with tx() as conn:
        ids = {}
        for ring, label in ((RING_A, "甲"), (RING_B, "乙")):
            n = _n(ring, label=label)
            v = sync._commit_one(conn, n, None, ts, "初始登记", None)
            ids[label] = (v["parcel_id"], v["id"])
        return ids


def _submit(cands, *, base=None, confirms=None, idem=None, as_of=None, job=None):
    payload = {"candidates": cands, "confirmations": confirms or [],
               "base_version_map": base or {}, "idem_key": idem,
               "device_id": "dev", "as_of": as_of, "job_id": job,
               "surveyor": "测绘员"}
    with tx() as conn:
        return sync.submit(conn, payload)


def _cand(ring, pid=None, area=None):
    return {"parcel_id": pid, "label": pid, "ring": ring, "points": [],
            "declared_area": area}


# ================================================================ 几何校验
class TestValidation:
    def test_unclosed(self):
        # 4 个界址点 + 回点漂移 0.5m（在 snap 邻域内但超闭合容差）
        errs = val.validate_ring([[0, 0], [100, 0], [100, 100], [0, 100], [0.1, 0]])
        assert any(e["code"] == "NOT_CLOSED" for e in errs)

    def test_closed_when_explicit_return_matches(self):
        assert val.validate_ring([[0, 0], [100, 0], [100, 100], [0, 100], [0, 0]]) == []

    def test_self_intersect_bowtie(self):
        bowtie = [[0, 0], [100, 0], [0, 100], [100, 100]]
        errs = val.validate_ring(bowtie)
        assert any(e["code"] == "SELF_INTERSECT" for e in errs)

    def test_area_tolerance(self):
        errs = val.validate_ring(RING_A, declared_area=5000)  # 实算 10000
        assert any(e["code"] == "AREA_MISMATCH" for e in errs)
        errs2 = val.validate_ring(RING_A, declared_area=10100)  # 1% 偏差
        assert not [e for e in errs2 if e["code"] == "AREA_MISMATCH"]

    def test_too_few(self):
        assert val.validate_ring([[0, 0], [1, 1]])[0]["code"] == "TOO_FEW_POINTS"

    def test_good_ring(self):
        assert val.validate_ring(RING_A) == []

    def test_fragment_diff_anchor(self):
        # 把右边界 x=100 弯到 x=110 再回来
        new = [[0, 0], [100, 0], [110, 50], [100, 100], [0, 100]]
        frags = geo.diff_fragments(RING_A, new)
        assert len(frags) == 1
        f = frags[0]
        assert f["anchor_start"] == [100, 0]
        assert f["anchor_end"] == [100, 100]
        assert f["new_chain"] == [[100, 0], [110, 50], [100, 100]]


# ================================================================ 提交/版本
class TestCommit:
    def test_first_commit_and_hashchain(self):
        r = _submit([_cand(RING_A, area=10000)])
        assert r["status"] == "COMMITTED"
        pid = r["accepted"][0]["parcel_id"]
        with tx() as conn:
            assert not vs.verify_hash_chain(conn, pid)
            v = vs.current_version(conn, pid)
            assert v["area"] == 10000

    def test_idempotent_replay(self):
        r1 = _submit([_cand(RING_A)], idem="k-1", as_of="2026-02-01T00:00:00Z")
        r2 = _submit([_cand([[0, 0], [50, 0], [50, 50], [0, 50]])],
                     idem="k-1", as_of="2026-02-02T00:00:00Z")
        assert r1["job_id"] == r2["job_id"]
        assert r2["accepted"] == r1["accepted"]

    def test_overlap_rejected(self):
        _seed_two()
        r = _submit([_cand([[50, 50], [150, 50], [150, 150], [50, 150]])])
        assert r["status"] == "REJECTED"
        assert any(e["code"] == "OVERLAP" for e in r["errors"])

    def test_unilateral_shared_edge_needs_confirmation(self):
        ids = _seed_two()
        pa, va = ids["甲"]
        # 只改甲，右边界凸出到 110 —— 与乙产生冲突（重叠+共享边）
        new_a = [[0, 0], [100, 0], [110, 50], [100, 100], [0, 100]]
        r = _submit([_cand(new_a, pa)], base={pa: va},
                    as_of="2026-03-01T00:00:00Z")
        assert r["status"] == "REJECTED"
        codes = {e["code"] for e in r["errors"]}
        assert "OVERLAP" in codes or "SHARED_NEIGHBOR_UNCONFIRMED" in codes

    def test_confirmed_shared_edge_propagates(self):
        ids = _seed_two()
        pa, va = ids["甲"]
        pb, vb = ids["乙"]
        # 双方一致地把共享边弯到 110（甲凸、乙凹），乙权利人确认
        new_a = [[0, 0], [100, 0], [110, 50], [100, 100], [0, 100]]
        r = _submit([_cand(new_a, pa)], base={pa: va},
                    confirms=[{"parcel_id": pb, "owner_name": "乙权利人",
                               "confirmed": True}],
                    as_of="2026-03-02T00:00:00Z")
        assert r["status"] == "COMMITTED", r
        pids = {a["parcel_id"] for a in r["accepted"]}
        assert {pa, pb} == pids
        with tx() as conn:
            ring_b = vs.current_version(conn, pb)["ring"]
            # 乙的左边界也含 110 拐点
            assert any(abs(x - 110) < 0.01 and abs(y - 50) < 0.01
                       for x, y in ring_b)
            # 面积：甲 +1000 左右，乙 -1000 左右（梯形凸入）
            assert abs(vs.current_version(conn, pa)["area"]
                       + vs.current_version(conn, pb)["area"] - 20000) < 1e-6


# ================================================================ 并发共享边争议
class TestDispute:
    def _two_teams(self, chain_a, chain_b):
        ids = _seed_two()
        pa, va = ids["甲"]
        pb, vb = ids["乙"]

        def ring_with(chain):
            # chain: (100,0) -> ... -> (100,100) 沿甲右边界
            return [[0, 0], [100, 0]] + chain[1:-1] + [[100, 100], [0, 100]]

        # 组1先提交（甲乙同批，共享边一致）
        ra = ring_with(chain_a)
        rb = chain_a + [[200, 100], [200, 0]]
        rb = geo.norm_ring(rb)
        r1 = _submit([_cand(ra, pa), _cand(rb, pb)],
                     base={pa: va, pb: vb}, idem="team1",
                     as_of="2026-04-01T00:00:00Z")
        assert r1["status"] == "COMMITTED", r1
        va1 = next(a["version_id"] for a in r1["accepted"] if a["parcel_id"] == pa)

        # 组2仍以旧基线作业，只提交甲，方案不同
        ra2 = ring_with(chain_b)
        r2 = _submit([_cand(ra2, pa)], base={pa: va}, idem="team2",
                     as_of="2026-04-02T00:00:00Z")
        assert r2["status"] == "DISPUTED"
        assert len(r2["disputes"]) == 1
        d = r2["disputes"][0]
        assert d["parcel_a"] == pa and d["parcel_b"] == pb
        assert geo.chain_deviation(d["geom_a"], chain_b) < 0.01
        assert geo.chain_deviation(d["geom_b"], chain_a) < 0.01
        # 甲未被组2覆盖：当前仍是组1版本
        with tx() as conn:
            assert vs.current_version(conn, pa)["id"] == va1
        return ids, d

    def test_conflict_creates_dispute_not_overwrite(self):
        chain1 = [[100, 0], [110, 50], [100, 100]]
        chain2 = [[100, 0], [90, 50], [100, 100]]
        self._two_teams(chain1, chain2)

    def test_convergent_no_dispute(self):
        ids = _seed_two()
        pa, va = ids["甲"]
        pb, vb = ids["乙"]
        chain = [[100, 0], [110, 50], [100, 100]]
        ra = [[0, 0], [100, 0], [110, 50], [100, 100], [0, 100]]
        rb = geo.norm_ring(chain + [[200, 100], [200, 0]])
        r1 = _submit([_cand(ra, pa), _cand(rb, pb)], base={pa: va, pb: vb},
                     idem="t1", as_of="2026-04-01T00:00:00Z")
        assert r1["status"] == "COMMITTED"
        # 组2独立测得相同结果 → 收敛，不产生争议
        r2 = _submit([_cand(ra, pa)], base={pa: va}, idem="t2",
                     as_of="2026-04-02T00:00:00Z")
        assert r2["status"] == "COMMITTED"

    def test_adjudicate_choose_b_updates_both_and_keeps_edges(self):
        chain1 = [[100, 0], [110, 50], [100, 100]]   # 已落库（B 方案）
        chain2 = [[100, 0], [90, 50], [100, 100]]    # 挂起（A 方案）
        ids, d = self._two_teams(chain1, chain2)
        pa, _ = ids["甲"]
        pb, _ = ids["乙"]
        with tx() as conn:
            pre_a = vs.current_version(conn, pa)
            pre_b = vs.current_version(conn, pb)
            res = adj.adjudicate(
                conn, [{"dispute_id": d["id"], "decision": "B",
                        "decided_by": "裁定员", "as_of": "2026-04-10T00:00:00Z"}])
            versions = res["adjudicated"][0]["versions"]
            assert len(versions) == 2
            # 未争议边界逐点保持
            va = vs.current_version(conn, pa)
            vb = vs.current_version(conn, pb)
            assert [0, 0] in va["ring"] and [0, 100] in va["ring"]
            kept_a = geo.ring_chain_between(va["ring"], [100, 100], [100, 0])
            kept_a_old = geo.ring_chain_between(pre_a["ring"], [100, 100], [100, 0])
            assert geo.chain_deviation(kept_a_old, kept_a) <= config.UNCHANGED_EDGE_TOL_M
            # 面积等量反向
            note = res["adjudicated"][0]["area_notes"]
            assert abs(note[0]["delta"] + note[1]["delta"]) < 0.01

    def test_adjudicate_revised_anchor_required(self):
        chain1 = [[100, 0], [110, 50], [100, 100]]
        chain2 = [[100, 0], [90, 50], [100, 100]]
        ids, d = self._two_teams(chain1, chain2)
        with tx() as conn, pytest.raises(ValueError, match="锚点"):
            adj.adjudicate(conn, [{
                "dispute_id": d["id"], "decision": "REVISED",
                "chain_a": [[101, 0], [105, 50], [100, 100]],  # 起点偏离
                "as_of": "2026-04-11T00:00:00Z"}])

    def test_adjudication_cannot_rewrite_uncontested(self):
        chain1 = [[100, 0], [110, 50], [100, 100]]
        chain2 = [[100, 0], [90, 50], [100, 100]]
        ids, d = self._two_teams(chain1, chain2)
        # REVISED 链本身合法（端点固定），未动其他边界 → 应通过；
        # 而想借链夹带 (0,0) 方向的改动是做不到的（replace_chain 只换片段）
        with tx() as conn:
            res = adj.adjudicate(conn, [{
                "dispute_id": d["id"], "decision": "REVISED",
                "chain_a": [[100, 0], [105, 25], [105, 75], [100, 100]],
                "as_of": "2026-04-12T00:00:00Z"}])
            assert len(res["adjudicated"][0]["versions"]) == 2
            pa, _ = ids["甲"]
            ring = vs.current_version(conn, pa)["ring"]
            # 左侧未争议边仍是直线 x=0
            left = [p for p in ring if abs(p[0]) < 1e-6]
            assert {tuple(p) for p in left} == {(0.0, 0.0), (0.0, 100.0)}

    def test_cannot_adjudicate_twice(self):
        chain1 = [[100, 0], [110, 50], [100, 100]]
        chain2 = [[100, 0], [90, 50], [100, 100]]
        ids, d = self._two_teams(chain1, chain2)
        with tx() as conn:
            adj.adjudicate(conn, [{"dispute_id": d["id"], "decision": "B",
                                   "as_of": "2026-04-13T00:00:00Z"}])
        with tx() as conn, pytest.raises(ValueError, match="已裁定"):
            adj.adjudicate(conn, [{"dispute_id": d["id"], "decision": "A",
                                   "as_of": "2026-04-14T00:00:00Z"}])


# ================================================================ 分割 / 合并
class TestLifecycle:
    def test_split_area_and_lineage(self):
        ids = _seed_two()
        pa, va = ids["甲"]
        left = [[0, 0], [50, 0], [50, 100], [0, 100]]
        right = [[50, 0], [100, 0], [100, 100], [50, 100]]
        with tx() as conn:
            r = lifecycle.split(conn, {
                "parent_version_id": va,
                "children": [_cand(left), _cand(right)],
                "note": "分家", "as_of": "2026-05-01T00:00:00Z"})
            assert r["status"] == "COMMITTED", r
            assert abs(r["area_note"]["delta"]) < 1e-6
            child_vids = [a["version_id"] for a in r["accepted"]]
            assert len(child_vids) == 2
            # 血缘：两个子版本父哈希均指向父版本
            for vid in child_vids:
                v = vs.get_version(conn, vid)
                assert va in _parents_of(conn, vid)
            # 父版本仍可按时间点查到
            v_at = vs.version_at(conn, pa, "2026-02-01T00:00:00Z")
            assert v_at["id"] == va

    def test_split_area_gap_rejected(self):
        ids = _seed_two()
        pa, va = ids["甲"]
        # 两个子宗只覆盖一部分，留缝
        left = [[0, 0], [40, 0], [40, 100], [0, 100]]
        right = [[60, 0], [100, 0], [100, 100], [60, 100]]
        with tx() as conn:
            r = lifecycle.split(conn, {
                "parent_version_id": va,
                "children": [_cand(left), _cand(right)],
                "as_of": "2026-05-02T00:00:00Z"})
            assert r["status"] == "REJECTED"
            assert any(e["code"] in ("AREA_RELATION_BROKEN", "GEOMETRY_RELATION_BROKEN")
                       for e in r["errors"])

    def test_merge(self):
        ids = _seed_two()
        pa, va = ids["甲"]
        pb, vb = ids["乙"]
        with tx() as conn:
            r = lifecycle.merge(conn, {
                "parent_version_ids": [va, vb],
                "result": _cand([[0, 0], [200, 0], [200, 100], [0, 100]]),
                "note": "合并", "as_of": "2026-06-01T00:00:00Z"})
            assert r["status"] == "COMMITTED", r
            assert abs(r["area_note"]["delta"]) < 1e-6
            assert r["accepted"][0]["area"] == 20000

    def test_merge_mismatch_rejected(self):
        ids = _seed_two()
        pa, va = ids["甲"]
        pb, vb = ids["乙"]
        with tx() as conn:
            r = lifecycle.merge(conn, {
                "parent_version_ids": [va, vb],
                "result": _cand([[0, 0], [199, 0], [199, 100], [0, 100]]),
                "as_of": "2026-06-02T00:00:00Z"})
            assert r["status"] == "REJECTED"


def _parents_of(conn, child_vid):
    for r in conn.execute("SELECT parent_versions, child_versions FROM parcel_op"):
        if child_vid in json.loads(r["child_versions"]):
            return json.loads(r["parent_versions"])
    return []


# ================================================================ 历史更正 + 证明
class TestCorrectionAndCert:
    def test_correction_keeps_old_version_and_cert_verifies(self):
        ids = _seed_two()
        pa, va = ids["甲"]
        with tx() as conn:
            c = cert.issue(conn, va, "2026-07-01T00:00:00Z")
            cert_id = c["cert_id"]
        # 历史更正：南侧界址点解析错误（整体南移 0.5m），不侵占邻宗
        corrected = [[0, -0.5], [100, -0.5], [100, 100], [0, 100]]
        with tx() as conn:
            r = lifecycle.correct(conn, {
                "version_id": va,
                "corrected": _cand(corrected, pa),
                "reason": "界址点解析错误更正",
                "as_of": "2026-07-10T00:00:00Z"})
            assert r["status"] == "COMMITTED", r
            new_vid = r["accepted"][0]["version_id"]
            assert new_vid != va
            assert va in _parents_of(conn, new_vid)
            # 旧版本行仍在、状态 ANNULLED、哈希未变
            old = vs.get_version(conn, va)
            assert old["status"] == "ANNULLED"
            assert vs.verify_hash_chain(conn, pa) == []
            # 已签发历史证明继续可验证
            v = cert.verify(conn, cert_id)
            assert v["valid"] is True, v
            assert v["checks"]["hash_chain_intact"] is True

    def test_cert_detects_tampering(self):
        ids = _seed_two()
        pa, va = ids["甲"]
        with tx() as conn:
            c = cert.issue(conn, va, "2026-07-02T00:00:00Z")
            cid = c["cert_id"]
        # 直接篡改库内版本坐标（绕过服务）
        with tx() as conn:
            row = conn.execute("SELECT ring_json FROM parcel_version WHERE id=?",
                               (va,)).fetchone()
            ring = json.loads(row["ring_json"])
            ring[1] = [120, 0]
            conn.execute("UPDATE parcel_version SET ring_json=? WHERE id=?",
                         (json.dumps(ring), va))
        with tx() as conn:
            v = cert.verify(conn, cid)
            assert v["valid"] is False

    def test_only_current_can_be_corrected(self):
        ids = _seed_two()
        pa, va = ids["甲"]
        with tx() as conn:
            lifecycle.correct(conn, {
                "version_id": va,
                "corrected": _cand([[-1, 0], [100, 0], [100, 100], [-1, 100]], pa),
                "reason": "x", "as_of": "2026-07-03T00:00:00Z"})
        with tx() as conn, pytest.raises(ValueError, match="当前有效"):
            lifecycle.correct(conn, {
                "version_id": va,
                "corrected": _cand([[0, -1], [100, -1], [100, 100], [0, 100]], pa),
                "reason": "y", "as_of": "2026-07-04T00:00:00Z"})


# ================================================================ 时间点查询
class TestTimeTravel:
    def test_as_of(self):
        ids = _seed_two("2026-01-10T08:00:00.000Z")
        pa, va = ids["甲"]
        new = [[0, 0], [100, 0], [100, 101], [0, 101]]
        _submit([_cand(new, pa)], base={pa: va},
                as_of="2026-08-01T00:00:00Z")
        with tx() as conn:
            assert vs.version_at(conn, pa, "2026-01-11T00:00:00Z")["id"] == va
            assert vs.version_at(conn, pa, "2026-08-02T00:00:00Z")["version_no"] == 2
            # 半开区间：恰好在变更前一刻仍是旧版
            assert vs.version_at(conn, pa, "2026-07-31T23:59:59Z")["id"] == va
