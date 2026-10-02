"""二阶段历史更正（草案 → 预演 → 原子发布 / 漂移 / 撤销）业务规则测试。"""
import json
import os
import tempfile

import pytest

from app import geo
from app.db import init_db, tx, get_conn
from app.services import versions as vs
from app.services import sync, lifecycle, corrections as cr, certificates as cert

_tmp = tempfile.mkdtemp(prefix="cad-corr-")
os.environ["CADASTRE_DB"] = os.path.join(_tmp, "t.db")

RING_A = [[0, 0], [100, 0], [100, 100], [0, 100]]
RING_B = [[100, 0], [200, 0], [200, 100], [100, 100]]


@pytest.fixture(autouse=True)
def fresh_db():
    os.environ["CADASTRE_DB"] = os.path.join(tempfile.mkdtemp(), "t.db")
    init_db()
    yield


def _n(ring, pid=None, label=None):
    c = {"parcel_id": pid, "label": label, "ring": ring,
         "points": [], "declared_area": None}
    return val_normalize(c)


def val_normalize(c):
    return sync.val.normalize_candidate(c)


def _cand(ring, pid=None):
    return {"parcel_id": pid, "label": "", "ring": ring,
            "points": [], "declared_area": None}


def seed_two():
    with tx() as conn:
        va = sync._commit_one(
            conn, _n(RING_A, label="甲"), None,
            "2026-01-10T08:00:00Z", "初始登记", None)
        vb = sync._commit_one(
            conn, _n(RING_B, label="乙"), None,
            "2026-01-10T08:00:00Z", "初始登记", None)
    return va, vb


def split_a(conn, va, ts="2026-05-01T00:00:00Z"):
    left = [[0, 0], [50, 0], [50, 100], [0, 100]]
    right = [[50, 0], [100, 0], [100, 100], [50, 100]]
    r = lifecycle.split(
        conn, {"parent_version_id": va["id"],
               "children": [_cand(left), _cand(right)], "as_of": ts})
    assert r["status"] == "COMMITTED", r
    return r


class TestDraftDoesNotChangeWorld:
    def test_draft_creates_no_version_or_op(self):
        va, _ = seed_two()
        with tx() as conn:
            n_ver = conn.execute("SELECT COUNT(*) c FROM parcel_version").fetchone()["c"]
            n_op = conn.execute("SELECT COUNT(*) c FROM parcel_op").fetchone()["c"]
            d = cr.create_draft(conn, {
                "version_id": va["id"],
                "corrected": {"ring": [[0, -0.5], [100, -0.5], [100, 100], [0, 100]]},
                "reason": "南边界解析错误"})
            # 草案行存在，但版本/操作数量不变
            assert conn.execute(
                "SELECT COUNT(*) c FROM correction_draft").fetchone()["c"] == 1
            assert conn.execute(
                "SELECT COUNT(*) c FROM parcel_version").fetchone()["c"] == n_ver
            assert conn.execute(
                "SELECT COUNT(*) c FROM parcel_op").fetchone()["c"] == n_op
            # 当前宗地几何、面积原样
            cur = vs.current_version(conn, va["parcel_id"])
            assert abs(cur["area"] - 10000) < 1e-6
            assert d["status"] == "OPEN"

    def test_draft_preview_shows_each_descendant(self):
        va, _ = seed_two()
        with tx() as conn:
            r = split_a(conn, va)
            child_pids = [a["parcel_id"] for a in r["accepted"]]
            d = cr.create_draft(conn, {
                "version_id": va["id"],
                "corrected": {"ring": [[0, -0.5], [100, -0.5], [100, 100], [0, 100]]}})
            nodes = d["preview"]["nodes"]
            # 目标 + 2 个分割子宗
            assert len(nodes) == 3
            op_types = {n["op_type"] for n in nodes}
            assert op_types == {"TARGET", "SPLIT"}
            # 每个节点都给了新几何、面积、面积差、血缘变化
            for n in nodes:
                assert n["new_ring"] is not None
                assert "new_area" in n and "area_delta" in n
                assert "lineage" in n
            # 面积守恒：子宗新面积和 = 更正父宗面积
            children = [n for n in nodes if n["op_type"] == "SPLIT"]
            s = sum(n["new_area"] for n in children)
            assert abs(s - 10050) < 1e-6
            assert d["releasable"] is True


class TestPublishAtomic:
    def test_publish_forks_chain_and_keeps_old(self):
        va, _ = seed_two()
        with tx() as conn:
            r = split_a(conn, va)
            old_versions = {p: [v["id"] for v in vs.list_versions(conn, p)]
                            for p in {va["parcel_id"],
                                      *[a["parcel_id"] for a in r["accepted"]]}}
            c = cert.issue(conn, va["id"], "2026-06-01T00:00:00Z")
            d = cr.create_draft(conn, {
                "version_id": va["id"],
                "corrected": {"ring": [[0, -0.5], [100, -0.5], [100, 100], [0, 100]]}})
            pub = cr.publish(conn, {"draft_id": d["draft_id"],
                                    "as_of": "2026-09-01T00:00:00Z"})
            assert pub["status"] == "PUBLISHED"
            # 每个受影响宗地都产生了新版本
            assert len(pub["new_versions"]) == 3
            # 旧版本行全部还在（含旧哈希、旧几何）
            for pid, vids in old_versions.items():
                for vid in vids:
                    row = vs.get_version(conn, vid)
                    assert row is not None
            # 旧证明仍验真（绑定旧版本哈希，新链不影响）
            v = cert.verify(conn, c["cert_id"])
            assert v["valid"] is True
            assert v["checks"]["hash_chain_intact"] is True
            # 旧链与新链各自哈希完整
            for pid in pub["chains_forked"]:
                assert vs.verify_hash_chain(conn, pid) == []
            # 新链版本 chain_parent_id 建立了平行链（子宗首版本挂其旧链前驱）
            for nv in pub["new_versions"]:
                new = vs.get_version(conn, nv["version_id"])
                assert new["base_version_id"] == nv["replaces"]

    def test_publish_is_idempotent(self):
        va, _ = seed_two()
        with tx() as conn:
            split_a(conn, va)
            d = cr.create_draft(conn, {
                "version_id": va["id"],
                "corrected": {"ring": [[0, -0.5], [100, -0.5], [100, 100], [0, 100]]}})
            p1 = cr.publish(conn, {"draft_id": d["draft_id"], "idem_key": "k1"})
            n_after_first = conn.execute(
                "SELECT COUNT(*) c FROM parcel_version").fetchone()["c"]
            # 同一发布请求（同 idem_key）重放
            p2 = cr.publish(conn, {"draft_id": d["draft_id"], "idem_key": "k1"})
            n_after_second = conn.execute(
                "SELECT COUNT(*) c FROM parcel_version").fetchone()["c"]
            assert p1["new_versions"] == p2["new_versions"]
            assert n_after_first == n_after_second

    def test_only_lineage_leaves_current(self):
        """已分割父宗不在版；更正后两个子宗（叶子）在版，面积和守恒。"""
        va, _ = seed_two()
        with tx() as conn:
            r = split_a(conn, va)
            child_pids = [a["parcel_id"] for a in r["accepted"]]
            d = cr.create_draft(conn, {
                "version_id": va["id"],
                "corrected": {"ring": [[0, -0.5], [100, -0.5], [100, 100], [0, 100]]}})
            cr.publish(conn, {"draft_id": d["draft_id"]})
            assert vs.current_version(conn, va["parcel_id"]) is None
            areas = [vs.current_version(conn, p)["area"] for p in child_pids]
            assert abs(sum(areas) - 10050) < 1e-6

    def test_time_travel_unchanged_before_publish(self):
        va, _ = seed_two()
        with tx() as conn:
            split_a(conn, va)
            d = cr.create_draft(conn, {
                "version_id": va["id"],
                "corrected": {"ring": [[0, -0.5], [100, -0.5], [100, 100], [0, 100]]}})
            cr.publish(conn, {"draft_id": d["draft_id"],
                              "as_of": "2026-09-01T00:00:00Z"})
            # 分割前（2026-02）查父宗仍是旧 10000
            v = vs.version_at(conn, va["parcel_id"], "2026-02-01T00:00:00Z")
            assert abs(v["area"] - 10000) < 1e-6


class TestMergePropagation:
    def test_correction_propagates_through_merge_result(self):
        """更正合并的一个父宗，合并结果按"更正后父宗并集"重建。"""
        va, vb = seed_two()
        with tx() as conn:
            r = lifecycle.merge(conn, {
                "parent_version_ids": [va["id"], vb["id"]],
                "result": _cand([[0, 0], [200, 0], [200, 100], [0, 100]]),
                "note": "合并", "as_of": "2026-04-01T00:00:00Z"})
            assert r["status"] == "COMMITTED", r
            d = cr.create_draft(conn, {
                "version_id": va["id"],
                "corrected": {"ring": [[0, -0.5], [100, -0.5],
                                       [100, 100], [0, 100]]}})
            assert d["releasable"], d["preview"]["errors"]
            mn = next(n for n in d["preview"]["nodes"]
                      if n["op_type"] == "MERGE")
            # 20000 + 甲南移增加的 50 = 20050
            assert abs(mn["new_area"] - 20050) < 1e-6
            pub = cr.publish(conn, {"draft_id": d["draft_id"]})
            assert pub["status"] == "PUBLISHED"
            # 合并结果新版本哈希绑定两个父（甲新版本 + 乙未变版本），链完整
            for pid in pub["chains_forked"]:
                assert vs.verify_hash_chain(conn, pid) == []


class TestDrift:
    def _draft_after_split(self, conn, va):
        self._split = split_a(conn, va)
        return cr.create_draft(conn, {
            "version_id": va["id"],
            "corrected": {"ring": [[0, -0.5], [100, -0.5], [100, 100], [0, 100]]}})

    def _affected_child_current(self, conn, va):
        # 分割子宗（受更正闭包影响），而非无关的乙宗地
        pid = self._split["accepted"][0]["parcel_id"]
        return vs.current_version(conn, pid)

    def test_descendant_change_blocks_publish_and_marks_drift(self):
        va, _ = seed_two()
        with tx() as conn:
            d = self._draft_after_split(conn, va)
            # 草案建立后给一个在版子宗追加新版本
            cur = self._affected_child_current(conn, va)
            ring2 = geo.norm_ring([[c[0], c[1] + 1] for c in cur["ring"]])
            n2 = _n(ring2, pid=cur["parcel_id"])
            sync._commit_one(
                conn, n2, cur["id"], "2026-08-01T00:00:00Z", "草案后变更", None,
                op_type="CORRECTION", parent_versions=[cur["id"]],
                extra_params={"reason": "drift"})
            n_before = conn.execute(
                "SELECT COUNT(*) c FROM parcel_version").fetchone()["c"]
            res = cr.publish(conn, {"draft_id": d["draft_id"]})
            assert res["status"] == "DRIFTED"
            assert res["drift_nodes"]  # 标出漂移节点
            # 没有产生任何更正版本
            n_after = conn.execute(
                "SELECT COUNT(*) c FROM parcel_version").fetchone()["c"]
            assert n_after == n_before
            assert conn.execute(
                "SELECT status FROM correction_draft WHERE id=?",
                (d["draft_id"],)).fetchone()["status"] == "DRIFTED"

    def test_dispute_change_blocks_publish(self):
        va, vb = seed_two()
        with tx() as conn:
            d = self._draft_after_split(conn, va)
            # 构造一个涉及受影响宗地的争议并裁定
            chain = json.dumps([[100, 0], [100, 100]])
            disp = {
                "id": "DISP-TEST", "job_a": "JOB-A", "job_b": "JOB-B",
                "cand_a": "C1", "cand_b": "C2",
                "anchor_start": json.dumps([100, 0]),
                "anchor_end": json.dumps([100, 100]),
                "status": "RESOLVED", "decision": "A",
                "decided_chain_json": chain,
                "decided_by": "x", "decided_at": "2026-08-01T00:00:00Z",
                "result_versions": json.dumps([]),
                "created_at": "2026-08-01T00:00:00Z",
                "base_chain_json": chain,
                "geom_a_json": json.dumps([[100, 0], [101, 50], [100, 100]]),
                "geom_b_json": json.dumps([[100, 0], [99, 50], [100, 100]]),
                "parcel_a": va["parcel_id"], "parcel_b": vb["parcel_id"],
            }
            cols = ",".join(disp.keys())
            qs = ",".join("?" * len(disp))
            conn.execute(f"INSERT INTO dispute ({cols}) VALUES ({qs})",
                         tuple(disp.values()))
            res = cr.publish(conn, {"draft_id": d["draft_id"]})
            assert res["status"] == "DRIFTED"
            assert any(x["kind"] == "DISPUTE_OPENED"
                       for x in res["drift_nodes"])

    def test_certificate_change_blocks_publish(self):
        va, _ = seed_two()
        with tx() as conn:
            d = self._draft_after_split(conn, va)
            # 草案建立后给受影响宗地新签发证明
            cur = self._affected_child_current(conn, va)
            cert.issue(conn, cur["id"], "2026-08-01T00:00:00Z")
            res = cr.publish(conn, {"draft_id": d["draft_id"]})
            assert res["status"] == "DRIFTED"
            assert any(x["kind"] == "CERTIFICATE_ISSUED"
                       for x in res["drift_nodes"])

    def test_re_rehearse_allows_publish_after_drift(self):
        va, _ = seed_two()
        with tx() as conn:
            d = self._draft_after_split(conn, va)
            cur = self._affected_child_current(conn, va)
            ring2 = geo.norm_ring([[c[0], c[1] + 1] for c in cur["ring"]])
            sync._commit_one(
                conn, _n(ring2, pid=cur["parcel_id"]), cur["id"],
                "2026-08-01T00:00:00Z", "变更", None,
                op_type="CORRECTION", parent_versions=[cur["id"]],
                extra_params={"reason": "drift"})
            assert cr.publish(conn, {"draft_id": d["draft_id"]})["status"] == "DRIFTED"
            cr.re_rehearse(conn, d["draft_id"])  # 重新预演
            assert conn.execute(
                "SELECT status FROM correction_draft WHERE id=?",
                (d["draft_id"],)).fetchone()["status"] == "OPEN"


class TestCancel:
    def test_cancel_open_leaves_no_artifacts(self):
        va, _ = seed_two()
        with tx() as conn:
            n_ver = conn.execute("SELECT COUNT(*) c FROM parcel_version").fetchone()["c"]
            d = cr.create_draft(conn, {
                "version_id": va["id"],
                "corrected": {"ring": [[0, -0.5], [100, -0.5], [100, 100], [0, 100]]}})
            cr.cancel(conn, d["draft_id"])
            # 草案标记撤销，从未产生版本（无半成品）
            assert conn.execute(
                "SELECT status,cancelled_at FROM correction_draft WHERE id=?",
                (d["draft_id"],)).fetchone()["status"] == "CANCELLED"
            assert conn.execute(
                "SELECT COUNT(*) c FROM parcel_version").fetchone()["c"] == n_ver
            # 撤销后不能发布
            with pytest.raises(ValueError):
                cr.publish(conn, {"draft_id": d["draft_id"]})

    def test_cannot_cancel_published(self):
        va, _ = seed_two()
        with tx() as conn:
            split_a(conn, va)
            d = cr.create_draft(conn, {
                "version_id": va["id"],
                "corrected": {"ring": [[0, -0.5], [100, -0.5], [100, 100], [0, 100]]}})
            cr.publish(conn, {"draft_id": d["draft_id"]})
            with pytest.raises(ValueError):
                cr.cancel(conn, d["draft_id"])


class TestRehearsalRejects:
    def test_illegal_geometry_not_releasable(self):
        va, _ = seed_two()
        with tx() as conn:
            d = cr.create_draft(conn, {
                "version_id": va["id"],
                "corrected": {"ring": [[0, 0], [100, 0], [0, 100], [100, 100]]}})
            assert d["releasable"] is False
            assert any(
                e["code"] == "SELF_INTERSECT"
                for n in d["preview"]["nodes"] for e in n["errors"])
            # 不能发布
            res = cr.publish(conn, {"draft_id": d["draft_id"]})
            assert res["status"] == "DRIFTED"
            assert res["live_errors"]
