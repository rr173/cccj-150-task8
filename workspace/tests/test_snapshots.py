"""地籍快照交换包（Snapshot Exchange Package）验收测试。

覆盖：
* 导出最小闭包（版本链/共享边/争议/证明/生效计划）+ 可独立核验清单；
* 接收方无网络离线预检（清单签章/分块哈希/载荷哈希/引用闭包/链/证明/共享边）；
* 分块乱序、重复上传、断点续传（进程中断后继续）；
* 终检一次性导入：缺块 / 同序号异内容 / 链断裂 / 证明引用缺失 /
  本地已有不同版本 → 可定位冲突且数据库原样；
* 相同包标识再次导入返回原结果；同标识不同内容拒绝；
* 导入后新旧版本对应关系、来源时间点、缺块/冲突会话视图。
"""
import contextlib
import copy
import json
import os
import tempfile

import pytest

_tmp = tempfile.mkdtemp(prefix="cad-snap-")
SRC_DB = os.path.join(_tmp, "src.db")
os.environ["CADASTRE_DB"] = SRC_DB
os.environ.setdefault("CADASTRE_PLAN_POLL_SECONDS", "3600")  # 本文件不依赖后台执行器

from fastapi.testclient import TestClient  # noqa: E402

from app import main  # noqa: E402
from app.db import init_db, tx, get_conn  # noqa: E402
from app.services import snapshots as ss  # noqa: E402
from app.services import sync, lifecycle, versions as vs, certificates as cert  # noqa: E402
from app.services.plans import canon_iso  # noqa: E402

client = TestClient(main.app)

RING_A = [[0, 0], [100, 0], [100, 100], [0, 100]]
RING_B = [[100, 0], [200, 0], [200, 100], [100, 100]]
AT = "2026-09-01T00:00:00Z"
AT_NORM = canon_iso(AT)


@pytest.fixture(autouse=True)
def fresh_db():
    for f in (SRC_DB,):
        if os.path.exists(f):
            os.remove(f)
    os.environ["CADASTRE_DB"] = SRC_DB
    init_db()
    yield


@contextlib.contextmanager
def receiver_db():
    """切到一个全新的"接收方"库（模拟无网络的另一台节点）。"""
    path = tempfile.mktemp(prefix="recv-", suffix=".db", dir=_tmp)
    old = os.environ["CADASTRE_DB"]
    os.environ["CADASTRE_DB"] = path
    try:
        if os.path.exists(path):
            os.remove(path)
        init_db()
        yield path
    finally:
        os.environ["CADASTRE_DB"] = old
        if os.path.exists(path):
            os.remove(path)


# ---------------------------------------------------------------- helpers
def _norm(ring, pid=None):
    return sync.val.normalize_candidate(
        {"parcel_id": pid, "label": None, "ring": ring,
         "points": [], "declared_area": None})


def _commit(ring, ts="2026-01-10T08:00:00Z"):
    with tx() as conn:
        return sync._commit_one(conn, _norm(ring), None, ts,
                                "初始登记", None, op_type="SURVEY")


def seed_ab():
    va = _commit(RING_A)
    vb = _commit(RING_B)
    with tx() as conn:
        conn.execute("UPDATE parcel SET label='甲' WHERE id=?", (va["parcel_id"],))
        conn.execute("UPDATE parcel SET label='乙' WHERE id=?", (vb["parcel_id"],))
    return va, vb


def export_pkg(parcel_ids, at=AT, chunk_size=4096, **kw):
    with tx() as conn:
        return ss.build_package(conn, {"parcel_ids": parcel_ids, "at": at,
                                       "chunk_size": chunk_size, **kw})


def decode_chunks(pkg):
    return [ss._b64decode(c) for c in pkg["chunks"]]


def upload_all(pkg, order=None, raw_chunks=None):
    """建会话并上传分块（默认乱序）。"""
    m = pkg["manifest"]
    with tx() as conn:
        ss.create_import(conn, m, "recv")
    raws = raw_chunks if raw_chunks is not None else decode_chunks(pkg)
    order = order if order is not None else list(reversed(range(m["chunk_count"])))
    for seq in order:
        with tx() as conn:
            r = ss.put_chunk(conn, m["package_id"], seq, raws[seq])
            assert not r["conflict"], r
    return m["package_id"]


# ================================================================ 导出闭包
class TestExportClosure:
    def test_closure_contains_chain_shared_edge_and_counts(self):
        va, vb = seed_ab()
        pkg = export_pkg([va["parcel_id"], vb["parcel_id"]])
        m = pkg["manifest"]
        assert m["format"] == ss.FORMAT
        assert m["package_id"].startswith("PKG-")
        assert m["counts"]["parcel"] == 2
        assert m["counts"]["version"] == 2
        assert m["counts"]["shared_edge"] == 1
        assert m["counts"]["point"] == 6  # 四角点归并共享边两端
        # 清单签章可独立验真
        assert ss.verify_manifest_signature(m)
        # 分块数与哈希齐备
        assert len(pkg["chunks"]) == m["chunk_count"]
        assert len(m["chunks_sha256"]) == m["chunk_count"]

    def test_export_at_time_point_uses_historical_versions(self):
        va, _ = seed_ab()
        # 之后给甲追加新版本
        with tx() as conn:
            sync._commit_one(conn, _norm([[0, -1], [100, -1], [100, 100], [0, 100]],
                                          pid := va["parcel_id"]),
                             va["id"], "2026-08-01T00:00:00Z", "变更", None)
        pkg_now = export_pkg([va["parcel_id"]], at="2026-09-01T00:00:00Z")
        pkg_old = export_pkg([va["parcel_id"]], at="2026-03-01T00:00:00Z")
        # 历史时点包只含旧版本链，当前时点含两版
        assert pkg_old["manifest"]["counts"]["version"] == 1
        assert pkg_now["manifest"]["counts"]["version"] == 2
        assert pkg_old["manifest"]["package_id"] != pkg_now["manifest"]["package_id"]

    def test_split_closure_pulls_parent_chain_and_ops(self):
        va, vb = seed_ab()
        with tx() as conn:
            r = lifecycle.split(conn, {
                "parent_version_id": va["id"],
                "children": [_norm([[0, 0], [50, 0], [50, 100], [0, 100]]),
                             _norm([[50, 0], [100, 0], [100, 100], [50, 100]])],
                "as_of": "2026-05-01T00:00:00Z"})
        assert r["status"] == "COMMITTED"
        kids = [a["parcel_id"] for a in r["accepted"]]
        pkg = export_pkg(kids + [vb["parcel_id"]])
        c = pkg["manifest"]["counts"]
        # 两子宗 + 父宗版本 + 乙；SPLIT 操作父子闭包完整
        assert c["version"] == 4
        assert c["op"] >= 4  # 2 SURVEY + split per-child + summary
        assert c["shared_edge"] >= 2  # 子-子 + 子-乙

    def test_certificate_included_and_self_verifiable(self):
        va, vb = seed_ab()
        with tx() as conn:
            c = cert.issue(conn, va["id"], "2026-06-01T00:00:00Z")
        pkg = export_pkg([va["parcel_id"], vb["parcel_id"]])
        assert pkg["manifest"]["counts"]["certificate"] == 1
        # 完全离库核验（local=False 不读本地库之外的内容）
        with get_conn() as conn:
            rep = ss.precheck(conn, pkg["manifest"], pkg["chunks"], local=False)
        assert rep["ready"] is True
        assert rep["internal_conflicts"] == []

    def test_tampered_manifest_signature_fails_precheck(self):
        va, vb = seed_ab()
        pkg = export_pkg([va["parcel_id"], vb["parcel_id"]])
        m = copy.deepcopy(pkg["manifest"])
        m["created_by"] = "attacker"  # 改清单未重签
        with get_conn() as conn:
            rep = ss.precheck(conn, m, pkg["chunks"], local=False)
        assert rep["manifest_signature_valid"] is False
        assert rep["ready"] is False
        assert any(x["code"] == "MANIFEST_SIGNATURE_INVALID"
                   for x in rep["internal_conflicts"])


# ================================================================ 争议/计划闭包
class TestDisputeAndPlanClosure:
    def _make_dispute(self, va, vb):
        """双方同改 x=100 共享边且方案不一致 → 生成一条 OPEN 争议。"""
        with tx() as conn:
            r1 = sync.submit(conn, {
                "idem_key": "disp1", "as_of": "2026-04-01T00:00:00Z",
                "base_version_map": {va["parcel_id"]: va["id"],
                                     vb["parcel_id"]: vb["id"]},
                "candidates": [
                    {"parcel_id": va["parcel_id"],
                     "ring": [[0, 0], [100, 0], [110, 50], [100, 100], [0, 100]],
                     "points": []},
                    {"parcel_id": vb["parcel_id"],
                     "ring": [[100, 0], [110, 50], [100, 100], [200, 100], [200, 0]],
                     "points": []}]})
            assert r1["status"] == "COMMITTED", r1
        with tx() as conn:
            r2 = sync.submit(conn, {
                "idem_key": "disp2", "as_of": "2026-04-02T00:00:00Z",
                "base_version_map": {va["parcel_id"]: va["id"]},
                "candidates": [
                    {"parcel_id": va["parcel_id"],
                     "ring": [[0, 0], [100, 0], [90, 50], [100, 100], [0, 100]],
                     "points": []}]})
        assert r2["status"] == "DISPUTED", r2
        return r2["disputes"][0]["id"]

    def test_dispute_closure_includes_jobs_candidates(self):
        va, vb = seed_ab()
        did = self._make_dispute(va, vb)
        pkg = export_pkg([va["parcel_id"]])
        c = pkg["manifest"]["counts"]
        assert c["dispute"] == 1
        assert c["job"] >= 1 and c["candidate"] >= 2
        # 乙因争议被带入闭包
        raw, _, _ = ss.assemble(pkg["manifest"], pkg["chunks"])
        payload, _ = ss.parse_payload(pkg["manifest"], raw)
        ids_ = {k.split(":", 1)[1] for k in payload["items"] if k.startswith("parcel:")}
        assert vb["parcel_id"] in ids_
        disp = next(v for k, v in payload["items"].items() if k == f"dispute:{did}")
        assert disp["geom_a"] and disp["geom_b"] and disp["status"] == "OPEN"
        # 包内引用闭包完整（候选/作业单都在）
        assert not ss.check_references(pkg["manifest"], payload)

    def test_effect_plan_closure_with_draft_and_occupancy(self):
        from app.services import corrections as cr, plans as ps
        va, vb = seed_ab()
        with tx() as conn:
            d = cr.create_draft(conn, {
                "version_id": va["id"],
                "corrected": {"ring": [[0, -0.5], [100, -0.5], [100, 100], [0, 100]],
                              "points": []},
                "reason": "南边界更正"})
            assert d["releasable"], d["preview"]["errors"]
            r = ps.register_plan(conn, {
                "draft_id": d["draft_id"], "request_key": "k-plan-1",
                "execute_at": "2027-01-15T00:00:00Z"})
            assert r["status"] == "WAITING", r
            plan_id = r["plan"]["id"]
        # 计划在 2026-09-30 登记；选取一个晚于登记、早于执行的时间点
        pkg = export_pkg([va["parcel_id"]], at="2026-12-15T00:00:00Z")
        c = pkg["manifest"]["counts"]
        assert c["plan"] == 1 and c["draft"] == 1 and c["occupancy"] >= 1
        raw, _, _ = ss.assemble(pkg["manifest"], pkg["chunks"])
        payload, _ = ss.parse_payload(pkg["manifest"], raw)
        plan = next(v for k, v in payload["items"].items() if k == f"plan:{plan_id}")
        assert plan["request_key"] == "k-plan-1"
        assert va["parcel_id"] in plan["parcels"]
        assert not ss.internal_checks(pkg["manifest"], payload)
        # 晚于执行时间的包里不应再出现该"未来计划登记"口径（登记仍在，但语义可扩展）
        pkg_before = export_pkg([va["parcel_id"]], at="2026-09-01T00:00:00Z")
        assert pkg_before["manifest"]["counts"]["plan"] == 0


# ================================================================ 离线预检（内容级）
class TestOfflinePrecheck:
    def _pkg_payload(self, pkg):
        raw, errs, missing = ss.assemble(pkg["manifest"], pkg["chunks"])
        assert not errs and not missing
        payload, perrs = ss.parse_payload(pkg["manifest"], raw)
        assert not perrs
        return payload

    def test_missing_chunk_reported(self):
        va, vb = seed_ab()
        pkg = export_pkg([va["parcel_id"], vb["parcel_id"]], chunk_size=512)
        chunks = list(pkg["chunks"])
        gone = 1
        chunks[gone] = ""
        with get_conn() as conn:
            rep = ss.precheck(conn, pkg["manifest"], chunks, local=False)
        assert rep["ready"] is False
        assert rep["chunks"]["missing"] == [gone]

    def test_wrong_chunk_hash_reported(self):
        va, vb = seed_ab()
        pkg = export_pkg([va["parcel_id"], vb["parcel_id"]], chunk_size=512)
        chunks = list(pkg["chunks"])
        raw = bytearray(ss._b64decode(chunks[0]))
        raw[0] ^= 0xFF
        chunks[0] = ss._b64encode(bytes(raw))
        with get_conn() as conn:
            rep = ss.precheck(conn, pkg["manifest"], chunks, local=False)
        assert rep["ready"] is False
        assert any(x["code"] == "CHUNK_HASH_MISMATCH" and x["id"] == 0
                   for x in rep["chunks"]["errors"])

    def test_payload_tamper_detected(self):
        va, vb = seed_ab()
        pkg = export_pkg([va["parcel_id"], vb["parcel_id"]])
        # 篡改载荷字节后重切：分块内容哈希必然失配（传输层即拦下，不进入内部核验）
        payload = self._pkg_payload(pkg)
        vid = next(k for k in payload["items"] if k.startswith("version:"))
        payload["items"][vid]["ring"][0] = [999, 999]
        tampered = ss.canonical(payload).encode()
        size = pkg["manifest"]["chunk_size"]
        raw_parts = [tampered[i:i + size] for i in range(0, len(tampered), size)]
        with get_conn() as conn:
            rep = ss.precheck(conn, pkg["manifest"],
                              [ss._b64encode(x) for x in raw_parts], local=False)
        assert rep["ready"] is False
        assert rep["chunks"]["errors"]
        assert rep["chunks"]["errors"][0]["code"] == "CHUNK_HASH_MISMATCH"

    def test_broken_reference_detected(self):
        va, vb = seed_ab()
        pkg = export_pkg([va["parcel_id"], vb["parcel_id"]])
        payload = self._pkg_payload(pkg)
        # 删掉一个界址点 → version_point 引用缺失（内容级闭包核验）
        pkey = next(k for k in payload["items"] if k.startswith("point:"))
        del payload["items"][pkey]
        errs = ss.internal_checks(pkg["manifest"], payload)
        assert any(x["code"] == "REFERENCE_MISSING" and x["entity"] == "version_point"
                   for x in errs), errs

    def test_broken_hash_chain_detected(self):
        va, vb = seed_ab()
        with tx() as conn:
            sync._commit_one(conn, _norm(RING_B, vb["parcel_id"]), vb["id"],
                             "2026-07-01T00:00:00Z", "变更", None)
        pkg = export_pkg([va["parcel_id"], vb["parcel_id"]])
        payload = self._pkg_payload(pkg)
        # 把乙首版本环换掉但保留 version_hash → 链重算不一致
        bvers = sorted((it for k, it in payload["items"].items()
                        if k.startswith("version:") and it["parcel_id"] == vb["parcel_id"]),
                       key=lambda v: v["version_no"])
        bvers[0]["ring"][1] = [201, 0]
        errs = ss.internal_checks(pkg["manifest"], payload)
        assert any(x["code"] == "CHAIN_BROKEN" and x["id"] == bvers[0]["id"]
                   for x in errs), errs

    def test_cert_reference_missing_detected(self):
        va, vb = seed_ab()
        with tx() as conn:
            cert.issue(conn, va["id"], "2026-06-01T00:00:00Z")
        pkg = export_pkg([va["parcel_id"], vb["parcel_id"]])
        payload = self._pkg_payload(pkg)
        ckey = next(k for k in payload["items"] if k.startswith("certificate:"))
        citem = payload["items"][ckey]
        citem["version_id"] = "PV-deadbeef"
        citem["document"]["version_id"] = "PV-deadbeef"
        errs = ss.internal_checks(pkg["manifest"], payload)
        assert any(x["code"] == "REFERENCE_MISSING" and x["entity"] == "certificate"
                   for x in errs), errs


# ================================================================ 分块上传
class TestChunkUpload:
    def test_out_of_order_and_duplicate(self):
        va, vb = seed_ab()
        pkg = export_pkg([va["parcel_id"], vb["parcel_id"]], chunk_size=512)
        pid = upload_all(pkg)  # 默认逆序
        with tx() as conn:
            s = ss.session_detail(conn, pid)
        assert s["status"] == "READY"
        assert s["missing_seqs"] == []
        # 重复上传幂等
        raws = decode_chunks(pkg)
        with tx() as conn:
            r = ss.put_chunk(conn, pid, 0, raws[0])
        assert r["duplicate"] is True and r["status"] == "READY"

    def test_same_seq_different_content_conflicts_and_keeps_correct(self):
        va, vb = seed_ab()
        pkg = export_pkg([va["parcel_id"], vb["parcel_id"]], chunk_size=512)
        pid = upload_all(pkg)
        with tx() as conn:
            r = ss.put_chunk(conn, pid, 2, b"!" * 50)
        assert r["conflict"] is True
        assert r["status"] == "UPLOADING"
        assert r["session"]["chunk_conflicts"][0]["code"] == "CHUNK_CONTENT_MISMATCH"
        assert r["session"]["chunk_conflicts"][0]["seq"] == 2
        # 终检被挡
        with tx() as conn:
            out = ss.finalize(conn, pid)
        assert out["status"] == "CONFLICT"
        assert out["chunk_conflicts"][0]["code"] == "CHUNK_CONTENT_MISMATCH"
        # 重传正确内容后冲突清除，可导入
        raws = decode_chunks(pkg)
        with tx() as conn:
            r = ss.put_chunk(conn, pid, 2, raws[2])
            assert r["status"] == "READY"
            out = ss.finalize(conn, pid)
        assert out["status"] == "IMPORTED"

    def test_missing_chunk_blocks_finalize_and_resumable(self):
        va, vb = seed_ab()
        pkg = export_pkg([va["parcel_id"], vb["parcel_id"]], chunk_size=512)
        m = pkg["manifest"]
        with tx() as conn:
            ss.create_import(conn, m)
        raws = decode_chunks(pkg)
        for seq in range(m["chunk_count"]):
            if seq == m["chunk_count"] - 1:
                continue  # 模拟上传中断，最后一块没到
            with tx() as conn:
                ss.put_chunk(conn, m["package_id"], seq, raws[seq])
        with tx() as conn:
            out = ss.finalize(conn, m["package_id"])
        assert out["status"] == "MISSING_CHUNKS"
        assert out["missing_seqs"] == [m["chunk_count"] - 1]
        # 进程中断后继续：新事务里补传最后一块
        with tx() as conn:
            ss.put_chunk(conn, m["package_id"], m["chunk_count"] - 1,
                         raws[m["chunk_count"] - 1])
            out = ss.finalize(conn, m["package_id"])
        assert out["status"] == "IMPORTED"

    def test_seq_out_of_range_rejected(self):
        va, vb = seed_ab()
        pkg = export_pkg([va["parcel_id"], vb["parcel_id"]])
        pid = pkg["manifest"]["package_id"]
        with tx() as conn:
            ss.create_import(conn, pkg["manifest"])
            with pytest.raises(ValueError):
                ss.put_chunk(conn, pid, 999, b"x")


# ================================================================ 一次性导入 / 幂等
class TestFinalizeImport:
    def test_imports_into_empty_db_and_replays_same_result(self):
        va, vb = seed_ab()
        pkg = export_pkg([va["parcel_id"], vb["parcel_id"]])
        pid = pkg["manifest"]["package_id"]
        raws = decode_chunks(pkg)
        with receiver_db():
            with tx() as conn:
                ss.create_import(conn, pkg["manifest"], "recv")
            for seq in reversed(range(pkg["manifest"]["chunk_count"])):
                with tx() as conn:
                    ss.put_chunk(conn, pid, seq, raws[seq])
            with tx() as conn:
                out1 = ss.finalize(conn, pid)
            assert out1["status"] == "IMPORTED"
            assert out1["source_at"] == AT_NORM
            assert out1["inserted"]["version"] == 2
            assert {v["state"] for v in out1["versions"]} == {"NEW"}
            assert len(out1["current_changes"]) == 2
            # 哈希链在目标库可独立验真
            with get_conn() as conn:
                assert not vs.verify_hash_chain(conn, va["parcel_id"])
                assert not vs.verify_hash_chain(conn, vb["parcel_id"])
                # 宗地/点/操作/挂接全部补齐
                assert conn.execute("SELECT COUNT(*) c FROM parcel").fetchone()["c"] == 2
                assert conn.execute("SELECT COUNT(*) c FROM point").fetchone()["c"] == 6
            # 相同包标识再次导入 → 原结果（不二次落账）
            with tx() as conn:
                ci = ss.create_import(conn, pkg["manifest"])
                assert ci["replayed"] is True
                out2 = ss.finalize(conn, pid)
            assert out2["replayed"] is True
            assert out2["versions"] == out1["versions"]

    def test_reimport_identical_content_is_idempotent_no_new_rows(self):
        va, vb = seed_ab()
        pkg = export_pkg([va["parcel_id"], vb["parcel_id"]])
        pid = pkg["manifest"]["package_id"]
        raws = decode_chunks(pkg)
        with receiver_db():
            with tx() as conn:
                ss.create_import(conn, pkg["manifest"])
            for seq in range(len(raws)):
                with tx() as conn:
                    ss.put_chunk(conn, pid, seq, raws[seq])
            with tx() as conn:
                assert ss.finalize(conn, pid)["status"] == "IMPORTED"
            with tx() as conn:
                out = ss.finalize(conn, pid)
            assert out["status"] == "IMPORTED" and out["replayed"] is True
            with get_conn() as conn:
                assert conn.execute("SELECT COUNT(*) c FROM parcel_version"
                                    ).fetchone()["c"] == 2

    def test_same_package_id_different_manifest_rejected(self):
        va, vb = seed_ab()
        pkg = export_pkg([va["parcel_id"], vb["parcel_id"]])
        with receiver_db():
            with tx() as conn:
                ss.create_import(conn, pkg["manifest"])
                other = copy.deepcopy(pkg["manifest"])
                other["created_by"] = "different-content"
                # 保留同 package_id 但内容不同（无论是否重签）→ 拒绝覆盖
                with pytest.raises(ss.PackageConflict) as ei:
                    ss.create_import(conn, other)
        assert ei.value.conflicts[0]["code"] == "PACKAGE_ID_CONFLICT"

    def test_local_existing_different_version_blocks_and_keeps_db(self):
        va, vb = seed_ab()
        pkg = export_pkg([va["parcel_id"], vb["parcel_id"]])
        pid = pkg["manifest"]["package_id"]
        raws = decode_chunks(pkg)
        with receiver_db():
            # 接收库预置：同 id 版本但内容分叉（不同哈希）
            with tx() as conn:
                conn.execute(
                    "INSERT INTO parcel(id,label,created_at) VALUES(?,?,?)",
                    (va["parcel_id"], "甲", "2026-01-01T00:00:00Z"))
                conn.execute(
                    """INSERT INTO parcel_version
                       (id,parcel_id,version_no,status,ring_json,area,declared_area,
                        base_version_id,chain_parent_id,valid_from,valid_to,created_at,
                        version_hash)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (va["id"], va["parcel_id"], 1, "COMMITTED",
                     json.dumps([[0, 0], [10, 0], [10, 10], [0, 10]]), 100.0, None,
                     None, None, "2026-01-01T00:00:00Z", None,
                     "2026-01-01T00:00:00Z", "different-hash"))
            with tx() as conn:
                ss.create_import(conn, pkg["manifest"])
            for seq in range(len(raws)):
                with tx() as conn:
                    ss.put_chunk(conn, pid, seq, raws[seq])
            before = _dump_versions()
            with tx() as conn:
                out = ss.finalize(conn, pid)
            assert out["status"] == "CONFLICT"
            codes = {x["code"] for x in out["local_conflicts"]}
            assert "VERSION_CONFLICT" in codes
            loc = [x for x in out["local_conflicts"] if x["id"] == va["id"]]
            assert loc and loc[0]["detail"]["local_hash"] == "different-hash"
            # 数据库原样：版本未被覆盖、无新增行
            assert _dump_versions() == before
            with get_conn() as conn:
                assert conn.execute(
                    "SELECT version_hash FROM parcel_version WHERE id=?",
                    (va["id"],)).fetchone()["version_hash"] == "different-hash"
                assert conn.execute("SELECT COUNT(*) c FROM parcel_version"
                                    ).fetchone()["c"] == 1

    def test_local_diverged_current_version_detected(self):
        va, vb = seed_ab()
        pkg = export_pkg([va["parcel_id"], vb["parcel_id"]])
        pid = pkg["manifest"]["package_id"]
        raws = decode_chunks(pkg)
        with receiver_db():
            # 接收库：导入包内同 id 旧版本，但本地在版的是另一个版本 id
            with tx() as conn:
                conn.execute(
                    "INSERT INTO parcel(id,label,created_at) VALUES(?,?,?)",
                    (va["parcel_id"], "甲", "2026-01-01T00:00:00Z"))
                conn.execute(
                    """INSERT INTO parcel_version
                       (id,parcel_id,version_no,status,ring_json,area,valid_from,
                        valid_to,created_at,version_hash)
                       VALUES(?,?,?,?,?,?,?,?,?,?)""",
                    (va["id"], va["parcel_id"], 1, "SUPERSEDED",
                     json.dumps(RING_A), 10000.0, "2026-01-01T00:00:00Z",
                     "2026-02-01T00:00:00Z", "2026-01-01T00:00:00Z", va["id"] + "-h"))
                conn.execute(
                    """INSERT INTO parcel_version
                       (id,parcel_id,version_no,status,ring_json,area,valid_from,
                        created_at,version_hash)
                       VALUES(?,?,?,?,?,?,?,?,?)""",
                    ("PV-localother01", va["parcel_id"], 2, "COMMITTED",
                     json.dumps(RING_A), 10000.0, "2026-02-01T00:00:00Z",
                     "2026-02-01T00:00:00Z", "local-hash"))
            with tx() as conn:
                ss.create_import(conn, pkg["manifest"])
            for seq in range(len(raws)):
                with tx() as conn:
                    ss.put_chunk(conn, pid, seq, raws[seq])
            with tx() as conn:
                out = ss.finalize(conn, pid)
            assert out["status"] == "CONFLICT"
            assert any(x["code"] == "CURRENT_DIVERGED" and x["id"] == va["parcel_id"]
                       and x["detail"]["local_current"] == "PV-localother01"
                       for x in out["local_conflicts"])

    def test_failed_finalize_writes_nothing(self):
        va, vb = seed_ab()
        pkg = export_pkg([va["parcel_id"], vb["parcel_id"]])
        pid = pkg["manifest"]["package_id"]
        raws = decode_chunks(pkg)
        with receiver_db():
            # 接收库预置名称被篡改的甲宗地（PARCEL_CONFLICT）
            with tx() as conn:
                conn.execute(
                    "INSERT INTO parcel(id,label,created_at) VALUES(?,?,?)",
                    (va["parcel_id"], "被篡改", "2026-01-01T00:00:00Z"))
            with tx() as conn:
                ss.create_import(conn, pkg["manifest"])
            for seq in range(len(raws)):
                with tx() as conn:
                    ss.put_chunk(conn, pid, seq, raws[seq])
            with tx() as conn:
                out = ss.finalize(conn, pid)
            assert out["status"] == "CONFLICT"
            assert any(x["code"] == "PARCEL_CONFLICT"
                       for x in out["local_conflicts"])
            with get_conn() as conn:
                # 包内任何版本/点/操作都未落库（仅预置的一宗地）
                assert conn.execute("SELECT COUNT(*) c FROM parcel").fetchone()["c"] == 1
                assert conn.execute("SELECT COUNT(*) c FROM parcel_version"
                                    ).fetchone()["c"] == 0
                assert conn.execute("SELECT COUNT(*) c FROM point").fetchone()["c"] == 0
                assert conn.execute("SELECT COUNT(*) c FROM parcel_op").fetchone()["c"] == 0


def _dump_versions():
    with get_conn() as conn:
        return [(r["id"], r["version_hash"], r["status"], r["valid_to"])
                for r in conn.execute(
                    "SELECT id,version_hash,status,valid_to FROM parcel_version ORDER BY id")]


# ================================================================ HTTP 端到端
class TestSnapshotHTTP:
    def test_export_precheck_upload_finalize_flow(self):
        va, vb = seed_ab()
        r = client.post("/api/snapshots/export", json={
            "parcel_ids": [va["parcel_id"], vb["parcel_id"]], "at": AT,
            "chunk_size": 1024})
        assert r.status_code == 200, r.text
        pkg = r.json()
        m = pkg["manifest"]
        assert pkg["chunk_count"] == m["chunk_count"]

        # 离线预检
        r = client.post("/api/snapshots/precheck", json={
            "manifest": m, "chunks": pkg["chunks"], "local": True})
        assert r.json()["ready"] is True

        # 建导入会话
        r = client.post("/api/snapshots/imports", json={"manifest": m})
        assert r.status_code == 200
        assert r.json()["status"] == "UPLOADING"
        # 重复建会话幂等
        assert client.post("/api/snapshots/imports", json={"manifest": m}
                           ).json()["replayed"] is True

        # 乱序分块（base64 表单字段）
        for seq in reversed(range(m["chunk_count"])):
            rr = client.put(f"/api/snapshots/imports/{m['package_id']}/chunks/{seq}",
                            data={"data": pkg["chunks"][seq]})
            assert rr.status_code == 200, rr.text
        # 重复上传
        rr = client.put(f"/api/snapshots/imports/{m['package_id']}/chunks/0",
                        data={"data": pkg["chunks"][0]})
        assert rr.json()["duplicate"] is True

        # 会话详情
        s = client.get(f"/api/snapshots/imports/{m['package_id']}").json()
        assert s["status"] == "READY" and s["missing_seqs"] == []

        # 一次性导入 + 重放
        f1 = client.post(f"/api/snapshots/imports/{m['package_id']}/finalize").json()
        assert f1["status"] == "IMPORTED"
        f2 = client.post(f"/api/snapshots/imports/{m['package_id']}/finalize").json()
        assert f2["replayed"] is True
        assert f2["versions"] == f1["versions"]

        # 导入后地图可查到两宗
        mp = client.get("/api/map").json()
        assert {p["id"] for p in mp["parcels"]} == {va["parcel_id"], vb["parcel_id"]}

    def test_http_wrong_chunk_and_missing_block_finalize(self):
        va, vb = seed_ab()
        pkg = client.post("/api/snapshots/export", json={
            "parcel_ids": [va["parcel_id"], vb["parcel_id"]], "at": AT,
            "chunk_size": 512}).json()
        m = pkg["manifest"]
        client.post("/api/snapshots/imports", json={"manifest": m})
        # 缺块
        f = client.post(f"/api/snapshots/imports/{m['package_id']}/finalize").json()
        assert f["status"] == "MISSING_CHUNKS"
        assert len(f["missing_seqs"]) == m["chunk_count"]
        # 传一块错误内容
        r = client.put(f"/api/snapshots/imports/{m['package_id']}/chunks/0",
                       data={"data": ss._b64encode(b"bad") * 4})
        assert r.json()["conflict"] is True
        f = client.post(f"/api/snapshots/imports/{m['package_id']}/finalize").json()
        assert f["status"] == "CONFLICT"
        assert f["chunk_conflicts"][0]["id"] == 0

    def test_http_unknown_session_404(self):
        assert client.get("/api/snapshots/imports/PKG-nope").status_code == 404
        assert client.post("/api/snapshots/imports/PKG-nope/finalize").status_code == 404

    def test_same_id_other_manifest_409(self):
        va, vb = seed_ab()
        pkg = client.post("/api/snapshots/export", json={
            "parcel_ids": [va["parcel_id"], vb["parcel_id"]], "at": AT}).json()
        client.post("/api/snapshots/imports", json={"manifest": pkg["manifest"]})
        other = copy.deepcopy(pkg["manifest"])
        other["created_by"] = "x"
        r = client.post("/api/snapshots/imports", json={"manifest": other})
        assert r.status_code == 409
        assert r.json()["detail"]["conflicts"][0]["code"] == "PACKAGE_ID_CONFLICT"
