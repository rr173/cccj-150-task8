"""地籍快照交换包——接收窗口与移交（Receiving Window & Handover）验收测试。

覆盖需求：
* 创建会话指定负责人与有效期；上传分块与终检只允许当前负责人；
* 到期 / 人工冻结后保留已验真分块、缺块状态与冲突记录，但拒绝继续写入；
* 负责人移交 / 续期 / 重新开启必须携带幂等请求键并使用会话版本号防并发覆盖；
* 重新开启前重新核验清单与现存分块，失配保持冻结并返回可定位原因；
* 已导入会话不得重开/移交/续期/冻结，也不得清理其导入结果；
* 保留期清理只清理冻结超期且从未导入的会话；
* 前端所需的会话视图字段：负责人、剩余时间、冻结原因、操作审计。
"""
import contextlib
import copy
import json
import os
import tempfile

import pytest

_tmp = tempfile.mkdtemp(prefix="cad-snapwin-")
SRC_DB = os.path.join(_tmp, "src.db")
os.environ["CADASTRE_DB"] = SRC_DB
os.environ.setdefault("CADASTRE_PLAN_POLL_SECONDS", "3600")

from fastapi.testclient import TestClient  # noqa: E402

from app import main  # noqa: E402
from app.db import init_db, tx, get_conn  # noqa: E402
from app.services import snapshots as ss  # noqa: E402
from app.services import sync, versions as vs  # noqa: E402

client = TestClient(main.app)

RING_A = [[0, 0], [100, 0], [100, 100], [0, 100]]
RING_B = [[100, 0], [200, 0], [200, 100], [100, 100]]
AT = "2026-09-01T00:00:00Z"
T0 = "2026-09-30T08:00:00.000Z"
T1 = "2026-09-30T08:31:00.000Z"   # 创建后 31 分钟（30 分钟窗口已过期）
T2 = "2026-09-30T10:00:00.000Z"


@pytest.fixture(autouse=True)
def fresh_db(monkeypatch):
    for f in (SRC_DB,):
        if os.path.exists(f):
            os.remove(f)
    os.environ["CADASTRE_DB"] = SRC_DB
    init_db()
    # 固定测试时钟：默认 T0（窗口内）；各调用仍可用 as_of 显式指定未来/过去时刻
    from app.services import ids as _ids
    monkeypatch.setattr(_ids, "now_iso", lambda: T0)
    yield


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


def make_pkg(chunk_size=512):
    va, vb = seed_ab()
    with tx() as conn:
        return ss.build_package(
            conn, {"parcel_ids": [va["parcel_id"], vb["parcel_id"]], "at": AT,
                   "chunk_size": chunk_size})


def raws_of(pkg):
    return [ss._b64decode(c) for c in pkg["chunks"]]


def open_session(pkg, owner="alice", ttl_minutes=30, created_by="recv"):
    pid = pkg["manifest"]["package_id"]
    with tx() as conn:
        r = ss.create_import(conn, pkg["manifest"], created_by, owner=owner,
                             ttl_minutes=ttl_minutes, as_of=T0)
    return pid, r


def upload(pid, pkg, seq, actor="alice", ts=T0, conflict_raw=None):
    raw = conflict_raw if conflict_raw is not None else raws_of(pkg)[seq]
    with tx() as conn:
        return ss.put_chunk(conn, pid, seq, raw, actor=actor, as_of=ts)


def do(action, pid, payload, *, ts=T0):
    with tx() as conn:
        fn = getattr(ss, action)
        return fn(conn, pid, {**payload, "as_of": ts})


@contextlib.contextmanager
def receiver_db():
    """切到一个全新的"接收方"库（空库，模拟无业务数据的接收节点）。"""
    from app import config
    path = tempfile.mktemp(prefix="recv-", suffix=".db", dir=_tmp)
    old = os.environ["CADASTRE_DB"]
    old_path = config.__dict__.get("_ovr")
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


# ================================================================ 窗口/负责人基础
class TestWindowAndOwner:
    def test_create_with_owner_and_ttl(self):
        pkg = make_pkg()
        pid, r = open_session(pkg)
        assert r["version"] == 1 and r["status"] == "UPLOADING"
        s = r["session"]
        assert s["owner"] == "alice"
        assert s["valid_until"] == "2026-09-30T08:30:00.000Z"
        assert s["remaining_seconds"] == 1800
        assert s["window_open"] is True and s["frozen"] is False
        with tx() as conn:
            evs = ss.list_events(conn, pid)
        assert evs[0]["action"] == "CREATE" and evs[0]["actor"] == "alice"

    def test_explicit_valid_until_must_be_future(self):
        pkg = make_pkg()
        with pytest.raises(ValueError):
            with tx() as conn:
                ss.create_import(conn, pkg["manifest"], owner="a",
                                 valid_until="2020-01-01T00:00:00Z", as_of=T0)

    def test_non_owner_cannot_upload_or_finalize(self):
        pkg = make_pkg()
        pid, _ = open_session(pkg)
        with pytest.raises(ss.NotOwner) as ei:
            upload(pid, pkg, 0, actor="mallory")
        assert ei.value.code == "NOT_OWNER"
        # 未写入任何分块
        with tx() as conn:
            s = ss.session_detail(conn, pid)
            assert s["received_count"] == 0
            evs = ss.list_events(conn, pid)
        assert any(e["action"] == "WRITE_DENIED" and e["actor"] == "mallory"
                   for e in evs)
        # 负责人自己可以
        assert upload(pid, pkg, 0)["accepted"] is True
        with pytest.raises(ss.NotOwner):
            with tx() as conn:
                ss.finalize(conn, pid, actor="mallory", as_of=T0)
        # 无 owner 的会话不做写入限制（向后兼容）
        pkg2 = make_pkg()
        with tx() as conn:
            ss.create_import(conn, pkg2["manifest"], as_of=T0)
            r = ss.put_chunk(conn, pkg2["manifest"]["package_id"], 0,
                             raws_of(pkg2)[0], as_of=T0)
        assert r["accepted"] is True


# ================================================================ 到期冻结
class TestExpiryFreeze:
    def test_expired_upload_rejected_but_chunks_kept(self):
        pkg = make_pkg()
        pid, _ = open_session(pkg)
        # 窗口内传一半分块
        n = pkg["manifest"]["chunk_count"]
        for seq in range(0, n, 2):
            upload(pid, pkg, seq)
        # 到期后再传 → 惰性冻结 + 409
        with pytest.raises(ss.SessionFrozen) as ei:
            upload(pid, pkg, 1, ts=T1)
        assert ei.value.reason == "EXPIRED"
        sess = ei.value.session
        assert sess["status"] == "FROZEN" and sess["frozen"] is True
        assert sess["frozen_reason"] == "EXPIRED"
        # 已验真分块与缺块全部保留
        with tx() as conn:
            s = ss.session_detail(conn, pid)
            assert s["received_count"] == (n + 1) // 2
            assert 1 in s["missing_seqs"]
            evs = ss.list_events(conn, pid)
        assert any(e["action"] == "FREEZE" and e["detail"]["reason"] == "EXPIRED"
                   for e in evs)
        assert any(e["action"] == "WRITE_DENIED" for e in evs)

    def test_expired_finalize_rejected(self):
        pkg = make_pkg()
        pid, _ = open_session(pkg)
        with pytest.raises(ss.SessionFrozen) as ei:
            with tx() as conn:
                ss.finalize(conn, pid, actor="alice", as_of=T1)
        assert ei.value.reason == "EXPIRED"
        # 冻结状态已落库
        with tx() as conn:
            assert ss.get_session(conn, pid)["status"] == "FROZEN"

    def test_conflicts_preserved_on_freeze(self):
        pkg = make_pkg()
        pid, _ = open_session(pkg)
        upload(pid, pkg, 0)
        upload(pid, pkg, 0, conflict_raw=b"!" * 50)  # 同序号异内容
        with tx() as conn:
            assert ss.session_detail(conn, pid)["chunk_conflicts"]
        # 人工冻结（负责人操作）
        with tx() as conn:
            out = ss.manual_freeze(conn, pid, {"request_key": "k-freeze",
                                               "version": 1, "actor": "alice"})
        assert out["status"] == "FROZEN" and out["frozen_reason"] == "MANUAL"
        with tx() as conn:
            s = ss.session_detail(conn, pid)
        assert s["frozen_reason"] == "MANUAL"
        assert s["chunk_conflicts"]  # 冲突记录保留
        assert s["received_count"] == 1  # 已收正确块保留
        # 冻结后续传被拒绝
        with pytest.raises(ss.SessionFrozen):
            upload(pid, pkg, 1)


# ================================================================ 移交 / 续期 / 版本号 / 幂等
class TestHandoverRenewVersion:
    def test_concurrent_handover_loser_gets_version_conflict(self):
        pkg = make_pkg()
        pid, _ = open_session(pkg)
        # 两个客户端都持有 version=1，先后移交：第一个成功（版本→2），第二个失败
        with tx() as conn:
            r1 = ss.handover(conn, pid, {"new_owner": "bob", "request_key": "k-h1",
                                         "version": 1, "actor": "alice"})
        assert r1["version"] == 2 and r1["owner"] == "bob"
        with pytest.raises(ss.VersionConflict) as ei:
            with tx() as conn:
                ss.handover(conn, pid, {"new_owner": "carol", "request_key": "k-h2",
                                        "version": 1, "actor": "alice"})
        assert ei.value.code == "VERSION_CONFLICT"
        # 负责人未被并发覆盖
        with tx() as conn:
            assert ss.get_session(conn, pid)["owner"] == "bob"
        # 失败请求未消费 request_key：客户端刷新版本号后同键可成功
        with tx() as conn:
            r2 = ss.handover(conn, pid, {"new_owner": "carol", "request_key": "k-h2",
                                         "version": 2, "actor": "bob"})
        assert r2["version"] == 3 and r2["owner"] == "carol"

    def test_duplicate_request_is_idempotent(self):
        pkg = make_pkg()
        pid, _ = open_session(pkg)
        body = {"new_owner": "bob", "request_key": "k-dup", "version": 1,
                "actor": "alice"}
        with tx() as conn:
            r1 = ss.handover(conn, pid, body)
        # 同键重放（哪怕客户端版本号已过期）→ 首次结果，不二次变更
        with tx() as conn:
            r2 = ss.handover(conn, pid, body)
        assert r2["replayed"] is True
        assert r2["version"] == r1["version"] == 2
        with tx() as conn:
            assert ss.get_session(conn, pid)["version_no"] == 2
            evs = ss.list_events(conn, pid)
        assert [e["action"] for e in evs].count("HANDOVER") == 1
        # 同键不同内容 → 400
        with pytest.raises(ss.SessionError) as ei:
            with tx() as conn:
                ss.handover(conn, pid, {**body, "new_owner": "carol"})
        assert ei.value.code == "REQUEST_KEY_CONFLICT"

    def test_handover_requires_key_and_version(self):
        pkg = make_pkg()
        pid, _ = open_session(pkg)
        with pytest.raises(ss.SessionError) as ei:
            with tx() as conn:
                ss.handover(conn, pid, {"new_owner": "bob", "version": 1,
                                        "actor": "alice"})
        assert ei.value.code == "REQUEST_KEY_REQUIRED"
        with pytest.raises(ss.SessionError) as ei:
            with tx() as conn:
                ss.handover(conn, pid, {"new_owner": "bob", "request_key": "k",
                                        "actor": "alice"})
        assert ei.value.code == "VERSION_REQUIRED"

    def test_new_owner_takes_over_writes(self):
        pkg = make_pkg()
        pid, _ = open_session(pkg)
        with tx() as conn:
            ss.handover(conn, pid, {"new_owner": "bob", "request_key": "k",
                                    "version": 1, "actor": "alice"})
        # 旧负责人不能再写
        with pytest.raises(ss.NotOwner):
            upload(pid, pkg, 0, actor="alice")
        assert upload(pid, pkg, 0, actor="bob")["accepted"] is True

    def test_renew_extends_window_and_replay(self):
        pkg = make_pkg()
        pid, _ = open_session(pkg)
        # 窗口到期前（08:20）续期 60 分钟 → 新截止 09:20
        tr = "2026-09-30T08:20:00.000Z"
        with tx() as conn:
            r = ss.renew(conn, pid, {"ttl_minutes": 60, "request_key": "k-renew",
                                    "version": 1, "actor": "alice", "as_of": tr})
        assert r["version"] == 2
        assert r["valid_until"] == "2026-09-30T09:20:00.000Z"
        # T1（原窗口 08:30 已过、新窗口内）可以继续上传
        assert upload(pid, pkg, 0, actor="alice", ts=T1)["accepted"] is True
        # 同键重放
        with tx() as conn:
            r2 = ss.renew(conn, pid, {"ttl_minutes": 60, "request_key": "k-renew",
                                     "version": 1, "actor": "alice", "as_of": tr})
        assert r2["replayed"] is True and r2["version"] == 2

    def test_renew_rejected_when_frozen_and_stale_version(self):
        pkg = make_pkg()
        pid, _ = open_session(pkg)
        # 过期冻结后持旧版本号续期：版本号仍为 1（到期冻结不递增），
        # 但冻结状态拒绝续期
        with pytest.raises(ss.SessionFrozen) as ei:
            with tx() as conn:
                ss.renew(conn, pid, {"ttl_minutes": 60, "request_key": "k-r",
                                     "version": 1, "actor": "alice", "as_of": T1})
        assert ei.value.reason == "EXPIRED"
        # 移交后版本号已变，旧客户端续期 → VERSION_CONFLICT
        with tx() as conn:
            ss.handover(conn, pid, {"new_owner": "bob", "request_key": "k-h",
                                    "version": 1, "actor": "alice"})
        with pytest.raises(ss.VersionConflict):
            with tx() as conn:
                ss.renew(conn, pid, {"ttl_minutes": 60, "request_key": "k-r2",
                                     "version": 1, "actor": "bob"})

    def test_handover_allowed_on_frozen_session_without_unfreezing(self):
        pkg = make_pkg()
        pid, _ = open_session(pkg)
        upload(pid, pkg, 0)
        # 到期冻结
        with pytest.raises(ss.SessionFrozen):
            upload(pid, pkg, 1, ts=T1)
        # 当前负责人仍可移交（不解除冻结）
        with tx() as conn:
            r = ss.handover(conn, pid, {"new_owner": "bob", "request_key": "k-h",
                                        "version": 1, "actor": "alice", "as_of": T1})
        assert r["status"] == "FROZEN"
        with tx() as conn:
            s = ss.get_session(conn, pid)
        assert s["owner"] == "bob" and s["frozen"] == 1
        # 新负责人仍不能直接写入（必须先重开）
        with pytest.raises(ss.SessionFrozen):
            upload(pid, pkg, 1, actor="bob", ts=T1)


# ================================================================ 重新开启（重验）
class TestReopen:
    def _frozen_expired_with_chunks(self, pkg, seq=0):
        pid, _ = open_session(pkg)
        upload(pid, pkg, seq)
        with pytest.raises(ss.SessionFrozen):
            upload(pid, pkg, seq + 1 if seq + 1 < pkg["manifest"]["chunk_count"] else seq,
                   ts=T1)
        return pid

    def test_reopen_verifies_and_resumes_upload(self):
        pkg = make_pkg()
        n = pkg["manifest"]["chunk_count"]
        pid = self._frozen_expired_with_chunks(pkg)
        # 重开（现存分块正确；缺块不阻止重开，允许续传）
        with tx() as conn:
            r = ss.reopen(conn, pid, {"request_key": "k-reopen", "version": 1,
                                     "actor": "alice", "ttl_minutes": 30, "as_of": T1})
        assert r["status"] == "UPLOADING" and r["version"] == 2
        # 原已收分块保留，补传其余后可终检导入
        for seq in range(1, n):
            assert upload(pid, pkg, seq, actor="alice", ts=T1)["accepted"] is True
        with tx() as conn:
            out = ss.finalize(conn, pid, actor="alice", as_of=T1)
        assert out["status"] == "IMPORTED"

    def test_reopen_without_new_window_when_expired_rejected(self):
        pkg = make_pkg()
        pid = self._frozen_expired_with_chunks(pkg)
        with pytest.raises(ss.SessionError) as ei:
            with tx() as conn:
                ss.reopen(conn, pid, {"request_key": "k-r", "version": 1,
                                      "actor": "alice", "as_of": T1})
        assert ei.value.code == "WINDOW_REQUIRED"

    def test_reopen_mismatch_keeps_frozen_with_locatable_reason(self):
        """全块齐备但接收库在冻结期间发生分叉：重开重验失败，保持冻结。"""
        pkg = make_pkg()            # 在源库导出
        m = pkg["manifest"]
        raws = raws_of(pkg)
        # 从 payload 取一个版本 id/parcel_id（先在源库拼出载荷）
        raw = b"".join(raws)
        payload, _ = ss.parse_payload(m, raw)
        vitem = next(v for k, v in payload["items"].items()
                     if k.startswith("version:"))
        with receiver_db():
            pid = m["package_id"]
            with tx() as conn:
                ss.create_import(conn, m, "recv", owner="alice",
                                 ttl_minutes=120, as_of=T0)
            for seq in range(m["chunk_count"]):
                upload(pid, pkg, seq)
            with tx() as conn:
                ss.manual_freeze(conn, pid, {"request_key": "k-f", "version": 1,
                                             "actor": "alice"})
            # 冻结期间接收库被写入同 id 不同哈希的本地版本（内容分叉）
            with tx() as conn:
                conn.execute(
                    "INSERT INTO parcel(id,label,created_at) VALUES(?,?,?)",
                    (vitem["parcel_id"], "甲", "2026-01-01T00:00:00Z"))
                conn.execute(
                    """INSERT INTO parcel_version
                       (id,parcel_id,version_no,status,ring_json,area,valid_from,
                        created_at,version_hash)
                       VALUES(?,?,?,?,?,?,?,?,?)""",
                    (vitem["id"], vitem["parcel_id"], vitem["version_no"],
                     "COMMITTED", json.dumps(vitem["ring"]), vitem["area"],
                     vitem["valid_from"], vitem["created_at"],
                     "TAMPERED-LOCAL-HASH"))
            # 重开：完整终检口径重验 → VERSION_CONFLICT，保持冻结
            with pytest.raises(ss.ReopenMismatch) as ei:
                with tx() as conn:
                    ss.reopen(conn, pid, {"request_key": "k-r", "version": 2,
                                          "actor": "alice", "ttl_minutes": 30})
            mismatches = ei.value.conflicts
            codes = {x["code"] for x in mismatches}
            assert "VERSION_CONFLICT" in codes
            loc = [x for x in mismatches if x["id"] == vitem["id"]]
            assert loc and loc[0]["detail"]["local_hash"] == "TAMPERED-LOCAL-HASH"
            with tx() as conn:
                s = ss.get_session(conn, pid)
                assert s["status"] == "FROZEN"
                assert s["frozen_reason"] == "REOPEN_MISMATCH"
                assert s["version_no"] == 2          # 版本号未递增
                assert s["frozen_detail"]["mismatch_count"] >= 1
            # request_key 已被终局拒绝：修复后同键重放仍回放首次拒绝
            with pytest.raises(ss.ReplayedDecision) as er:
                with tx() as conn:
                    ss.reopen(conn, pid, {"request_key": "k-r", "version": 2,
                                          "actor": "alice", "ttl_minutes": 30})
            assert er.value.payload["replayed"] is True
            assert er.value.payload["code"] == "REOPEN_MISMATCH"
            # 回放的是首次判定时的快照（仍带着失配明细）
            assert any(x["id"] == vitem["id"] and
                       x["detail"]["local_hash"] == "TAMPERED-LOCAL-HASH"
                       for x in er.value.payload["conflicts"])
            # 即使携带（会话被推进后的）新版本号，原操作标识依旧回放拒绝
            with pytest.raises(ss.ReplayedDecision):
                with tx() as conn:
                    ss.reopen(conn, pid, {"request_key": "k-r", "version": 99,
                                          "actor": "alice", "ttl_minutes": 30})
            # 消除冲突：必须用**新 request_key + 当前版本号**才能再次校验通过
            with tx() as conn:
                conn.execute("DELETE FROM parcel_version WHERE id=?",
                             (vitem["id"],))
                conn.execute("DELETE FROM parcel WHERE id=?",
                             (vitem["parcel_id"],))
                r = ss.reopen(conn, pid, {"request_key": "k-r2", "version": 2,
                                          "actor": "alice", "ttl_minutes": 30})
            assert r["status"] in ("UPLOADING", "READY")
            assert r["version"] == 3
            # 重放未重复落审计：REOPEN_REJECTED 只在首次拒绝时记一条
            with tx() as conn:
                evs = ss.list_events(conn, pid)
            assert sum(1 for e in evs if e["action"] == "REOPEN_REJECTED") == 1
            assert sum(1 for e in evs if e["action"] == "FREEZE"
                       and e["detail"].get("reason") == "REOPEN_MISMATCH") == 1

    def test_reopen_tampered_manifest_fails(self):
        pkg = make_pkg()
        pid = self._frozen_expired_with_chunks(pkg)
        # 篡改已存清单（模拟存储层异常）→ 重验签章失败，保持冻结
        with tx() as conn:
            row = ss.get_session(conn, pid)
            m2 = copy.deepcopy(row["manifest"])
            m2["created_by"] = "attacker"
            conn.execute("UPDATE snapshot_session SET manifest_json=? WHERE package_id=?",
                         (json.dumps(m2, ensure_ascii=False), pid))
        with pytest.raises(ss.ReopenMismatch) as ei:
            with tx() as conn:
                ss.reopen(conn, pid, {"request_key": "k-r", "version": 1,
                                      "actor": "alice", "ttl_minutes": 30, "as_of": T1})
        assert any(x["code"] == "MANIFEST_SIGNATURE_INVALID"
                   for x in ei.value.conflicts)
        with tx() as conn:
            assert ss.get_session(conn, pid)["frozen_reason"] == "REOPEN_MISMATCH"

    def test_reopen_duplicate_request_replays(self):
        pkg = make_pkg()
        pid = self._frozen_expired_with_chunks(pkg)
        body = {"request_key": "k-r", "version": 1, "actor": "alice",
                "ttl_minutes": 30, "as_of": T1}
        with tx() as conn:
            r1 = ss.reopen(conn, pid, body)
        with tx() as conn:
            r2 = ss.reopen(conn, pid, body)
        assert r1["version"] == r2["version"] == 2
        assert r2["replayed"] is True


# ================================================================ 重开拒绝的请求去重（终局判定）
class TestReopenDecisionIdempotency:
    """一次重开校验被拒后，操作标识（request_key）永久对应首次拒绝响应。

    场景：磁盘分块损坏（或接收库分叉）导致 reopen 重验失败 → 会话保持冻结；
    后台修复后，原 request_key 的连续点击/网络重试只回放首次拒绝，必须用
    新 request_key + 最新会话版本号才能再次校验；会话已导入后同样不可恢复。
    """

    @contextlib.contextmanager
    def _frozen_ready_with_corrupt_chunk(self, *, corrupt=True):
        """全块齐备 → 人工冻结 → 直接破坏磁盘上的分块 1（模拟磁盘损坏）。

        在独立的"接收方"库内完成，yield (pkg, pid, raws)。
        """
        pkg = make_pkg()
        m = pkg["manifest"]
        raws = raws_of(pkg)
        assert m["chunk_count"] >= 2
        pid = m["package_id"]
        with receiver_db():
            with tx() as conn:
                ss.create_import(conn, m, "recv", owner="alice",
                                 ttl_minutes=120, as_of=T0)
            for seq, raw in enumerate(raws):
                with tx() as conn:
                    ss.put_chunk(conn, pid, seq, raw, actor="alice", as_of=T0)
            with tx() as conn:
                ss.manual_freeze(conn, pid, {"request_key": "k-f", "version": 1,
                                             "actor": "alice"})
            if corrupt:
                with tx() as conn:
                    conn.execute(
                        "UPDATE snapshot_chunk SET content=?,sha256=? "
                        "WHERE package_id=? AND seq=1",
                        (b"CORRUPT-BYTES-ON-DISK",
                         ss.sha256_hex(b"CORRUPT-BYTES-ON-DISK"), pid))
            yield pkg, pid, raws

    def _repair_chunk(self, pid, raws, seq=1):
        """后台修复磁盘上的损坏分块（不经过会话写入守卫）。"""
        with tx() as conn:
            conn.execute(
                "UPDATE snapshot_chunk SET content=?,sha256=? "
                "WHERE package_id=? AND seq=?",
                (raws[seq], ss.sha256_hex(raws[seq]), pid, seq))

    # ---- 1) 首次拒绝 + 拒绝响应重放（连续点击/网络重试不绕过首次判定）
    def test_first_rejection_is_replayed_forever(self):
        with self._frozen_ready_with_corrupt_chunk() as (pkg, pid, raws):
            body = {"request_key": "k-ro-1", "version": 2, "actor": "alice",
                    "ttl_minutes": 30, "as_of": T1}
            # 首次：重验发现分块 1 损坏 → REOPEN_MISMATCH，保持冻结
            with pytest.raises(ss.ReopenMismatch) as ei:
                with tx() as conn:
                    ss.reopen(conn, pid, body)
            first_codes = sorted(c["code"] for c in ei.value.conflicts)
            assert "CHUNK_HASH_MISMATCH" in first_codes
            bad = [c for c in ei.value.conflicts if c.get("seq") == 1 or c.get("id") == 1]
            assert bad and bad[0]["code"] == "CHUNK_HASH_MISMATCH"
            with tx() as conn:
                s = ss.get_session(conn, pid)
                row = conn.execute(
                    "SELECT outcome,status_code FROM snapshot_request WHERE request_key=?",
                    ("k-ro-1",)).fetchone()
            assert s["status"] == "FROZEN" and s["version_no"] == 2
            assert s["frozen_reason"] == "REOPEN_MISMATCH"
            assert row["outcome"] == "REJECTED" and row["status_code"] == 409

            # 后台修复损坏分块：原操作标识的重放仍回放首次拒绝（带首次失配明细）
            self._repair_chunk(pid, raws)
            for i in range(5):  # 连续点击/网络层自动重试
                with pytest.raises(ss.ReplayedDecision) as er:
                    with tx() as conn:
                        ss.reopen(conn, pid, body)
                p = er.value.payload
                assert p["replayed"] is True
                assert p["code"] == "REOPEN_MISMATCH"
                assert sorted(c["code"] for c in p["conflicts"]) == first_codes
                assert any(c.get("seq") == 1 or c.get("id") == 1 for c in p["conflicts"])
                assert p["session"]["frozen_reason"] == "REOPEN_MISMATCH"

            # 不产生任何新的状态变更：仍冻结、版本号不增、幂等记录只有一条、
            # 冻结与 REOPEN_REJECTED 审计各只记一次
            with tx() as conn:
                s = ss.get_session(conn, pid)
                evs = ss.list_events(conn, pid)
                n_req = conn.execute(
                    "SELECT COUNT(*) c FROM snapshot_request WHERE request_key=?",
                    ("k-ro-1",)).fetchone()["c"]
            assert s["status"] == "FROZEN" and s["version_no"] == 2
            assert n_req == 1
            assert sum(1 for e in evs if e["action"] == "REOPEN_REJECTED") == 1
            assert sum(1 for e in evs if e["action"] == "FREEZE"
                       and e["detail"].get("reason") == "REOPEN_MISMATCH") == 1

    # ---- 并发：首次判定进行中的同键并发请求（多客户端/双击）全部排队，
    #      恰好一个首次判定，其余回放——不会产生第二次校验/第二次状态变更
    def test_concurrent_duplicates_share_single_decision(self):
        import threading
        with self._frozen_ready_with_corrupt_chunk() as (pkg, pid, raws):
            outcomes = []
            barrier = threading.Barrier(5)

            def attempt(i):
                body = {"request_key": "k-ro-race", "version": 2,
                        "actor": "alice", "ttl_minutes": 30, "as_of": T1}
                barrier.wait()
                try:
                    with tx() as conn:
                        ss.reopen(conn, pid, body)
                    outcomes.append(("ok", i))
                except ss.ReopenMismatch:
                    outcomes.append(("first", i))
                except ss.ReplayedDecision as e:
                    outcomes.append(("replay", i, bool(e.payload.get("replayed"))))
                except Exception as e:  # noqa: BLE001
                    outcomes.append(("other", i, type(e).__name__))

            threads = [threading.Thread(target=attempt, args=(i,)) for i in range(5)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            kinds = [o[0] for o in outcomes]
            assert kinds.count("first") == 1 and kinds.count("replay") == 4, outcomes
            assert all(o[2] for o in outcomes if o[0] == "replay")
            with tx() as conn:
                evs = ss.list_events(conn, pid)
            assert sum(1 for e in evs if e["action"] == "REOPEN_REJECTED") == 1
            assert sum(1 for e in evs if e["action"] == "FREEZE"
                       and e["detail"].get("reason") == "REOPEN_MISMATCH") == 1

    # ---- 同键携带新版本号（会话已被推进）也不绕过；同键异内容 400
    def test_replay_takes_precedence_over_version_and_content(self):
        with self._frozen_ready_with_corrupt_chunk() as (pkg, pid, raws):
            body = {"request_key": "k-ro-1", "version": 2, "actor": "alice",
                    "ttl_minutes": 30, "as_of": T1}
            with pytest.raises(ss.ReopenMismatch):
                with tx() as conn:
                    ss.reopen(conn, pid, body)
            self._repair_chunk(pid, raws)
            # 换一个会话版本号（模拟客户端已刷新）重放旧标识：依旧回放拒绝，
            # 不会被当成 VERSION_CONFLICT，也不会重新校验成功
            with pytest.raises(ss.ReplayedDecision) as er:
                with tx() as conn:
                    ss.reopen(conn, pid, {**body, "version": 99})
            assert er.value.payload["replayed"] is True
            # 同键不同请求内容 → REQUEST_KEY_CONFLICT（不能借改内容重放）
            with pytest.raises(ss.SessionError) as ei:
                with tx() as conn:
                    ss.reopen(conn, pid, {**body, "ttl_minutes": 60})
            assert ei.value.code == "REQUEST_KEY_CONFLICT"

    # ---- 2) 修复后：新 request_key + 最新版本号 → 重验通过、解冻成功
    def test_new_key_after_repair_succeeds(self):
        with self._frozen_ready_with_corrupt_chunk() as (pkg, pid, raws):
            body = {"request_key": "k-ro-bad", "version": 2, "actor": "alice",
                    "ttl_minutes": 30, "as_of": T1}
            with pytest.raises(ss.ReopenMismatch):
                with tx() as conn:
                    ss.reopen(conn, pid, body)
            # 未修复前，新标识同样被拒（拒绝与 request_key 无关，损坏客观存在）
            with pytest.raises(ss.ReopenMismatch) as ei:
                with tx() as conn:
                    ss.reopen(conn, pid, {**body, "request_key": "k-ro-try2"})
            assert any(c.get("seq") == 1 or c.get("id") == 1 for c in ei.value.conflicts)
            # 后台修复后用新标识 + 当前版本号 → 通过
            self._repair_chunk(pid, raws)
            with tx() as conn:
                r = ss.reopen(conn, pid, {
                    "request_key": "k-ro-ok", "version": 2, "actor": "alice",
                    "ttl_minutes": 30, "as_of": T1})
            assert r["replayed"] is False
            assert r["status"] == "READY" and r["version"] == 3
            with tx() as conn:
                s = ss.get_session(conn, pid)
            assert s["frozen"] == 0 and s["frozen_reason"] is None
            # 全块齐备且正确：可以终检导入
            with tx() as conn:
                out = ss.finalize(conn, pid, actor="alice", as_of=T1)
            assert out["status"] == "IMPORTED"
            # 旧被拒标识在导入后重放：仍回放首次拒绝（不返回导入结果、不写状态）
            with pytest.raises(ss.ReplayedDecision) as er:
                with tx() as conn:
                    ss.reopen(conn, pid, body)
            assert er.value.payload["code"] == "REOPEN_MISMATCH"

    # ---- 3) 过期修订号拦截（新标识也不行；且不消费标识）
    def test_stale_version_with_new_key_blocked_and_key_not_consumed(self):
        with self._frozen_ready_with_corrupt_chunk(corrupt=False) as (pkg, pid, raws):
            # 冻结后版本号 = 2；先让会话被推进到 3（一次成功重开）
            with tx() as conn:
                r = ss.reopen(conn, pid, {"request_key": "k-ro-0", "version": 2,
                                          "actor": "alice", "ttl_minutes": 30,
                                          "as_of": T1})
            assert r["version"] == 3
            # 再冻结（版本 → 4）
            with tx() as conn:
                ss.manual_freeze(conn, pid, {"request_key": "k-f2", "version": 3,
                                             "actor": "alice", "as_of": T1})
            # 全新标识持旧版本号 → VERSION_CONFLICT，且标识未被消费
            body = {"request_key": "k-ro-stale", "version": 2, "actor": "alice",
                    "ttl_minutes": 30, "as_of": T1}
            with pytest.raises(ss.VersionConflict) as ei:
                with tx() as conn:
                    ss.reopen(conn, pid, body)
            assert ei.value.code == "VERSION_CONFLICT"
            with tx() as conn:
                assert conn.execute(
                    "SELECT COUNT(*) c FROM snapshot_request WHERE request_key=?",
                    ("k-ro-stale",)).fetchone()["c"] == 0
            # 同标识改带最新版本号 → 通过版本关（重验），证明未消费
            with tx() as conn:
                r2 = ss.reopen(conn, pid, {**body, "version": 4})
            assert r2["version"] == 5

    # ---- 4) 已完成导入：不可恢复（新标识 SESSION_IMPORTED；旧标识回放拒绝）
    def test_imported_session_not_recoverable(self):
        with self._frozen_ready_with_corrupt_chunk() as (pkg, pid, raws):
            rejected_body = {"request_key": "k-ro-rej", "version": 2,
                             "actor": "alice", "ttl_minutes": 30, "as_of": T1}
            with pytest.raises(ss.ReopenMismatch):
                with tx() as conn:
                    ss.reopen(conn, pid, rejected_body)
            self._repair_chunk(pid, raws)
            with tx() as conn:
                r = ss.reopen(conn, pid, {**rejected_body, "request_key": "k-ro-fix"})
            assert r["status"] == "READY"
            with tx() as conn:
                assert ss.finalize(conn, pid, actor="alice", as_of=T1)["status"] == "IMPORTED"
            # 新标识（即使带当前版本号）→ SESSION_IMPORTED
            with pytest.raises(ss.SessionFrozen) as ei:
                with tx() as conn:
                    ss.reopen(conn, pid, {"request_key": "k-ro-after-import",
                                          "version": 3, "actor": "alice",
                                          "ttl_minutes": 30, "as_of": T2})
            assert ei.value.code == "SESSION_IMPORTED"
            # 旧被拒标识重放：仍回放首次拒绝
            with pytest.raises(ss.ReplayedDecision) as er:
                with tx() as conn:
                    ss.reopen(conn, pid, rejected_body)
            assert er.value.payload["code"] == "REOPEN_MISMATCH"
            # 终检本身幂等返回首次导入结果
            with tx() as conn:
                out = ss.finalize(conn, pid, actor="anyone", as_of=T2)
            assert out["status"] == "IMPORTED" and out["replayed"] is True


# ================================================================ 已导入保护
class TestImportedProtection:
    def _imported(self, pkg):
        pid = pkg["manifest"]["package_id"]
        with tx() as conn:
            ss.create_import(conn, pkg["manifest"], "recv", owner="alice",
                             ttl_minutes=120, as_of=T0)
        for seq, raw in enumerate(raws_of(pkg)):
            with tx() as conn:
                ss.put_chunk(conn, pid, seq, raw, actor="alice", as_of=T0)
        with tx() as conn:
            out = ss.finalize(conn, pid, actor="alice", as_of=T0)
        assert out["status"] == "IMPORTED"
        return pid

    def test_imported_session_rejects_all_management(self):
        pkg = make_pkg()
        pid = self._imported(pkg)
        for action, fn, payload in (
                ("handover", ss.handover,
                 {"new_owner": "x", "request_key": "k", "version": 1}),
                ("renew", ss.renew,
                 {"ttl_minutes": 10, "request_key": "k", "version": 1}),
                ("freeze", ss.manual_freeze,
                 {"request_key": "k", "version": 1}),
                ("reopen", ss.reopen,
                 {"request_key": "k", "version": 1, "ttl_minutes": 10})):
            with pytest.raises(ss.SessionFrozen) as ei:
                with tx() as conn:
                    fn(conn, pid, payload)
            assert ei.value.code == "SESSION_IMPORTED", action
        # 终检仍幂等返回首次结果
        with tx() as conn:
            r = ss.finalize(conn, pid, actor="anyone", as_of=T2)
        assert r["replayed"] is True and r["status"] == "IMPORTED"

    def test_imported_result_not_cleaned(self):
        pkg = make_pkg()
        pid = self._imported(pkg)
        # 即使保留期为 0：已导入会话仍受保护
        with tx() as conn:
            rep = ss.cleanup_expired(conn, retention_days=0, as_of=T2)
        assert rep["removed_count"] == 0
        assert rep["protected_imported"] == 1
        with tx() as conn:
            assert ss.get_session(conn, pid) is not None
            # 导入落库的业务数据仍在
            assert conn.execute(
                "SELECT COUNT(*) c FROM parcel_version").fetchone()["c"] == 2


# ================================================================ 保留期清理
class TestRetentionCleanup:
    def test_only_frozen_beyond_retention_cleaned(self):
        pkg1 = make_pkg()   # 库 1：导出端数据
        pid1, _ = open_session(pkg1, ttl_minutes=10)
        upload(pid1, pkg1, 0)
        # 到期冻结于 T1
        with pytest.raises(ss.SessionFrozen):
            upload(pid1, pkg1, 1, ts=T1)
        with tx() as conn:
            assert ss.get_session(conn, pid1)["frozen_at"] == T1

        # 清理时刻 T1 + 6 天：默认保留 7 天 → 不清理
        with tx() as conn:
            rep = ss.cleanup_expired(
                conn, as_of="2026-10-06T08:31:00.000Z")
            assert rep["removed_count"] == 0
            assert ss.get_session(conn, pid1) is not None

        # 超过保留期（8 天）→ 清理会话、分块、审计、幂等请求
        with tx() as conn:
            rep = ss.cleanup_expired(
                conn, as_of="2026-10-08T08:31:00.000Z")
            assert rep["removed_count"] == 1
            assert rep["removed"][0]["package_id"] == pid1
            assert ss.get_session(conn, pid1) is None
            assert conn.execute(
                "SELECT COUNT(*) c FROM snapshot_chunk WHERE package_id=?",
                (pid1,)).fetchone()["c"] == 0
            assert conn.execute(
                "SELECT COUNT(*) c FROM snapshot_session_event WHERE package_id=?",
                (pid1,)).fetchone()["c"] == 0

    def test_unfrozen_sessions_never_cleaned(self):
        pkg = make_pkg()
        pid, _ = open_session(pkg, ttl_minutes=10000)
        upload(pid, pkg, 0, ts=T0)
        with tx() as conn:
            rep = ss.cleanup_expired(conn, retention_days=0, as_of=T2)
            assert rep["removed_count"] == 0
            assert ss.get_session(conn, pid) is not None


# ================================================================ HTTP 端到端
class TestHTTPWindow:
    def test_full_window_lifecycle_http(self):
        pkg = make_pkg()
        m = pkg["manifest"]
        # 建会话（负责人 + 有效期）
        r = client.post("/api/snapshots/imports", json={
            "manifest": m, "owner": "alice", "ttl_minutes": 30, "as_of": T0})
        assert r.status_code == 200, r.text
        assert r.json()["session"]["remaining_seconds"] == 1800

        # 非负责人上传 → 403
        rr = client.put(f"/api/snapshots/imports/{m['package_id']}/chunks/0",
                        data={"data": pkg["chunks"][0], "actor": "mallory"})
        assert rr.status_code == 403
        assert rr.json()["detail"]["code"] == "NOT_OWNER"

        # 负责人上传成功
        rr = client.put(f"/api/snapshots/imports/{m['package_id']}/chunks/0",
                        data={"data": pkg["chunks"][0], "actor": "alice"})
        assert rr.status_code == 200 and rr.json()["accepted"] is True

        # 移交：缺 request_key → 422（必填字段校验）
        rr = client.post(f"/api/snapshots/imports/{m['package_id']}/handover",
                         json={"new_owner": "bob", "version": 1, "actor": "alice"})
        assert rr.status_code == 422
        # 旧版本号并发移交 → 409 VERSION_CONFLICT
        client.post(f"/api/snapshots/imports/{m['package_id']}/handover",
                    json={"new_owner": "bob", "request_key": "h1", "version": 1,
                          "actor": "alice"})
        rr = client.post(f"/api/snapshots/imports/{m['package_id']}/handover",
                         json={"new_owner": "carol", "request_key": "h2",
                               "version": 1, "actor": "alice"})
        assert rr.status_code == 409
        assert rr.json()["detail"]["code"] == "VERSION_CONFLICT"

        # 到期后续期（bob 是负责人；用服务层注入时间模拟过期，HTTP 层走真实时间，
        # 这里直接验证冻结后终检 409 的结构——改为通过 freeze 接口人工冻结）
        rr = client.post(f"/api/snapshots/imports/{m['package_id']}/freeze",
                         json={"request_key": "f1", "version": 2, "actor": "bob"})
        assert rr.status_code == 200 and rr.json()["frozen_reason"] == "MANUAL"
        # 冻结后上传 → 409，响应带可定位会话视图
        rr = client.put(f"/api/snapshots/imports/{m['package_id']}/chunks/1",
                        data={"data": pkg["chunks"][1], "actor": "bob"})
        assert rr.status_code == 409
        detail = rr.json()["detail"]
        assert detail["code"] == "SESSION_FROZEN"
        assert detail["session"]["frozen_reason"] == "MANUAL"
        assert detail["session"]["received_count"] == 1  # 已收块保留

        # 重开（全块未齐，现存块正确）
        rr = client.post(f"/api/snapshots/imports/{m['package_id']}/reopen",
                         json={"request_key": "r1", "version": 3, "actor": "bob",
                               "ttl_minutes": 60})
        assert rr.status_code == 200, rr.text
        assert rr.json()["version"] == 4
        # 同键重放
        rr2 = client.post(f"/api/snapshots/imports/{m['package_id']}/reopen",
                          json={"request_key": "r1", "version": 3, "actor": "bob",
                                "ttl_minutes": 60})
        assert rr2.json()["replayed"] is True

        # 列表/详情含负责人、剩余时间、冻结原因；审计可查
        lst = client.get("/api/snapshots/imports").json()
        row = next(x for x in lst if x["package_id"] == m["package_id"])
        assert row["owner"] == "bob" and row["version"] == 4
        assert row["remaining_seconds"] is not None and row["remaining_seconds"] > 0
        evs = client.get(f"/api/snapshots/imports/{m['package_id']}/events").json()
        actions = [e["action"] for e in evs]
        for a in ("CREATE", "CHUNK_ACCEPTED", "WRITE_DENIED", "HANDOVER",
                  "FREEZE", "REOPEN"):
            assert a in actions, a

    def test_expired_upload_409_via_http(self):
        pkg = make_pkg()
        m = pkg["manifest"]
        # 建会话时窗口直接给定为过去时刻 → 400
        r = client.post("/api/snapshots/imports", json={
            "manifest": m, "owner": "alice",
            "valid_until": "2020-01-01T00:00:00Z"})
        assert r.status_code == 400
        # 用绝对有效期创建一个在固定时钟 T0 下"即将到期"的会话不便经 HTTP 注入，
        # 改为：创建无窗口会话，人工冻结，再上传 → 409（冻结原因 MANUAL）
        r = client.post("/api/snapshots/imports", json={"manifest": m})
        assert r.status_code == 200
        client.post(f"/api/snapshots/imports/{m['package_id']}/freeze",
                    json={"request_key": "f", "version": 1})
        rr = client.put(f"/api/snapshots/imports/{m['package_id']}/chunks/0",
                        data={"data": pkg["chunks"][0]})
        assert rr.status_code == 409
        assert rr.json()["detail"]["reason"] == "MANUAL"
        # 保留期清理接口可用
        rep = client.post("/api/snapshots/imports-cleanup",
                          json={"retention_days": 0}).json()
        assert "removed_count" in rep and rep["protected_imported"] >= 0

    def test_reopen_rejection_replay_http(self):
        """HTTP 全链路：损坏分块 → reopen 409（终局拒绝）→ 同键重放永远 409
        回放 → 修复后新 key+最新版本成功导入；旧 key 仍 409。"""
        pkg = make_pkg()
        m = pkg["manifest"]
        pid = m["package_id"]
        # 建会话（无窗口，负责人 alice）并乱序上传全部分块
        r = client.post("/api/snapshots/imports", json={
            "manifest": m, "owner": "alice"})
        assert r.status_code == 200
        for seq, b64 in reversed(list(enumerate(pkg["chunks"]))):
            rr = client.put(f"/api/snapshots/imports/{pid}/chunks/{seq}",
                            data={"data": b64, "actor": "alice"})
            assert rr.status_code == 200
        # 人工冻结（version 1 → 2）
        assert client.post(f"/api/snapshots/imports/{pid}/freeze",
                           json={"request_key": "f1", "version": 1,
                                 "actor": "alice"}).status_code == 200
        # 直接损坏磁盘上的分块 1
        with tx() as conn:
            conn.execute(
                "UPDATE snapshot_chunk SET content=?,sha256=? "
                "WHERE package_id=? AND seq=1",
                (b"DISK-CORRUPTED", ss.sha256_hex(b"DISK-CORRUPTED"), pid))

        body = {"request_key": "ro-bad", "version": 2, "actor": "alice",
                "ttl_minutes": 30}
        # 首次重开 → 409 REOPEN_MISMATCH（可定位）
        r1 = client.post(f"/api/snapshots/imports/{pid}/reopen", json=body)
        assert r1.status_code == 409
        d1 = r1.json()["detail"]
        assert d1["code"] == "REOPEN_MISMATCH"
        assert any(c.get("id") == 1 and c["code"] == "CHUNK_HASH_MISMATCH"
                   for c in d1["conflicts"])
        # 连续点击 × 3（同键重放）→ 全部回放首次拒绝：409 + replayed=true，
        # 失配明细与首次完全一致
        for _ in range(3):
            rr = client.post(f"/api/snapshots/imports/{pid}/reopen", json=body)
            assert rr.status_code == 409
            dd = rr.json()["detail"]
            assert dd["replayed"] is True
            assert dd["code"] == "REOPEN_MISMATCH"
            assert [c["code"] for c in dd["conflicts"]] == \
                   [c["code"] for c in d1["conflicts"]]
        # 审计只记一次 REOPEN_REJECTED
        evs = client.get(f"/api/snapshots/imports/{pid}/events").json()
        assert [e["action"] for e in evs].count("REOPEN_REJECTED") == 1

        # 后台修复分块后，旧 key 仍回放首次拒绝（即便带新版本号）
        with tx() as conn:
            raw = ss._b64decode(pkg["chunks"][1])
            conn.execute(
                "UPDATE snapshot_chunk SET content=?,sha256=? "
                "WHERE package_id=? AND seq=1",
                (raw, ss.sha256_hex(raw), pid))
        rr = client.post(f"/api/snapshots/imports/{pid}/reopen",
                         json={**body, "version": 99})
        assert rr.status_code == 409
        assert rr.json()["detail"]["replayed"] is True

        # 新 key 但过期版本号 → 409 VERSION_CONFLICT
        rr = client.post(f"/api/snapshots/imports/{pid}/reopen",
                         json={"request_key": "ro-new", "version": 1,
                               "actor": "alice", "ttl_minutes": 30})
        assert rr.status_code == 409
        assert rr.json()["detail"]["code"] == "VERSION_CONFLICT"

        # 新 key + 最新版本号（仍为 2）→ 200 重验通过、解冻
        rr = client.post(f"/api/snapshots/imports/{pid}/reopen",
                         json={"request_key": "ro-ok", "version": 2,
                               "actor": "alice", "ttl_minutes": 30})
        assert rr.status_code == 200, rr.text
        assert rr.json()["status"] == "READY" and rr.json()["version"] == 3
        # 终检导入成功
        rf = client.post(f"/api/snapshots/imports/{pid}/finalize",
                         json={"actor": "alice"})
        assert rf.status_code == 200 and rf.json()["status"] == "IMPORTED"
        # 已导入：新 key 重开 → 409 SESSION_IMPORTED；旧被拒 key → 回放 409
        rr = client.post(f"/api/snapshots/imports/{pid}/reopen",
                         json={"request_key": "ro-late", "version": 3,
                               "actor": "alice", "ttl_minutes": 30})
        assert rr.status_code == 409
        assert rr.json()["detail"]["code"] == "SESSION_IMPORTED"
        rr = client.post(f"/api/snapshots/imports/{pid}/reopen", json=body)
        assert rr.status_code == 409
        assert rr.json()["detail"]["code"] == "REOPEN_MISMATCH"

    def test_imported_session_management_409_http(self):
        pkg = make_pkg()
        m = pkg["manifest"]
        client.post("/api/snapshots/imports", json={"manifest": m})
        for seq in reversed(range(m["chunk_count"])):
            client.put(f"/api/snapshots/imports/{m['package_id']}/chunks/{seq}",
                       data={"data": pkg["chunks"][seq]})
        f = client.post(f"/api/snapshots/imports/{m['package_id']}/finalize",
                        json={}).json()
        assert f["status"] == "IMPORTED"
        for path, body in (
                ("handover", {"new_owner": "x", "request_key": "k", "version": 1}),
                ("renew", {"ttl_minutes": 1, "request_key": "k", "version": 1}),
                ("freeze", {"request_key": "k", "version": 1}),
                ("reopen", {"request_key": "k", "version": 1, "ttl_minutes": 1})):
            r = client.post(f"/api/snapshots/imports/{m['package_id']}/{path}",
                            json=body)
            assert r.status_code == 409, (path, r.text)
            assert r.json()["detail"]["code"] == "SESSION_IMPORTED"
