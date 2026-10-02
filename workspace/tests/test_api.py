"""HTTP API 集成测试（TestClient + 临时库）。"""
import importlib
import os
import tempfile

import pytest
from fastapi.testclient import TestClient

_tmp = tempfile.mkdtemp(prefix="cadastre-api-")
os.environ["CADASTRE_DB"] = os.path.join(_tmp, "api.db")

from app import main, db  # noqa: E402

client = TestClient(main.app)


@pytest.fixture(autouse=True)
def fresh_db():
    if os.path.exists(os.environ["CADASTRE_DB"]):
        os.remove(os.environ["CADASTRE_DB"])
    db.init_db()
    yield


def _new(ring, label):
    return client.post("/api/sync/submit", json={
        "device_id": "d1", "surveyor": "张三",
        "candidates": [{"parcel_id": None, "label": label, "ring": ring}]})


def test_health_and_flow():
    assert client.get("/api/health").json()["ok"] is True

    # 新宗
    r = _new([[0, 0], [100, 0], [100, 100], [0, 100]], "甲")
    assert r.status_code == 200 and r.json()["status"] == "COMMITTED"
    pa = r.json()["accepted"][0]["parcel_id"]

    # 坏几何被拒
    r = _new([[0, 0], [100, 0], [0, 100], [100, 100]], "坏")
    assert r.json()["status"] == "REJECTED"
    assert any(e["code"] == "SELF_INTERSECT" for e in r.json()["errors"])

    # 地图数据
    mp = client.get("/api/map").json()
    assert len(mp["parcels"]) >= 1

    # 时间点查询：初始时刻无版本
    assert client.get(f"/api/parcels/{pa}", params={"at": "2000-01-01T00:00:00Z"}
                      ).status_code == 404

    # 版本列表
    vs = client.get(f"/api/parcels/{pa}/versions").json()
    assert len(vs) == 1
    vid = vs[0]["id"]

    # 签发并验证证明
    c = client.post("/api/certificates", json={"version_id": vid}).json()
    cid = c["cert_id"]
    v = client.get(f"/api/certificates/{cid}/verify").json()
    assert v["valid"] is True

    # bundle + 作业状态
    b = client.post("/api/sync/bundle",
                    json={"parcel_ids": [pa], "surveyor": "李四"}).json()
    jid = b["job_id"]
    assert b["bundle"]["parcels"][0]["ring"]
    st = client.get(f"/api/sync/jobs/{jid}").json()
    assert st["status"] == "OPEN"


def test_conflict_and_adjudication_api():
    r1 = _new([[0, 0], [100, 0], [100, 100], [0, 100]], "甲")
    pa = r1.json()["accepted"][0]["parcel_id"]
    va = r1.json()["accepted"][0]["version_id"]
    r2 = _new([[100, 0], [200, 0], [200, 100], [100, 100]], "乙")
    pb = r2.json()["accepted"][0]["parcel_id"]
    vb = r2.json()["accepted"][0]["version_id"]

    chain = [[100, 0], [110, 50], [100, 100]]
    ra = [[0, 0], [100, 0], [110, 50], [100, 100], [0, 100]]
    rb = [[100, 0], [110, 50], [100, 100], [200, 100], [200, 0]]
    t1 = client.post("/api/sync/submit", json={
        "idem_key": "g1", "as_of": "2026-04-01T00:00:00Z",
        "base_version_map": {pa: va, pb: vb},
        "candidates": [
            {"parcel_id": pa, "ring": ra},
            {"parcel_id": pb, "ring": rb}]}).json()
    assert t1["status"] == "COMMITTED"

    t2 = client.post("/api/sync/submit", json={
        "idem_key": "g2", "as_of": "2026-04-02T00:00:00Z",
        "base_version_map": {pa: va},
        "candidates": [{"parcel_id": pa,
                        "ring": [[0, 0], [100, 0], [90, 50], [100, 100], [0, 100]]}]}).json()
    assert t2["status"] == "DISPUTED"
    did = t2["disputes"][0]["id"]

    detail = client.get(f"/api/disputes/{did}").json()
    assert detail["candidate_a"]["ring"]
    assert detail["current_a"]

    adj = client.post("/api/disputes/adjudicate", json=[{
        "dispute_id": did, "decision": "B",
        "decided_by": "仲裁委", "as_of": "2026-04-10T00:00:00Z"}]).json()
    assert len(adj["adjudicated"][0]["versions"]) == 2
    # 再次裁定应 400
    again = client.post("/api/disputes/adjudicate",
                        json=[{"dispute_id": did, "decision": "A"}])
    assert again.status_code == 400


def test_split_merge_api():
    r = _new([[0, 0], [100, 0], [100, 100], [0, 100]], "甲")
    va = r.json()["accepted"][0]["version_id"]
    s = client.post("/api/ops/split", json={
        "parent_version_id": va, "note": "分割",
        "children": [
            {"ring": [[0, 0], [50, 0], [50, 100], [0, 100]]},
            {"ring": [[50, 0], [100, 0], [100, 100], [50, 100]]}]}).json()
    assert s["status"] == "COMMITTED"
    assert abs(s["area_note"]["delta"]) < 1e-6

    # 时间点：分割前仍是完整父宗
    snap = client.get("/api/at/2020-01-01T00:00:00Z").json()
    assert len(snap) == 0


def test_idempotency_api():
    a = client.post("/api/sync/submit", json={
        "idem_key": "same",
        "candidates": [{"ring": [[0, 0], [10, 0], [10, 10], [0, 10]]}]}).json()
    b = client.post("/api/sync/submit", json={
        "idem_key": "same",
        "candidates": [{"ring": [[0, 0], [20, 0], [20, 20], [0, 20]]}]}).json()
    assert a["job_id"] == b["job_id"]
    assert a["accepted"] == b["accepted"]


def test_correction_draft_two_phase_flow():
    """HTTP：建草案→预演不改变在版宗地→发布原子分叉→重放幂等→撤销。"""
    # 甲、乙两宗 + 分割甲
    r1 = client.post("/api/sync/submit", json={
        "candidates": [{"parcel_id": None, "label": "甲",
                        "ring": [[0, 0], [100, 0], [100, 100], [0, 100]]}]})
    pa = r1.json()["accepted"][0]["parcel_id"]
    va = r1.json()["accepted"][0]["version_id"]
    client.post("/api/sync/submit", json={
        "candidates": [{"parcel_id": None, "label": "乙",
                        "ring": [[100, 0], [200, 0], [200, 100], [100, 100]]}]})
    sp = client.post("/api/ops/split", json={
        "parent_version_id": va,
        "children": [{"ring": [[0, 0], [50, 0], [50, 100], [0, 100]]},
                     {"ring": [[50, 0], [100, 0], [100, 100], [50, 100]]}]})
    assert sp.json()["status"] == "COMMITTED"

    # 一个分割子宗的当前面积（用于确认草案阶段不改变在版宗地）
    child_pid = sp.json()["accepted"][0]["parcel_id"]
    current_before = client.get(
        f"/api/parcels/{child_pid}").json()["version"]["area"]

    # 1) 建草案 + 预演
    d = client.post("/api/correction-drafts", json={
        "version_id": va,
        "corrected": {"ring": [[0, -0.5], [100, -0.5], [100,100], [0, 100]]},
        "reason": "南界址解析错误"})
    assert d.status_code == 200
    body = d.json()
    did = body["draft_id"]
    assert body["releasable"] is True
    assert len(body["preview"]["nodes"]) == 3
    # 草案阶段在版宗地未改变
    assert client.get(f"/api/parcels/{child_pid}").json()["version"]["area"] == current_before

    # 2) 发布（原子、幂等）
    p = client.post(f"/api/correction-drafts/{did}/publish", json={})
    assert p.json()["status"] == "PUBLISHED"
    assert len(p.json()["new_versions"]) == 3
    p2 = client.post(f"/api/correction-drafts/{did}/publish", json={})
    assert p2.json()["new_versions"] == p.json()["new_versions"]

    # 3) 草案列表 / 地图接口含草案
    assert any(x["id"] == did for x in client.get("/api/correction-drafts").json())
    mp = client.get("/api/map").json()
    assert "correction_drafts" in mp

    # 4) 已发布不能撤销
    assert client.post(f"/api/correction-drafts/{did}/cancel").status_code == 400


def test_correction_draft_cancel_and_drift_http():
    r1 = client.post("/api/sync/submit", json={
        "candidates": [{"ring": [[0, 0], [100, 0], [100, 100], [0, 100]]}]})
    va = r1.json()["accepted"][0]["version_id"]
    # 撤销 OPEN 草案
    d = client.post("/api/correction-drafts", json={
        "version_id": va,
        "corrected": {"ring": [[0, -0.3], [100, -0.3], [100, 100], [0, 100]]}})
    did = d.json()["draft_id"]
    c = client.post(f"/api/correction-drafts/{did}/cancel")
    assert c.json()["status"] == "CANCELLED"
    assert client.post(f"/api/correction-drafts/{did}/publish", json={}).status_code == 400

    # 漂移：建草案后给宗地追加新版本，发布返回 DRIFTED
    d2 = client.post("/api/correction-drafts", json={
        "version_id": va,
        "corrected": {"ring": [[0, -0.5], [100, -0.5], [100, 100], [0, 100]]}})
    did2 = d2.json()["draft_id"]
    client.post("/api/ops/correction", json={
        "version_id": va,
        "corrected": {"ring": [[0, -0.1], [100, -0.1], [100, 100], [0, 100]]},
        "reason": "草案后的另一变更"})
    pub = client.post(f"/api/correction-drafts/{did2}/publish", json={})
    assert pub.json()["status"] == "DRIFTED"
    assert pub.json()["drift_nodes"]
    # 重新预演后草案回 OPEN
    client.post(f"/api/correction-drafts/{did2}/rehearse")
    g = client.get(f"/api/correction-drafts/{did2}").json()
    assert g["status"] in ("OPEN",)
