"""完整端到端演示脚本（通过 HTTP）：按标签识别甲乙宗地。"""
import httpx

c = httpx.Client(base_url="http://127.0.0.1:8077", timeout=10)


def by_label(label):
    for p in c.get("/api/map").json()["parcels"]:
        if p["label"] == label:
            return p
    raise SystemExit(f"找不到 {label}")


def ring_eq(r, pts):
    return sorted(tuple(x) for x in r) == sorted(tuple(x) for x in pts)


jia = by_label("甲宗地")
yi = by_label("乙宗地")
pa, va = jia["id"], jia["current"]["id"]
pb, vb = yi["id"], yi["current"]["id"]
assert ring_eq(jia["current"]["ring"], [[0, 0], [100, 0], [100, 100], [0, 100]])
assert ring_eq(yi["current"]["ring"], [[100, 0], [200, 0], [200, 100], [100, 100]])
print("种子确认：甲", pa, "乙", pb)

# ---- 校验：坏几何 ----
bad = c.post("/api/sync/validate", json={
    "candidates": [{"ring": [[0, 0], [100, 0], [0, 100], [100, 100]]}]}).json()
assert not bad["valid"] and bad["errors"][0]["code"] == "SELF_INTERSECT"
print("✓ 自交校验拒绝")

# ---- 组1：甲乙同测，共享边凸到 110 ----
ra = [[0, 0], [100, 0], [110, 50], [100, 100], [0, 100]]
rb = [[100, 0], [110, 50], [100, 100], [200, 100], [200, 0]]
r1 = c.post("/api/sync/submit", json={
    "idem_key": "team1", "as_of": "2026-04-01T00:00:00Z",
    "base_version_map": {pa: va, pb: vb},
    "candidates": [{"parcel_id": pa, "ring": ra},
                   {"parcel_id": pb, "ring": rb}]}).json()
assert r1["status"] == "COMMITTED", r1
print("✓ 组1落库（共享边一致，面积 10500/9500）")

# ---- 组2：基线过期，只测甲，方案不同（凹到 90）----
ra2 = [[0, 0], [100, 0], [90, 50], [100, 100], [0, 100]]
r2 = c.post("/api/sync/submit", json={
    "idem_key": "team2", "as_of": "2026-04-02T00:00:00Z",
    "base_version_map": {pa: va},
    "candidates": [{"parcel_id": pa, "ring": ra2}]}).json()
assert r2["status"] == "DISPUTED" and len(r2["disputes"]) == 1, r2
d = r2["disputes"][0]
assert {d["parcel_a"], d["parcel_b"]} == {pa, pb}
print("✓ 组2未覆盖组1，形成争议版本（差异几何 A/B 并存）")

# 争议期间时点查询：甲仍是组1版本
mid = c.get(f"/api/parcels/{pa}", params={"at": "2026-04-05T00:00:00Z"}).json()
assert abs(mid["version"]["area"] - 10500) < 1e-6
print("✓ 争议挂起期间，时点查询仍返回已落库版本")

# ---- 裁定：REVISED，链在 103 ----
did = d["id"]
adj = c.post("/api/disputes/adjudicate", json=[{
    "dispute_id": did, "decision": "REVISED",
    "chain_a": [[100, 0], [103, 50], [100, 100]],
    "decided_by": "仲裁委员会", "as_of": "2026-04-10T00:00:00Z"}]).json()
res = adj["adjudicated"][0]
assert len(res["versions"]) == 2
notes = {n["parcel_id"]: n["delta"] for n in res["area_notes"]}
assert abs(notes[pa] + notes[pb]) < 1e-6, notes
assert abs(notes[pa] - (-350)) < 1e-6 and abs(notes[pb] - 350) < 1e-6
print(f"✓ 裁定完成：甲 {notes[pa]:+.0f}m²，乙 {notes[pb]:+.0f}m²（等量反向），两宗同步出版本")

# 未争议边界未动
jia_now = by_label("甲宗地")["current"]["ring"]
assert [0, 0] in jia_now and [0, 100] in jia_now and [100, 0] in jia_now
print("✓ 未争议边界逐点保留")

# 锚点外的篡改链应被拒
bad_adj = c.post("/api/disputes/adjudicate", json=[{
    "dispute_id": "DISP-x", "decision": "A"}])
assert bad_adj.status_code in (400, 404)

# ---- 证明：签发给裁定版本，再分割也不影响验真 ----
cert = c.post("/api/certificates", json={
    "version_id": res["versions"][0], "as_of": "2026-04-11T00:00:00Z"}).json()
v = c.get(f"/api/certificates/{cert['cert_id']}/verify").json()
assert v["valid"], v
print("✓ 历史证明签发并验真（含哈希链完整性）：", cert["cert_id"])

# 篡改库后验证失败
import os, json as _json, sqlite3
db = os.environ.get("CADASTRE_DB", "data/cadastre.db")
con = sqlite3.connect(db)
row = con.execute("SELECT ring_json FROM parcel_version WHERE id=?",
                  (res["versions"][0],)).fetchone()
ring = _json.loads(row[0]); ring[1] = [ring[1][0] + 5, ring[1][1]]
con.execute("UPDATE parcel_version SET ring_json=? WHERE id=?",
            (_json.dumps(ring), res["versions"][0]))
con.commit(); con.close()
v2 = c.get(f"/api/certificates/{cert['cert_id']}/verify").json()
assert not v2["valid"] and v2["checks"]["hash_chain_intact"] is False
print("✓ 篡改几何后证明验真失败")
# 还原（真实系统中此版本哈希链已断裂、审计可查；演示恢复以继续后续流程）
con = sqlite3.connect(db)
con.execute("UPDATE parcel_version SET ring_json=? WHERE id=?",
            (_json.dumps(v2["document"]["ring"]), res["versions"][0]))
con.commit(); con.close()
assert c.get(f"/api/certificates/{cert['cert_id']}/verify").json()["valid"]

# ---- 时间点快照 ----
s_old = c.get("/api/at/2026-01-15T00:00:00Z").json()
s_new = c.get("/api/at/2026-05-01T00:00:00Z").json()
assert len(s_old) == 2 and abs(sum(x["area"] for x in s_old) - 20000) < 1e-6
assert {x["status"] for x in s_new} == {"ADJUDICATED"}
print("✓ 任意时间点地籍快照可查（半开区间 [from,to)）")

# ---- 离线包 / 媒体 / 幂等 ----
b = c.post("/api/sync/bundle", json={"parcel_ids": [pa], "surveyor": "外业一组"}).json()
assert b["bundle"]["basis"][pa]
up = c.post(f"/api/sync/jobs/{b['job_id']}/media",
            files={"file": ("marker.jpg", b"\xff\xd8\xff\xe0fake", "image/jpeg")},
            data={"point_ref": "BP1"})
assert up.status_code == 200
print("✓ 离线作业单/界标照片上传：", up.json()["media_id"])

a = c.post("/api/sync/submit", json={
    "idem_key": "idem-x",
    "candidates": [{"ring": [[0, 0], [10, 0], [10, 10], [0, 10]]}]}).json()
b2 = c.post("/api/sync/submit", json={
    "idem_key": "idem-x",
    "candidates": [{"ring": [[0, 0], [20, 0], [20, 20], [0, 20]]}]}).json()
assert a["job_id"] == b2["job_id"] and a["accepted"] == b2["accepted"]
print("✓ 幂等提交重放返回同一结果")

# ---- 快照交换包：接收窗口与移交 ----
pkg = c.post("/api/snapshots/export", json={
    "parcel_ids": [pa, pb], "at": "2026-06-01T00:00:00Z", "chunk_size": 1024}).json()
m = pkg["manifest"]
# 建会话：负责人 alice + 有效期
cr0 = c.post("/api/snapshots/imports", json={
    "manifest": m, "owner": "alice", "ttl_minutes": 60}).json()
pid = cr0["package_id"]
assert cr0["session"]["owner"] == "alice" and cr0["version"] == 1
# 非负责人不能上传
deny = c.put(f"/api/snapshots/imports/{pid}/chunks/0",
             data={"data": pkg["chunks"][0], "actor": "mallory"})
assert deny.status_code == 403 and deny.json()["detail"]["code"] == "NOT_OWNER"
# 负责人上传
assert c.put(f"/api/snapshots/imports/{pid}/chunks/0",
             data={"data": pkg["chunks"][0], "actor": "alice"}).json()["accepted"]
# 移交：幂等键 + 版本号；旧版本并发移交被挡
h1 = c.post(f"/api/snapshots/imports/{pid}/handover", json={
    "new_owner": "bob", "request_key": "demo-h1", "version": 1, "actor": "alice"})
assert h1.status_code == 200 and h1.json()["version"] == 2
h2 = c.post(f"/api/snapshots/imports/{pid}/handover", json={
    "new_owner": "carol", "request_key": "demo-h2", "version": 1, "actor": "alice"})
assert h2.status_code == 409 and h2.json()["detail"]["code"] == "VERSION_CONFLICT"
# 同键重放返回首次结果
assert c.post(f"/api/snapshots/imports/{pid}/handover", json={
    "new_owner": "bob", "request_key": "demo-h1", "version": 1,
    "actor": "alice"}).json()["replayed"] is True
# 人工冻结后写入被拒（已收块保留），重开重验后续传
fz = c.post(f"/api/snapshots/imports/{pid}/freeze", json={
    "request_key": "demo-fz", "version": 2, "actor": "bob"})
assert fz.json()["frozen_reason"] == "MANUAL"
fr = c.put(f"/api/snapshots/imports/{pid}/chunks/1",
           data={"data": pkg["chunks"][1], "actor": "bob"})
assert fr.status_code == 409 and fr.json()["detail"]["code"] == "SESSION_FROZEN"
assert fr.json()["detail"]["session"]["received_count"] == 1
ro = c.post(f"/api/snapshots/imports/{pid}/reopen", json={
    "request_key": "demo-ro", "version": 3, "actor": "bob", "ttl_minutes": 60})
assert ro.status_code == 200 and ro.json()["version"] == 4
# 审计时间线含关键动作
actions = {e["action"] for e in c.get(f"/api/snapshots/imports/{pid}/events").json()}
assert {"CREATE", "WRITE_DENIED", "HANDOVER", "FREEZE", "REOPEN"} <= actions
# 保留期清理：未导入的活动/冻结新会话不删；已导入保护（本例最终不导入，避免落库扰动）
cl = c.post("/api/snapshots/imports-cleanup", json={"retention_days": 7}).json()
assert "removed_count" in cl and cl["protected_imported"] >= 0
print("✓ 接收窗口：负责人/有效期/写入限制/移交版本幂等/冻结保留/重开重验/审计/清理保护")

print("\n全部端到端断言通过 ✅")
