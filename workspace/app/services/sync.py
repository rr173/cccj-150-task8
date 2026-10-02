"""离线同步与提交服务。

流程
----
1. create_job / bundle：设备获取宗地现状、基线版本，生成作业单；
2. 离线采集（设备端），照片单独 upload_media；
3. submit：幂等提交 → 校验 → 对比基线 → 提交时再次比对库内当前版本：
   - 无并发改动 → 直接落新版本（COMMITTED）；
   - 与另一组测量同时改了同一折片段且几何不一致 → **不覆盖**，
     双方候选都保留并形成带差异几何的 dispute，作业单状态 DISPUTED；
   - 仅对方改动而己方未动该片段 → 自动变基（rebase）；
   - 基线过期且冲突片段双方差异不同 → DISPUTED。
"""
from __future__ import annotations

import json

from .. import geo, config
from ..db import get_conn
from . import ids
from .ids import now_iso, as_of
from . import versions as vs
from . import validation as val


# ================================================================ 离线作业单
def _job_blob(conn, parcel_ids):
    parcels, basis = [], {}
    for pid in parcel_ids:
        if pid is None:
            continue
        pv = vs.current_version(conn, pid)
        if not pv:
            continue
        basis[pid] = pv["id"]
        p = conn.execute("SELECT id,label FROM parcel WHERE id=?", (pid,)).fetchone()
        parcels.append({
            "parcel_id": pid,
            "label": p["label"] if p else pid,
            "version_id": pv["id"],
            "ring": pv["ring"],
            "area": pv["area"],
            "point_ids": vs.version_point_ids(conn, pv["id"]),
        })
    neighbors = [
        {"parcel_id": v["parcel_id"], "ring": v["ring"], "area": v["area"]}
        for v in vs.all_current(conn)
        if v["parcel_id"] not in set(filter(None, parcel_ids))
    ]
    return {
        "tolerance": {
            "closure_m": config.CLOSURE_TOL_M,
            "snap_m": config.POINT_SNAP_TOL_M,
            "shared_search_m": config.SHARED_SEARCH_TOL_M,
            "shared_consist_m": config.SHARED_CONSIST_TOL_M,
            "area_ratio": config.AREA_TOL_RATIO,
        },
        "basis": basis,
        "parcels": parcels,
        "neighbors": neighbors,
        "downloaded_at": now_iso(),
    }


def create_job(conn, *, device_id, surveyor, parcel_ids) -> dict:
    jid = ids.new_id("JOB")
    ts = now_iso()
    blob = _job_blob(conn, parcel_ids)
    conn.execute(
        """INSERT INTO survey_job
           (id,device_id,surveyor,status,base_version_map,base_parcel_ids,created_at)
           VALUES(?,?,?,?,?,?,?)""",
        (jid, device_id, surveyor, "OPEN",
         json.dumps(blob["basis"]), json.dumps(parcel_ids), ts))
    return {"job_id": jid, "created_at": ts, "bundle": blob}


def get_job(conn, job_id) -> dict | None:
    row = conn.execute("SELECT * FROM survey_job WHERE id=?", (job_id,)).fetchone()
    if not row:
        return None
    d = dict(row)
    d["base_version_map"] = json.loads(d["base_version_map"])
    d["base_parcel_ids"] = json.loads(d["base_parcel_ids"])
    d["payload"] = json.loads(d["payload"]) if d["payload"] else None
    d["error_json"] = json.loads(d["error_json"]) if d["error_json"] else None
    d["candidates"] = [dict(r) for r in conn.execute(
        "SELECT id,parcel_id,label,ring_json,declared_area,status FROM candidate WHERE job_id=?",
        (job_id,))]
    return d


# ================================================================ 照片
def save_media(conn, *, job_id, filename, raw: bytes, mime, point_ref=None) -> str:
    mid = ids.new_id("MED")
    safe = f"{mid}_{filename.split('/')[-1]}"
    path = config.MEDIA_DIR / safe
    path.write_bytes(raw)
    conn.execute(
        """INSERT INTO media(id,job_id,point_ref,filename,mime,size,created_at)
           VALUES(?,?,?,?,?,?,?)""",
        (mid, job_id, point_ref, safe, mime, len(raw), now_iso()))
    return mid


# ================================================================ 提交
def _store_candidate(conn, job_id, n: dict, ts) -> str:
    cid = ids.new_id("CAND")
    conn.execute(
        """INSERT INTO candidate
           (id,job_id,parcel_id,label,ring_json,points_json,declared_area,status,created_at)
           VALUES(?,?,?,?,?,?,?,?,?)""",
        (cid, job_id, n["parcel_id"], n["label"],
         json.dumps(n["ring"]), json.dumps(n["points"]),
         n["declared_area"], "PENDING", ts))
    return cid


def _store_confirmations(conn, job_id, confirmations):
    for cf in confirmations:
        conn.execute(
            """INSERT INTO owner_confirmation
               (job_id,parcel_id,owner_name,owner_id_no,segment_desc,confirmed,confirmed_at)
               VALUES(?,?,?,?,?,?,?)""",
            (job_id, cf.get("parcel_id"), cf["owner_name"], cf.get("owner_id_no"),
             cf.get("segment_desc"), 1 if cf.get("confirmed", True) else 0,
             now_iso() if cf.get("confirmed", True) else None))


def _open_disputes_for_edge(conn, parcel_a, parcel_b):
    rows = conn.execute(
        """SELECT d.* FROM dispute d
           WHERE d.status='OPEN'
             AND ((d.parcel_a=? AND d.parcel_b=?) OR (d.parcel_a=? AND d.parcel_b=?))""",
        (parcel_a, parcel_b, parcel_b, parcel_a)).fetchall()
    return [dict(r) for r in rows]


def _diff_against_bases(conn, normals, base_map):
    """逐宗地计算 基线环→候选环 的变化片段。"""
    diffs = {}
    for n in normals:
        pid = n["parcel_id"]
        base_vid = base_map.get(pid) if base_map else None
        if not pid or not base_vid:
            diffs[id(n)] = None  # 新宗地
            continue
        base = vs.get_version(conn, base_vid)
        if not base:
            diffs[id(n)] = None
            continue
        frags = geo.diff_fragments(base["ring"], n["ring"])
        diffs[id(n)] = {
            "base_version": base,
            "fragments": frags,
            "changed": geo.changed_fragment_keys(frags),
        }
    return diffs


def submit(conn, payload: dict) -> dict:
    """payload = SubmissionIn.model_dump()"""
    ts = as_of(payload.get("as_of"))
    idem = payload.get("idem_key")
    if idem:
        row = conn.execute("SELECT response_json FROM idempotency WHERE idem_key=?",
                           (idem,)).fetchone()
        if row:
            return json.loads(row["response_json"])

    device_id = payload.get("device_id", "device-1")
    raw_cands = payload["candidates"]
    confirmations = payload.get("confirmations") or []

    # 取/建作业单
    jid = payload.get("job_id")
    if jid:
        job = get_job(conn, jid)
        if not job:
            raise ValueError(f"作业单不存在: {jid}")
        base_map = job["base_version_map"]
    else:
        parcel_ids = [c.get("parcel_id") for c in raw_cands]
        job = create_job(conn, device_id=device_id,
                         surveyor=payload.get("surveyor"), parcel_ids=parcel_ids)
        jid = job["job_id"]
        base_map = job["bundle"]["basis"]
    # 请求可显式覆盖基线（设备 bundle 中的 basis）
    if payload.get("base_version_map"):
        base_map = {k: v for k, v in payload["base_version_map"].items() if v}

    _store_confirmations(conn, jid, confirmations)

    # 0) 先规范化；若携带相邻权利人确认，则把共享链变化传播为邻宗候选，
    #    随后对"完整候选集"统一校验（成对一致 → 不报重叠/共享边错误）
    pre_normals = [val.normalize_candidate(c) for c in raw_cands]
    confirmed_neighbors = {cf.get("parcel_id")
                           for cf in confirmations
                           if cf.get("confirmed") and cf.get("parcel_id")}
    pre_normals = _propagate_confirmed_edges(conn, pre_normals,
                                             confirmed_neighbors, ts)
    effective_raw = [{"parcel_id": n["parcel_id"], "label": n["label"],
                      "ring": n["ring"], "points": list(n.get("points", {}).values()),
                      "declared_area": n.get("declared_area")}
                     for n in pre_normals]
    # 1) 几何校验（含传播生成的邻宗候选；确认过的邻宗不再判 UNCONFIRMED）
    errors, normals = val.validate_submission(conn, effective_raw, confirmations, base_map)

    if errors:
        for n in normals:
            cid = _store_candidate(conn, jid, n, ts)
            conn.execute("UPDATE candidate SET status='REJECTED' WHERE id=?", (cid,))
        conn.execute(
            "UPDATE survey_job SET status='REJECTED', payload=?, error_json=?, submitted_at=? WHERE id=?",
            (json.dumps(payload), json.dumps(errors), ts, jid))
        resp = {"job_id": jid, "status": "REJECTED", "accepted": [],
                "disputes": [], "errors": errors}
        _idem(conn, idem, resp, ts)
        return resp

    cid_map = {id(n): _store_candidate(conn, jid, n, ts) for n in normals}
    base_map = {**base_map,
                **{n["parcel_id"]: (vs.current_version(conn, n["parcel_id"]) or {}).get("id")
                   for n in normals if n.get("_propagated_from")}}

    # 3) 按**共享边**检测并发分歧（不按最后提交者覆盖）
    base_diffs = _diff_against_bases(conn, normals, base_map)
    cur_by_pid = {n["parcel_id"]: vs.current_version(conn, n["parcel_id"])
                  for n in normals if n["parcel_id"]}
    new_disputes: list[dict] = []
    seen_edges: set[str] = set()
    disputed_cand: set[str] = set()

    for n in normals:
        pid = n["parcel_id"]
        cid = cid_map[id(n)]
        bd = base_diffs.get(id(n))
        cur = cur_by_pid.get(pid)
        if not bd or not cur:
            continue
        if cur["id"] == bd["base_version"]["id"]:
            continue  # 基线仍是最新，无并发
        cur_frags = geo.diff_fragments(bd["base_version"]["ring"], cur["ring"])
        other_changed = geo.changed_fragment_keys(cur_frags)
        for f in bd["fragments"]:
            if f["anchor_start"] is None:
                continue
            key = geo.anchor_key(f["anchor_start"], f["anchor_end"])
            if key not in other_changed:
                continue  # 对方未动这段
            of = next((x for x in cur_frags
                       if geo.anchor_key(x["anchor_start"], x["anchor_end"]) == key),
                      None)
            if not of:
                continue
            dev = geo.chain_deviation(f["new_chain"], of["new_chain"])
            if dev <= config.SHARED_CONSIST_TOL_M:
                continue  # 双方收敛
            nb_pid = _neighbor_parcel(conn, bd["base_version"], f)
            edge_id = _edge_id(pid, nb_pid, f)
            if edge_id in seen_edges:
                continue
            seen_edges.add(edge_id)
            other_job, other_cand = _origin_of_version(conn, cur["id"], cid, jid)
            disp = _create_dispute(
                conn, parcel_a=pid, parcel_b=nb_pid,
                job_a=jid, job_b=other_job or jid,
                cand_a=cid, cand_b=other_cand or cid,
                frag=f, other_chain=of["new_chain"], ts=ts,
                note={"deviation": round(dev, 3)})
            new_disputes.append(disp)
            disputed_cand.add(cid)
            if other_cand:
                disputed_cand.add(other_cand)

    # 4) 原子批次：出现任何争议 → 整作业挂起，候选全部保留不落版本
    if new_disputes:
        for cid in {cid_map[id(n)] for n in normals}:
            conn.execute(
                "UPDATE candidate SET status='IN_DISPUTE' WHERE id=? AND status='PENDING'",
                (cid,))
        conn.execute(
            "UPDATE survey_job SET status='DISPUTED', payload=?, submitted_at=? WHERE id=?",
            (json.dumps(payload), ts, jid))
        for d in new_disputes:
            for j in {d["job_a"], d["job_b"]}:
                conn.execute(
                    "UPDATE survey_job SET status='DISPUTED' WHERE id=? AND status IN ('OPEN','SUBMITTED')",
                    (j,))
        resp = {"job_id": jid, "status": "DISPUTED", "accepted": [],
                "disputes": [_dispute_brief(conn, d["id"]) for d in new_disputes],
                "errors": []}
    else:
        committed = _commit_clean(conn, normals, cid_map, base_diffs, set(),
                                  ts, payload.get("surveyor"), jid)
        conn.execute(
            "UPDATE survey_job SET status='COMMITTED', payload=?, submitted_at=?, committed_at=? WHERE id=?",
            (json.dumps(payload), ts, ts, jid))
        resp = {"job_id": jid, "status": "COMMITTED", "accepted": committed,
                "disputes": [], "errors": []}

    _idem(conn, idem, resp, ts)
    return resp


def _edge_id(pid_a, pid_b, frag):
    a, b = sorted((pid_a, pid_b))
    return f"{a}|{b}|" + geo.edge_key(frag["anchor_start"], frag["anchor_end"])


def _propagate_confirmed_edges(conn, normals, confirmed_neighbors, ts):
    """对"改了共享边且邻宗已确认"的候选，生成邻宗候选（仅替换对应片段，其余不动）。"""
    existing = {n["parcel_id"]: n for n in normals if n["parcel_id"]}
    extra = []
    for n in list(normals):
        if not n["parcel_id"]:
            continue
        cur = vs.current_version(conn, n["parcel_id"])
        if not cur:
            continue
        for frag in geo.diff_fragments(cur["ring"], n["ring"]):
            if frag["anchor_start"] is None:
                continue
            for nb in vs.all_current(conn):
                if nb["parcel_id"] in existing or nb["parcel_id"] not in confirmed_neighbors:
                    continue
                ring = nb["ring"]
                si = geo.find_vertex(ring, frag["anchor_start"], config.POINT_SNAP_TOL_M)
                ei = geo.find_vertex(ring, frag["anchor_end"], config.POINT_SNAP_TOL_M)
                if si is None or ei is None or si == ei:
                    continue
                # 两条候选路径，选与基线链贴合的一条
                p1 = geo._slice_ring_cyclic(ring, si, ei)
                p2 = geo._slice_ring_cyclic(ring, ei, si)
                d1, d2 = geo.path_pair_match(p1, p2, frag["base_chain"])
                if d1 <= d2:
                    ref = p1
                else:
                    ref = p2
                if geo.chain_deviation(ref, frag["base_chain"]) > config.SHARED_SEARCH_TOL_M:
                    continue
                new_ring = geo.replace_segment(
                    nb["ring"], ref[0], ref[-1], frag["new_chain"],
                    frag["base_chain"])
                nn = {
                    "parcel_id": nb["parcel_id"], "label": nb["parcel_id"],
                    "ring": new_ring, "area": geo.ring_area(new_ring),
                    "declared_area": None, "points": {},
                    "owner": None, "owner_id_no": None,
                    "_propagated_from": n["parcel_id"],
                }
                existing[nb["parcel_id"]] = nn
                extra.append(nn)
    return normals + extra


def _idem(conn, key, resp, ts):
    if not key:
        return
    conn.execute(
        "INSERT OR REPLACE INTO idempotency(idem_key,response_json,created_at) VALUES(?,?,?)",
        (key, json.dumps(resp), ts))


def _origin_of_version(conn, version_id, exclude_cand, exclude_job):
    """追踪版本由哪个 candidate/job 产生（parcel_op.job_id）。"""
    row = conn.execute(
        "SELECT job_id FROM parcel_op WHERE ? IN "
        "(SELECT value FROM json_each(child_versions)) AND job_id IS NOT NULL LIMIT 1",
        (version_id,)).fetchone()
    if row and row["job_id"] != exclude_job:
        c = conn.execute(
            "SELECT id FROM candidate WHERE job_id=? ORDER BY created_at LIMIT 1",
            (row["job_id"],)).fetchone()
        return row["job_id"], c["id"] if c else None
    # 退化：找最近非本作业的 IN_DISPUTE/ACCEPTED 候选
    c = conn.execute(
        """SELECT id,job_id FROM candidate
           WHERE status IN ('ACCEPTED','IN_DISPUTE') AND job_id!=?
           ORDER BY created_at DESC LIMIT 1""", (exclude_job,)).fetchone()
    return (c["job_id"], c["id"]) if c else (None, None)


def _neighbor_parcel(conn, cur_version, frag):
    """争议片段外的相邻宗地：环上同时含两个锚点的另一宗地。"""
    s, e = frag["anchor_start"], frag["anchor_end"]
    for pv in vs.all_current(conn):
        if pv["parcel_id"] == cur_version["parcel_id"]:
            continue
        if geo.find_vertex(pv["ring"], s, config.POINT_SNAP_TOL_M) is not None and \
           geo.find_vertex(pv["ring"], e, config.POINT_SNAP_TOL_M) is not None:
            return pv["parcel_id"]
    return cur_version["parcel_id"] + ":NEIGHBOR"


def _create_dispute(conn, *, parcel_a, parcel_b, job_a, job_b, cand_a, cand_b,
                    frag, other_chain, ts, note):
    did = ids.new_id("DISP")
    conn.execute(
        """INSERT INTO dispute
           (id,parcel_a,parcel_b,job_a,job_b,cand_a,cand_b,base_chain_json,
            geom_a_json,geom_b_json,anchor_start,anchor_end,status,created_at)
           VALUES(?,?,?,?,?,?,?,?,?,?,?,?,'OPEN',?)""",
        (did, parcel_a, parcel_b, job_a, job_b, cand_a, cand_b,
         json.dumps(frag["base_chain"]),
         json.dumps(frag["new_chain"]), json.dumps(other_chain),
         json.dumps(frag["anchor_start"]), json.dumps(frag["anchor_end"]), ts))
    return {"id": did, "job_a": job_a, "job_b": job_b,
            "parcel_a": parcel_a, "parcel_b": parcel_b, "note": note,
            "_frag": frag, "_other": other_chain}


def _dispute_brief(conn, did):
    r = conn.execute("SELECT * FROM dispute WHERE id=?", (did,)).fetchone()
    return {
        "id": r["id"], "parcel_a": r["parcel_a"], "parcel_b": r["parcel_b"],
        "job_a": r["job_a"], "job_b": r["job_b"], "status": r["status"],
        "anchor_start": json.loads(r["anchor_start"]) if r["anchor_start"].startswith("[") else r["anchor_start"],
        "anchor_end": json.loads(r["anchor_end"]) if r["anchor_end"].startswith("[") else r["anchor_end"],
        "base_chain": json.loads(r["base_chain_json"]),
        "geom_a": json.loads(r["geom_a_json"]),
        "geom_b": json.loads(r["geom_b_json"]),
    }


def list_open_disputes(conn):
    return [_dispute_brief(conn, r["id"]) for r in conn.execute(
        "SELECT id FROM dispute WHERE status='OPEN' ORDER BY created_at")]


def get_dispute(conn, did):
    r = conn.execute("SELECT * FROM dispute WHERE id=?", (did,)).fetchone()
    if not r:
        return None
    d = dict(r)
    for k in ("base_chain_json", "geom_a_json", "geom_b_json", "decided_chain_json",
              "result_versions"):
        d[k.replace("_json", "").replace("_versions", "_versions")] = \
            json.loads(d[k]) if d[k] else None
    return d


# ================================================================ 落版本
def _commit_one(conn, n, base_vid, ts, surveyor, jid, op_type="SURVEY",
                parent_versions=None, extra_params=None):
    pid = vs.ensure_parcel(conn, n["parcel_id"], n["label"], ts)
    pids = vs.register_ring(conn, n["ring"], n.get("points"), ts)
    parents = parent_versions if parent_versions is not None else \
        ([base_vid] if base_vid else [])
    parent_hashes = [h for h in (vs._hash_of(conn, p) for p in parents) if h]
    v = vs.create_version(
        conn, parcel_id=pid, ring=n["ring"], area=n["area"],
        status="COMMITTED", ts=ts, base_version_id=base_vid,
        parent_hashes=parent_hashes, declared_area=n.get("declared_area"))
    vs.link_version_points(conn, v["id"], pids)
    opid = ids.new_id("OP")
    conn.execute(
        """INSERT INTO parcel_op(id,type,parent_versions,child_versions,params_json,
           job_id,area_note,created_at) VALUES(?,?,?,?,?,?,?,?)""",
        (opid, op_type, json.dumps(parents), json.dumps([v["id"]]),
         json.dumps({"label": n.get("label"), "surveyor": surveyor,
                     **(extra_params or {})}),
         jid, json.dumps({"area": v["area"],
                          "declared": n.get("declared_area")}), ts))
    return v


def _commit_clean(conn, normals, cid_map, base_diffs, disputed_pids,
                  ts, surveyor, jid):
    """无争议候选落库（跳过争议宗地；新宗地建宗）。"""
    out = []
    for n in normals:
        cid = cid_map.get(id(n))
        if n["parcel_id"] in disputed_pids:
            continue
        bd = base_diffs.get(id(n))
        base_vid = bd["base_version"]["id"] if bd else None
        params = {"propagated_from": n.get("_propagated_from")} if n.get("_propagated_from") else None
        v = _commit_one(conn, n, base_vid, ts, surveyor, jid, extra_params=params)
        conn.execute("UPDATE candidate SET status='ACCEPTED', parcel_id=? WHERE id=?",
                     (v["parcel_id"], cid))
        out.append({"candidate_id": cid, "parcel_id": v["parcel_id"],
                    "version_id": v["id"], "version_no": v["version_no"],
                    "area": v["area"],
                    "propagated_from": n.get("_propagated_from")})
    return out
