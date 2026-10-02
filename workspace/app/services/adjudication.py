"""争议裁定服务。

铁律
----
* 只能选择 A、选择 B，或给出 REVISED 修订链；
* 修订链端点必须固定在原争议片段的两个锚点上；
* 用服务端当前版本 + 替换片段的方式重建环，**未参与争议的边界逐点保持不动**
  （偏差超过 UNCHANGED_EDGE_TOL 即拒绝）。
"""
from __future__ import annotations

import json

from .. import geo, config
from . import ids
from .ids import as_of
from . import versions as vs
from . import validation as val


def _cand_ring(conn, cand_id):
    r = conn.execute("SELECT ring_json FROM candidate WHERE id=?",
                     (cand_id,)).fetchone()
    return geo.norm_ring(json.loads(r["ring_json"])) if r else None


def _dispute_row(conn, did):
    return conn.execute("SELECT * FROM dispute WHERE id=?", (did,)).fetchone()


def adjudicate(conn, items: list[dict]) -> dict:
    ts = as_of(items[0].get("as_of")) if items and items[0].get("as_of") else as_of(None)
    results, dids = [], []

    for item in items:
        did = item["dispute_id"]
        d = _dispute_row(conn, did)
        if not d:
            raise ValueError(f"争议不存在: {did}")
        if d["status"] != "OPEN":
            raise ValueError(f"争议 {did} 已裁定")
        decision = item["decision"]

        start = json.loads(d["anchor_start"])
        end = json.loads(d["anchor_end"])
        base_chain = json.loads(d["base_chain_json"])
        if decision == "A":
            chosen = json.loads(d["geom_a_json"])
        elif decision == "B":
            chosen = json.loads(d["geom_b_json"])
        else:
            raw = item.get("chain_a") or item.get("chain_b")
            if not raw or len(raw) < 2:
                raise ValueError("REVISED 必须提供修订折线 chain_a/chain_b")
            chosen = [geo.round_pt(p) for p in raw]

        # 锚点必须固定
        if geo._dist(chosen[0], start) > config.POINT_SNAP_TOL_M or \
           geo._dist(chosen[-1], end) > config.POINT_SNAP_TOL_M:
            raise ValueError("修订链端点必须固定在争议片段的两个锚点上")
        chosen[0], chosen[-1] = geo.round_pt(start), geo.round_pt(end)

        # 取双方候选环
        ring_a = _cand_ring(conn, d["cand_a"])
        ring_b = _cand_ring(conn, d["cand_b"])

        parcel_ids = [d["parcel_a"]]
        if d["parcel_b"] and not d["parcel_b"].endswith(":NEIGHBOR"):
            parcel_ids.append(d["parcel_b"])

        base_chain = json.loads(d["base_chain_json"])
        new_versions, area_notes = [], []
        new_rings: dict[str, list] = {}
        for pid in parcel_ids:
            cur = vs.current_version(conn, pid)
            if not cur:
                continue
            ring = cur["ring"]
            si = geo.find_vertex(ring, start, config.POINT_SNAP_TOL_M)
            ei = geo.find_vertex(ring, end, config.POINT_SNAP_TOL_M)
            if si is None or ei is None or si == ei:
                continue
            p1 = geo._slice_ring_cyclic(ring, si, ei)
            p2 = geo._slice_ring_cyclic(ring, ei, si)
            d1, d2 = geo.path_pair_match(p1, p2, base_chain)
            if d1 <= d2:
                segment, complement = p1, p2
            else:
                segment, complement = p2, p1

            before_area = cur["area"]
            new_ring = geo.replace_segment(ring, start, end, chosen, base_chain)

            # —— 强制校验 1：未争议补链逐点不动（补链可能方向相反，用无序偏差）——
            kept = geo.ring_chain_between(new_ring, complement[0], complement[-1],
                                          reference=complement)
            dev_keep = geo.chain_deviation(complement, kept)
            if dev_keep > config.UNCHANGED_EDGE_TOL_M:
                raise ValueError(
                    f"宗地 {pid} 未争议边界发生改动（偏差 {dev_keep:.3f}m），裁定被拒绝")

            # —— 强制校验 2：新环几何合法（闭合/自交/面积）——
            errs = val.validate_ring(new_ring)
            if errs:
                raise ValueError(f"宗地 {pid} 裁定后几何非法: {errs[0]['message']}")

            new_rings[pid] = new_ring
            area_notes.append({"parcel_id": pid, "before": before_area,
                               "after": geo.ring_area(new_ring),
                               "delta": round(geo.ring_area(new_ring) - before_area, 3)})

        # —— 强制校验 3：两宗地面积增减必须等量反向（面积关系守恒，仅共享边移动）——
        if len(area_notes) == 2:
            d1, d2 = area_notes[0]["delta"], area_notes[1]["delta"]
            if abs(d1 + d2) > config.SPLIT_MERGE_AREA_RATIO * \
                    max(area_notes[0]["before"], 1e-9):
                raise ValueError(
                    f"裁定破坏面积关系：两宗面积变化 {d1:+.3f}/{d2:+.3f} 非等量反向")

        # —— 校验两侧新环共享边一致：取有向片段（允许反向后重合）——
        pids = list(new_rings)
        if len(pids) == 2:
            r1, r2 = new_rings[pids[0]], new_rings[pids[1]]
            c1 = geo.ring_chain_between(r1, start, end, reference=base_chain)
            c2 = geo.ring_chain_between(r2, start, end, reference=base_chain)
            if geo.chain_deviation(c1, c2) > config.SHARED_CONSIST_TOL_M:
                raise ValueError("裁定后两宗共享边仍不一致")

        parent_version_ids: list[str] = []
        for pid, new_ring in new_rings.items():
            cur = vs.current_version(conn, pid)
            parent_version_ids.append(cur["id"])
            v = vs.create_version(conn, parcel_id=pid, ring=new_ring,
                                  area=geo.ring_area(new_ring),
                                  status="ADJUDICATED", ts=ts,
                                  base_version_id=cur["id"],
                                  parent_hashes=[vs._hash_of(conn, cur["id"])])
            vs.link_version_points(conn, v["id"],
                                   vs.register_ring(conn, new_ring, None, ts))
            new_versions.append(v["id"])

        opid = ids.new_id("OP")
        conn.execute(
            """INSERT INTO parcel_op
               (id,type,parent_versions,child_versions,params_json,job_id,
                dispute_id,area_note,created_at)
               VALUES(?,?,?,?,?,?,?,?,?)""",
            (opid, "ADJUDICATION", json.dumps(parent_version_ids), json.dumps(new_versions),
             json.dumps({"dispute_id": did, "decision": decision,
                         "decided_by": item.get("decided_by"),
                         "chain": chosen}),
             None, did,
             json.dumps({"area_conservation": area_notes}), ts))

        conn.execute(
            "UPDATE dispute SET status='RESOLVED', decision=?, decided_chain_json=?, "
            "decided_by=?, decided_at=?, result_versions=? WHERE id=?",
            (decision, json.dumps(chosen), item.get("decided_by"), ts,
             json.dumps(new_versions), did))
        # 关联候选置为已接受
        conn.execute("UPDATE candidate SET status='ACCEPTED' WHERE id IN (?,?)",
                     (d["cand_a"], d["cand_b"]))
        for j in {d["job_a"], d["job_b"]}:
            still_open = conn.execute(
                "SELECT COUNT(*) c FROM dispute WHERE status='OPEN' AND (job_a=? OR job_b=?)",
                (j, j)).fetchone()["c"]
            if not still_open:
                conn.execute(
                    "UPDATE survey_job SET status='COMMITTED', committed_at=? "
                    "WHERE id=? AND status='DISPUTED'", (ts, j))

        results.append({"dispute_id": did, "decision": decision,
                        "versions": new_versions, "area_notes": area_notes})
        dids.append(did)

    return {"adjudicated": results}
