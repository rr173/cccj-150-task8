"""分割 / 合并 / 历史更正：面积关系 + 版本血缘。

* SPLIT：子宗并集必须等于父宗（全等），面积和守恒；
* MERGE：结果必须与父宗并集全等，面积守恒；
* CORRECTION：更正错误登记；旧版本**保留可查**（ANNULLED），血缘指向被更正版本，
  已签发证明仍按版本哈希验签，不因更正而失效。
"""
from __future__ import annotations

import json

from shapely.geometry import Polygon

from .. import geo, config
from . import ids
from .ids import as_of
from . import versions as vs
from . import validation as val
from . import sync as sync_svc


def _rings_equal(r1, r2, tol=config.SHARED_SEARCH_TOL_M) -> tuple[bool, dict]:
    p1, p2 = geo.as_polygon(r1), geo.as_polygon(r2)
    if not p1.is_valid or not p2.is_valid:
        return False, {"reason": "invalid"}
    sym = p1.symmetric_difference(p2)
    area_diff = float(sym.area)
    hd = geo.chain_deviation(r1 + [r1[0]], r2 + [r2[0]]) if area_diff > 1e-6 else 0.0
    ratio = area_diff / max(p1.area, 1e-9)
    return ratio < 0.01 and hd < 1.0, {
        "symmetric_diff_area": round(area_diff, 4),
        "hausdorff_m": round(hd, 4)}


def split(conn, payload: dict) -> dict:
    ts = as_of(payload.get("as_of"))
    parent = vs.get_version(conn, payload["parent_version_id"])
    if not parent:
        raise ValueError("父版本不存在")

    raw_children = payload["children"]
    errors, normals = val.validate_submission(
        conn, raw_children, [], None,
        exclude_parcels={parent["parcel_id"]})
    # 子宗间不得重叠（校验器已覆盖）
    hard = [e for e in errors if e["code"] != "SHARED_NEIGHBOR_UNCONFIRMED"]
    if hard:
        return {"status": "REJECTED", "errors": hard, "accepted": []}

    child_rings = [n["ring"] for n in normals]
    union, sum_area = geo.polygon_union(child_rings)
    area_note = {
        "parent_area": parent["area"],
        "children_sum": round(sum(n["area"] for n in normals), 6),
        "delta": round(sum(n["area"] for n in normals) - parent["area"], 6),
    }
    ratio = abs(area_note["delta"]) / max(parent["area"], 1e-9)
    if ratio > config.SPLIT_MERGE_AREA_RATIO:
        return {"status": "REJECTED", "accepted": [],
                "errors": [{"code": "AREA_RELATION_BROKEN",
                            "message": f"分割面积不守恒：偏差 {ratio:.3%} > "
                                       f"{config.SPLIT_MERGE_AREA_RATIO:.2%}",
                            "detail": area_note}]}

    equal, eq_note = _rings_equal(parent["ring"], geo.norm_ring(list(union.exterior.coords[:-1])))
    area_note["geometry_equals_parent"] = equal
    area_note["geometry_check"] = eq_note
    if not equal:
        return {"status": "REJECTED", "accepted": [],
                "errors": [{"code": "GEOMETRY_RELATION_BROKEN",
                            "message": "子宗并集与父宗地边界不一致",
                            "detail": eq_note}]}

    # 落库：每个子宗一个新宗地，血缘指向同一父版本
    child_versions = []
    accepted = []
    for n in normals:
        v = sync_svc._commit_one(
            conn, n, None, ts, payload.get("note"), None,
            op_type="SPLIT", parent_versions=[parent["id"]],
            extra_params={"split_of": parent["id"], "area_note": area_note})
        child_versions.append(v["id"])
        accepted.append({"parcel_id": v["parcel_id"], "version_id": v["id"],
                         "area": v["area"]})

    # 记录汇总操作（父版本保持不可变，仅关闭其当前效力）
    conn.execute("UPDATE parcel_version SET valid_to=?, status='SUPERSEDED' WHERE id=? AND valid_to IS NULL",
                 (ts, parent["id"]))
    opid = ids.new_id("OP")
    conn.execute(
        """INSERT INTO parcel_op(id,type,parent_versions,child_versions,params_json,
           job_id,area_note,created_at) VALUES(?,?,?,?,?,?,?,?)""",
        (opid, "SPLIT", json.dumps([parent["id"]]),
         json.dumps(child_versions),
         json.dumps({"note": payload.get("note")}), None,
         json.dumps(area_note), ts))
    return {"status": "COMMITTED", "accepted": accepted, "area_note": area_note}


def merge(conn, payload: dict) -> dict:
    ts = as_of(payload.get("as_of"))
    parents = [vs.get_version(conn, vid) for vid in payload["parent_version_ids"]]
    if any(p is None for p in parents):
        raise ValueError("存在不存在的父版本")

    errors, normals = val.validate_submission(
        conn, [payload["result"].model_dump() if hasattr(payload["result"], "model_dump")
               else payload["result"]], [], None,
        exclude_parcels={p["parcel_id"] for p in parents})
    hard = [e for e in errors if e["code"] != "SHARED_NEIGHBOR_UNCONFIRMED"]
    if hard:
        return {"status": "REJECTED", "errors": hard, "accepted": []}
    res = normals[0]

    union, sum_area = geo.polygon_union([p["ring"] for p in parents])
    area_note = {
        "parents_sum": round(sum(p["area"] for p in parents), 6),
        "result_area": res["area"],
        "delta": round(res["area"] - sum(p["area"] for p in parents), 6),
    }
    ratio = abs(area_note["delta"]) / max(sum(p["area"] for p in parents), 1e-9)
    if ratio > config.SPLIT_MERGE_AREA_RATIO:
        return {"status": "REJECTED", "accepted": [],
                "errors": [{"code": "AREA_RELATION_BROKEN",
                            "message": f"合并面积不守恒：偏差 {ratio:.3%}",
                            "detail": area_note}]}
    equal, eq_note = _rings_equal(
        geo.norm_ring(list(union.exterior.coords[:-1])), res["ring"])
    area_note["geometry_equals_union"] = equal
    area_note["geometry_check"] = eq_note
    if not equal:
        return {"status": "REJECTED", "accepted": [],
                "errors": [{"code": "GEOMETRY_RELATION_BROKEN",
                            "message": "合并结果与父宗并集边界不一致",
                            "detail": eq_note}]}

    # 父宗地关闭（但不删除），结果落到第一个父宗地号上（演示约定）
    target_pid = parents[0]["parcel_id"]
    res["parcel_id"] = target_pid
    res["label"] = target_pid
    v = sync_svc._commit_one(
        conn, res, parents[0]["id"], ts, payload.get("note"), None,
        op_type="MERGE", parent_versions=[p["id"] for p in parents],
        extra_params={"merged": [p["id"] for p in parents], "area_note": area_note})
    for p in parents[1:]:
        conn.execute(
            "UPDATE parcel_version SET valid_to=?, status='SUPERSEDED' WHERE id=? AND valid_to IS NULL",
            (ts, p["id"]))
    conn.execute(
        "UPDATE parcel_version SET valid_to=?, status='SUPERSEDED' WHERE id=? AND id!=? AND parcel_id=? AND valid_to IS NULL",
        (ts, parents[0]["id"], v["id"], target_pid))
    # 其余父宗地标记 ANNULLED 的当前版本（并入后该宗号灭失，演示保留）
    for p in parents[1:]:
        conn.execute(
            "UPDATE parcel_version SET status='ANNULLED' WHERE parcel_id=? AND valid_to IS NULL",
            (p["parcel_id"],))

    opid = ids.new_id("OP")
    conn.execute(
        """INSERT INTO parcel_op(id,type,parent_versions,child_versions,params_json,
           job_id,area_note,created_at) VALUES(?,?,?,?,?,?,?,?)""",
        (opid, "MERGE", json.dumps([p["id"] for p in parents]),
         json.dumps([v["id"]]),
         json.dumps({"note": payload.get("note")}), None,
         json.dumps(area_note), ts))
    return {"status": "COMMITTED",
            "accepted": [{"parcel_id": target_pid, "version_id": v["id"],
                          "area": v["area"]}],
            "area_note": area_note}


def correct(conn, payload: dict) -> dict:
    """登记更正：保留旧版本（ANNULDED 状态但行不删），新版本血缘指向它。

    仅允许更正**当前有效**版本；更正更早历史版本会造成血缘分叉，本平台拒绝。
    """
    ts = as_of(payload.get("as_of"))
    old = vs.get_version(conn, payload["version_id"])
    if not old:
        raise ValueError("被更正版本不存在")
    cur = vs.current_version(conn, old["parcel_id"])
    if not cur or cur["id"] != old["id"]:
        raise ValueError("只能更正当前有效版本；历史时点状态保持不可变")

    raw = payload["corrected"].model_dump() if hasattr(payload["corrected"], "model_dump") \
        else payload["corrected"]
    raw["parcel_id"] = old["parcel_id"]
    errors, normals = val.validate_submission(
        conn, [raw], [], None, exclude_parcels={old["parcel_id"]})
    hard = [e for e in errors if e["code"] != "SHARED_NEIGHBOR_UNCONFIRMED"]
    if hard:
        return {"status": "REJECTED", "errors": hard, "accepted": []}
    n = normals[0]
    n["parcel_id"] = old["parcel_id"]

    v = sync_svc._commit_one(
        conn, n, old["id"], ts, payload.get("reason"), None,
        op_type="CORRECTION", parent_versions=[old["id"]],
        extra_params={"reason": payload.get("reason"),
                      "corrected_version": old["id"]})
    # 旧版本：关闭效力、标注 ANNULLED；行保留、哈希不变，已签发证明仍可验
    # （create_version 已将其置为 SUPERSEDED，此处仅改状态）
    conn.execute(
        "UPDATE parcel_version SET status='ANNULLED' WHERE id=?", (old["id"],))
    area_note = {"old_area": old["area"], "new_area": v["area"],
                 "delta": round(v["area"] - old["area"], 3)}
    conn.execute(
        "UPDATE parcel_op SET area_note=? WHERE id IN "
        "(SELECT id FROM parcel_op WHERE type='CORRECTION' "
        "ORDER BY created_at DESC LIMIT 1)", (json.dumps(area_note),))
    return {"status": "COMMITTED",
            "accepted": [{"parcel_id": v["parcel_id"], "version_id": v["id"],
                          "corrected": old["id"], "area": v["area"]}],
            "area_note": area_note}
