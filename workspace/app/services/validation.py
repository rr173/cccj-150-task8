"""候选边界校验。

错误码
------
* NOT_CLOSED            多边形未闭合
* SELF_INTERSECT        自交
* TOO_FEW_POINTS        顶点不足
* ZERO_SEGMENT          零长/过短边
* AREA_MISMATCH         声明面积与计算面积超容差
* AREA_NONPOSITIVE      面积非正
* OVERLAP               提交内/与已登记宗地非法重叠
* SHARED_INCONSISTENT   同一提交内共享边不一致
* SHARED_NEIGHBOR_CHANGE 改动了未参与宗地的共享边
* SHARED_NEIGHBOR_UNCONFIRMED 上述改动缺少相邻权利人确认
"""
from __future__ import annotations

from .. import geo, config


def _err(code, message, detail=None):
    return {"code": code, "message": message, "detail": detail}


# ---------------------------------------------------------------- 单环
def validate_ring(ring, declared_area=None) -> list[dict]:
    errors = []
    if len(ring) < 3:
        return [_err("TOO_FEW_POINTS", "界址点不足 3 个", {"got": len(ring)})]

    # 外业环常把首点作为回点重复记录在末尾：
    # 末点在首点邻域（snap）内但偏差超闭合容差 → 未闭合
    first, last = ring[0], ring[-1]
    gap = geo._dist(first, last)
    last_is_return = len(ring) >= 4 and gap <= config.POINT_SNAP_TOL_M
    if last_is_return and gap > config.CLOSURE_TOL_M:
        return [_err("NOT_CLOSED",
                     f"多边形未闭合：回点与首点偏差 {gap:.3f}m > {config.CLOSURE_TOL_M}m",
                     {"gap_m": round(gap, 3)})]

    norm = geo.norm_ring(ring)
    if len(norm) < 3:
        errors.append(_err("TOO_FEW_POINTS", "去重后有效界址点不足 3 个"))
        return errors

    zs = geo.zero_segments(norm)
    if zs:
        errors.append(_err("ZERO_SEGMENT",
                           f"存在 {len(zs)} 条短于 {config.MIN_SEG_LEN_M}m 的界址边",
                           {"edges": zs}))

    crosses = geo.self_intersection_points(norm)
    if crosses:
        errors.append(_err("SELF_INTERSECT",
                           f"多边形自交：{len(crosses)} 处穿越",
                           {"points": [list(p) for p in crosses]}))

    area = geo.ring_area(norm)
    if area <= 1e-6:
        errors.append(_err("AREA_NONPOSITIVE", f"多边形面积非正: {area:.3f} m²"))
    elif declared_area:
        diff = abs(area - float(declared_area))
        ratio = diff / float(declared_area) if declared_area else 1.0
        if ratio > config.AREA_TOL_RATIO:
            errors.append(_err(
                "AREA_MISMATCH",
                f"面积容差超限：计算 {area:.2f} vs 声明 {declared_area:.2f}，"
                f"偏差 {ratio:.2%} > {config.AREA_TOL_RATIO:.0%}",
                {"computed": round(area, 3), "declared": float(declared_area),
                 "ratio": round(ratio, 5)}))
    return errors


# ---------------------------------------------------------------- 整批提交
def _points_map(cand) -> dict:
    return {p.local_id: p.model_dump() for p in (cand.points or [])}


def normalize_candidate(cand: dict) -> dict:
    """cand: ParcelCandidateIn.model_dump()"""
    norm = geo.norm_ring(cand["ring"])
    return {
        "parcel_id": cand.get("parcel_id"),
        "label": cand.get("label") or cand.get("parcel_id"),
        "ring": norm,
        "area": geo.ring_area(norm),
        "declared_area": cand.get("declared_area"),
        "points": {p["local_id"]: p for p in cand.get("points", [])},
        "owner": cand.get("owner"),
        "owner_id_no": cand.get("owner_id_no"),
    }


def validate_submission(conn, raw_candidates: list[dict],
                        confirmations: list[dict] | None = None,
                        base_override: dict | None = None,
                        exclude_parcels: set[str] | None = None
                        ) -> tuple[list[dict], list[dict]]:
    """返回 (errors, normalized_candidates)。

    base_override: {parcel_id: base_version_id}，为 None 时以当前有效版本为准。
    exclude_parcels: 分割/合并时被取代的父宗地，不做库内冲突检查。
    """
    confirmations = confirmations or []
    exclude_parcels = exclude_parcels or set()
    errors: list[dict] = []
    normals: list[dict] = []

    # 1) 单环校验
    for c in raw_candidates:
        es = validate_ring(c["ring"], c.get("declared_area"))
        for e in es:
            e["detail"] = {**(e.get("detail") or {}),
                           "parcel_id": c.get("parcel_id"),
                           "label": c.get("label")}
        errors.extend(es)
        normals.append(normalize_candidate(c))
    if errors:
        return errors, normals

    ids_in_sub = {c["parcel_id"] for c in normals if c["parcel_id"]}
    confirmed_neighbors = {cf.get("parcel_id") for cf in confirmations
                           if cf.get("confirmed") and cf.get("parcel_id")}

    # 2) 提交内成对检查：不得重叠；共享则必须一致
    for i in range(len(normals)):
        for j in range(i + 1, len(normals)):
            a, b = normals[i], normals[j]
            ov = geo.overlap_area(a["ring"], b["ring"])
            if ov > 1e-3:
                errors.append(_err(
                    "OVERLAP",
                    f"候选宗地 {a['label']} 与 {b['label']} 内部重叠 {ov:.2f} m²",
                    {"overlap_area": round(ov, 3),
                     "a": a["parcel_id"], "b": b["parcel_id"]}))
            segs = geo.shared_segments(a["ring"], b["ring"])
            if segs:
                band = geo.boundary_band(a["ring"], b["ring"])
                if band["mismatch_len"] > config.MIN_SEG_LEN_M:
                    errors.append(_err(
                        "SHARED_INCONSISTENT",
                        f"{a['label']} 与 {b['label']} 共享边不一致："
                        f"偏差段 {band['mismatch_len']:.2f}m",
                        {"a": a["parcel_id"], "b": b["parcel_id"], **band}))

    # 3) 与库中已登记宗地检查
    from .versions import all_current, get_version
    currents = all_current(conn)
    cur_by_parcel = {v["parcel_id"]: v for v in currents}
    for n in normals:
        # 基线版本：若候选基于旧版本（离线期间库内已更新），与库内的几何冲突
        # 属于"并发分歧"，不在这里拒绝，交由提交逻辑形成争议
        base_vid = (base_override or {}).get(n["parcel_id"])
        stale = False
        if base_vid:
            bv = get_version(conn, base_vid)
            cv = cur_by_parcel.get(n["parcel_id"])
            stale = bool(bv and cv and bv["id"] != cv["id"])
        for pv in currents:
            pid = pv["parcel_id"]
            if n["parcel_id"] == pid or pid in exclude_parcels:
                continue  # 自身新旧版本对比/被取代父宗在提交逻辑处理
            band = geo.boundary_band(n["ring"], pv["ring"])
            touching = bool(geo.shared_segments(n["ring"], pv["ring"])) or \
                band["consistent_len"] > config.MIN_SEG_LEN_M
            ov = geo.overlap_area(n["ring"], pv["ring"])
            if ov > 1e-3 and pid not in ids_in_sub:
                if stale:
                    continue  # 过期基线下的重叠 = 并发分歧证据，进入争议流程
                errors.append(_err(
                    "OVERLAP",
                    f"候选 {n['label']} 与已登记宗地 {pid} 重叠 {ov:.2f} m²",
                    {"overlap_area": round(ov, 3),
                     "a": n["parcel_id"], "b": pid}))
            # 真实共享边（存在重合段）才做一致性检查；
            # 仅有重叠缓冲带（平行相邻边界）不算共享边
            segs = geo.shared_segments(n["ring"], pv["ring"])
            if segs and pid not in ids_in_sub:
                if stale:
                    continue  # 过期基线：按并发争议处理
                # 逐重合段比对：取该段中点，看两环在该位置边界偏差
                mism = 0.0
                for s in segs:
                    mx, my = s["midpoint"]
                    dev = _edge_deviation_at(n["ring"], pv["ring"], mx, my)
                    mism = max(mism, dev)
                if mism > config.SHARED_CONSIST_TOL_M and pid not in confirmed_neighbors:
                    errors.append(_err(
                        "SHARED_NEIGHBOR_UNCONFIRMED",
                        f"候选 {n['label']} 调整了与相邻宗地 {pid} 的共享边"
                        f"（偏差 {mism:.2f}m），但缺少该相邻权利人的确认",
                        {"neighbor": pid, "max_deviation_m": round(mism, 3)}))
    return errors, normals


def _edge_deviation_at(ring_a, ring_b, mx, my, radius=2.0):
    """两环在 (mx,my) 附近边界的最大偏差（Hausdorff，限局部）。"""
    from shapely.geometry import LineString, Point
    la = geo.as_boundary(ring_a)
    lb = geo.as_boundary(ring_b)
    center = Point(mx, my)
    sa = la.intersection(center.buffer(radius))
    sb = lb.intersection(center.buffer(radius))
    if sa.is_empty or sb.is_empty:
        return 0.0
    return geo.chain_deviation(geo._line_coords(sa), geo._line_coords(sb))
