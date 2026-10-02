"""二阶段历史更正：更正草案（可预演）→ 原子发布（分叉版本链）。

阶段一（DRAFT）
    * create_draft：校验更正环，但**不产生任何 parcel_version 行**，不影响任何
      在版宗地；
    * 从目标版本沿 parcel_op 血缘向后（下游）遍历受影响后代（SPLIT 子宗、
      MERGE 结果、CORRECTION/ADJUDICATION 链），逐节点用几何传导
      （geo.transfer_fragments）推演新几何，给出：
        - new_ring 新几何、old/new 面积与面积差；
        - lineage 血缘变化（该版本由哪个操作产生、父版本是谁、发布后新 id）；
      预演结果与一份世界状态指纹一并存入 correction_draft。

阶段二（PUBLISH）
    * publish：重算指纹并与建案时比对——受影响后代、争议或证明状态有任何
      变化即判 DRIFTED，**不套用旧预演、不写任何版本**，标出漂移节点，草案
      保留供重新预演；
    * 无漂移则在**单事务**内原子生成整条更正版本链（每个受影响版本一个
      新版本行，chain_parent_id 指向同宗地新链锚点，旧行与旧哈希原样保留），
      并写 CORRECTION_PUBLISH（总结）+ CORRECTION_REPLAY（每个被重放的原
      操作）血缘；已签发证明继续绑定旧版本哈希，验真不受影响；
    * 相同发布请求重放（同一 draft 或同一 idem_key）返回首次结果。

CANCEL：撤销草案，只删除草案行（本来就没有半成品版本）。
"""
from __future__ import annotations

import json

from .. import geo, config
from . import ids
from .ids import as_of
from . import versions as vs
from . import validation as val


# ================================================================ 草案存取
def _row(conn, draft_id):
    return conn.execute("SELECT * FROM correction_draft WHERE id=?",
                        (draft_id,)).fetchone()


def get_draft(conn, draft_id) -> dict | None:
    r = _row(conn, draft_id)
    if not r:
        return None
    d = dict(r)
    for k in ("corrected_ring_json", "preview_json", "fingerprint_json",
              "result_json"):
        d[k.replace("_json", "")] = json.loads(d[k]) if d[k] else None
    return d


def list_drafts(conn, status: str | None = None):
    sql = "SELECT id,target_version_id,reason,status,created_at,previewed_at," \
          "published_at,cancelled_at FROM correction_draft"
    args = ()
    if status:
        sql += " WHERE status=?"
        args = (status,)
    sql += " ORDER BY created_at"
    return [dict(r) for r in conn.execute(sql, args).fetchall()]


def _guard_active_plan(conn, draft_id: str, by_plan: str | None):
    """草案存在生效中的计划时，禁止手动发布/重新预演（计划是基线唯一管理者）。"""
    from . import plans  # 延迟导入避免循环依赖
    row = plans._active_plan_for_draft(conn, draft_id, exclude_plan=by_plan)
    if row:
        raise ValueError(f"草案已登记生效计划 {row['id']}，"
                         f"请在计划上改期/取消/恢复，不能直接操作草案")


# ================================================================ 血缘遍历
def _all_ops(conn):
    rows = conn.execute(
        "SELECT * FROM parcel_op ORDER BY created_at, id").fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["parent_versions"] = json.loads(d["parent_versions"])
        d["child_versions"] = json.loads(d["child_versions"])
        d["params"] = json.loads(d["params_json"])
        out.append(d)
    return out


def _descendants(conn, target_vid: str):
    """从目标版本出发，沿血缘向下游遍历，返回受影响版本（含目标，拓扑序）。

    返回 [(version_id, depth, op)]：op 是产生该版本的操作（目标为 None）。
    多父操作（MERGE/ADJUDICATION）只要任一父版本受影响即纳入。
    """
    ops = _all_ops(conn)
    affected = {target_vid: 0}
    origin_op = {}
    changed = True
    while changed:
        changed = False
        for op in ops:
            hit = [v for v in op["parent_versions"] if v in affected]
            if not hit:
                continue
            for ch in op["child_versions"]:
                depth = 1 + min(affected[v] for v in hit)
                if ch not in affected or depth < affected[ch]:
                    affected[ch] = depth
                    # 用汇总操作（全部父子）作为血缘来源，而非 per-child op
                    origin_op[ch] = _producing_op(conn, ch) or op
                    changed = True
    order = sorted(affected, key=lambda v: (affected[v], v))
    return [(v, affected[v], origin_op.get(v)) for v in order]


def _producing_op(conn, version_id):
    """产生该版本的**汇总**血缘操作（child_versions 含它且子版本最多的一条）。

    split/merge 落库时每个子版本各有一条 op，另有一条 SPLIT/MERGE 汇总 op
    把全部父子版本记在一起；传导/守恒要以汇总 op 为准。子版本数并列时优先
    选 SPLIT/MERGE/CORRECTION_PUBLISH 这类汇总操作，再按 id 确定（不依赖
    可能同时间戳的 created_at 排序）。
    """
    summary_rank = {"SPLIT": 2, "MERGE": 2, "CORRECTION_PUBLISH": 2,
                    "CORRECTION": 1, "ADJUDICATION": 1, "SURVEY": 0,
                    "CORRECTION_REPLAY": 0}
    best = None
    for op in _all_ops(conn):
        if version_id not in op["child_versions"]:
            continue
        rank = (len(op["child_versions"]),
                summary_rank.get(op["type"], 0))
        best_rank = (len(best["child_versions"]),
                     summary_rank.get(best["type"], 0)) if best else None
        if best is None or rank > best_rank or \
                (rank == best_rank and op["id"] > best["id"]):
            best = op
    return best


# ================================================================ 几何预演
def _replay_node(conn, vid, new_by_old: dict, op) -> dict:
    """推演单个受影响版本的新几何。返回节点描述（含错误/面积差）。"""
    old = vs.get_version(conn, vid)
    # 以汇总操作（SPLIT/MERGE 全体父子）为准做传导与血缘；闭包传入的 op 可能
    # 是 per-child 操作。
    top = _producing_op(conn, vid) or op
    op = top
    node = {
        "version_id": vid,
        "parcel_id": old["parcel_id"],
        "version_no": old["version_no"],
        "op_type": op["type"] if op else "TARGET",
        "depth": 0,
        "old_ring": old["ring"],
        "old_area": old["area"],
        "status": old["status"],
        "changed": False,
        "errors": [],
        "lineage": None,
    }
    if op is None:
        return node  # 目标版本的新几何由草案环给出，调用方填充

    if op["type"] == "MERGE":
        # 合并结果的语义即"父宗并集"：直接用更正后各父宗（未受影响的用旧环）
        # 求并集重建，避免在合并长外环上逐段传导的锚点对齐问题。
        parent_rings = []
        for pv in op["parent_versions"]:
            pold = vs.get_version(conn, pv)
            if not pold:
                continue
            parent_rings.append(new_by_old.get(pv, pold["ring"]))
        used_parents = [pv for pv in op["parent_versions"]
                        if pv in new_by_old]
        cur_ring = None
        if parent_rings and used_parents:
            try:
                union, _ = geo.polygon_union(parent_rings)
                cur_ring = geo.norm_ring(list(union.exterior.coords[:-1]))
            except Exception as e:  # noqa: BLE001
                node["errors"].append({
                    "code": "REHEARSAL_UNION_FAILED", "message": str(e)})
                cur_ring = old["ring"]
    else:
        # SPLIT / CORRECTION / ADJUDICATION 等：逐父把变更片段传导到本版本环
        cur_ring = old["ring"]
        used_parents = []
        for pv in op["parent_versions"]:
            pold = vs.get_version(conn, pv)
            if not pold:
                continue
            new_parent = new_by_old.get(pv)
            if new_parent is None:
                continue  # 该父版本未受影响（不在更正闭包内）
            frags = geo.diff_fragments(pold["ring"], new_parent)
            if not frags:
                continue
            cur_ring = geo.transfer_fragments(cur_ring, pold["ring"], frags)
            used_parents.append(pv)
    new_ring = geo.norm_ring(cur_ring) if cur_ring is not None else old["ring"]
    node["new_ring"] = new_ring
    node["changed"] = geo.chain_deviation(
        new_ring + [new_ring[0]], old["ring"] + [old["ring"][0]]) > 1e-6
    node["new_area"] = geo.ring_area(new_ring)
    node["area_delta"] = round(node["new_area"] - old["area"], 6)
    node["lineage"] = {
        "op_id": op["id"], "op_type": op["type"],
        "parent_versions": op["parent_versions"],
        "replayed_from_parents": used_parents,
    }

    # ---- 校验 ----
    errs = val.validate_ring(new_ring)
    if errs:
        node["errors"].extend({"code": e["code"], "message": e["message"]}
                              for e in errs)
    return node


def _validate_groups(conn, nodes: list[dict], op_by_vid: dict):
    """跨节点守恒校验：SPLIT 子宗和=更正后父；MERGE 结果=更正后父并集。

    分组用**汇总操作**（child_versions 最多的那条 SPLIT/MERGE op），
    以保证同一分割的所有子宗在同一组。
    """
    by_vid = {n["version_id"]: n for n in nodes}
    groups = {}
    for n in nodes:
        if not n.get("lineage"):
            continue
        top = _producing_op(conn, n["version_id"])
        if top and top["type"] in ("SPLIT", "MERGE"):
            groups.setdefault(top["id"], (top, []))[1].append(n)
    for op, members in groups.values():
        opid = op["id"]
        if op["type"] == "SPLIT":
            parent_new = next((by_vid[p]["new_ring"]
                               for p in op["parent_versions"] if p in by_vid
                               and "new_ring" in by_vid[p]), None)
            if parent_new is None:
                continue
            pa = geo.ring_area(parent_new)
            s = sum(m.get("new_area", m["old_area"]) for m in members)
            ratio = abs(s - pa) / max(pa, 1e-9)
            if ratio > config.SPLIT_MERGE_AREA_RATIO:
                for m in members:
                    m["errors"].append({
                        "code": "REHEARSAL_AREA_BROKEN",
                        "message": f"分割后代面积和 {s:.3f} 与更正后父宗 "
                                   f"{pa:.3f} 偏差 {ratio:.3%}（传导不守恒）"})
        elif op["type"] == "MERGE":
            # 用全部父：受影响的取更正后新环，未受影响的取库内旧环，
            # 与 _replay_node 的合并重建口径保持一致。
            rings = []
            for pv in op["parent_versions"]:
                if pv in by_vid and "new_ring" in by_vid[pv]:
                    rings.append(by_vid[pv]["new_ring"])
                else:
                    pv_old = vs.get_version(conn, pv)
                    if pv_old:
                        rings.append(pv_old["ring"])
            if not rings:
                continue
            try:
                union, _ = geo.polygon_union(rings)
                res = next(m for m in members)
                eq, note = _rings_equal(geo.norm_ring(
                    list(union.exterior.coords[:-1])), res["new_ring"])
                if not eq:
                    res["errors"].append({
                        "code": "REHEARSAL_GEOMETRY_BROKEN",
                        "message": "合并结果与更正后父宗并集不一致",
                        "detail": note})
            except Exception as e:  # noqa: BLE001
                members[0]["errors"].append({
                    "code": "REHEARSAL_UNION_FAILED", "message": str(e)})


def _op_by_id(conn, opid):
    for op in _all_ops(conn):
        if op["id"] == opid:
            return op
    return None


def _rings_equal(r1, r2, tol=config.SHARED_SEARCH_TOL_M):
    p1, p2 = geo.as_polygon(r1), geo.as_polygon(r2)
    if not p1.is_valid or not p2.is_valid:
        return False, {"reason": "invalid"}
    sym = p1.symmetric_difference(p2)
    return float(sym.area) < 1e-6, {
        "symmetric_diff_area": round(float(sym.area), 6)}


# ================================================================ 预演主流程
def rehearse(conn, target_vid: str, corrected_ring, reason: str) -> dict:
    """计算目标版本 + 全部下游后代的更正预演。不写库。"""
    target = vs.get_version(conn, target_vid)
    if not target:
        raise ValueError("被更正版本不存在")
    corrected_ring = geo.norm_ring(corrected_ring)

    closure = _descendants(conn, target_vid)
    nodes_by_vid = {}
    nodes = []

    # 目标节点
    tnode = {
        "version_id": target_vid,
        "parcel_id": target["parcel_id"],
        "version_no": target["version_no"],
        "op_type": "TARGET",
        "depth": 0,
        "old_ring": target["ring"],
        "old_area": target["area"],
        "status": target["status"],
        "new_ring": corrected_ring,
        "new_area": geo.ring_area(corrected_ring),
        "changed": True,
        "errors": [{"code": e["code"], "message": e["message"]}
                   for e in val.validate_ring(corrected_ring)],
        "lineage": None,
    }
    tnode["area_delta"] = round(tnode["new_area"] - target["area"], 6)
    nodes.append(tnode)
    nodes_by_vid[target_vid] = tnode

    new_by_old = {target_vid: corrected_ring}
    for vid, depth, op in closure:
        if vid == target_vid:
            continue
        node = _replay_node(conn, vid, new_by_old, op)
        node["depth"] = depth
        nodes.append(node)
        nodes_by_vid[vid] = node
        if "new_ring" in node:
            new_by_old[vid] = node["new_ring"]

    _validate_groups(conn, nodes, {})

    # 重叠检查：更正后新几何之间 / 与未受影响在版宗地不得非法重叠
    _check_overlaps(conn, nodes, nodes_by_vid)

    errors = [{"version_id": n["version_id"], "parcel_id": n["parcel_id"],
               "errors": n["errors"]}
              for n in nodes if n["errors"]]
    affected_parcels = sorted({n["parcel_id"] for n in nodes})
    preview = {
        "target_version_id": target_vid,
        "target_parcel_id": target["parcel_id"],
        "reason": reason,
        "corrected_ring": corrected_ring,
        "nodes": [{
            "version_id": n["version_id"],
            "parcel_id": n["parcel_id"],
            "version_no": n["version_no"],
            "op_type": n["op_type"],
            "depth": n["depth"],
            "old_ring": n["old_ring"],
            "old_area": n["old_area"],
            "new_ring": n.get("new_ring"),
            "new_area": n.get("new_area"),
            "area_delta": n.get("area_delta"),
            "changed": n["changed"],
            "lineage": n.get("lineage"),
            "errors": n["errors"],
        } for n in nodes],
        "affected_parcels": affected_parcels,
        "errors": errors,
        "releasable": not errors,
    }
    preview["fingerprint"] = fingerprint(conn, preview)
    return preview


def _check_overlaps(conn, nodes, nodes_by_vid):
    """重叠校验（避免血缘祖先/后代、被取代宗地的误报）：

    * 同一 SPLIT 操作的新子宗之间不得内部重叠（本应只共享分割线）；
    * 与"既不是受影响宗地、也不是受影响宗地血缘祖先"的在版宗地不得重叠；
      共享边移动（与邻宗边界不一致）不在此拦截——属相邻关系，需相邻权利人
      确认而非几何作废（与既有提交流程一致）。
    """
    node_of_vid = {n["version_id"]: n for n in nodes}
    closure_vids = {n["version_id"] for n in nodes}

    groups = {}
    for n in nodes:
        if n.get("lineage") and n["lineage"]["op_type"] == "SPLIT":
            groups.setdefault(n["lineage"]["op_id"], []).append(n)
    for members in groups.values():
        for i in range(len(members)):
            for j in range(i + 1, len(members)):
                a, b = members[i], members[j]
                ra, rb = a.get("new_ring"), b.get("new_ring")
                if not ra or not rb:
                    continue
                ov = geo.overlap_area(ra, rb)
                if ov > 1e-3:
                    a["errors"].append({
                        "code": "REHEARSAL_OVERLAP",
                        "message": f"同一分割的后代 {b['parcel_id']} 更正后内部"
                                   f"重叠 {ov:.2f} m²"})

    def is_ancestor_version(potential_vid):
        seen, stack = set(), list(closure_vids)
        while stack:
            v = stack.pop()
            if v in seen:
                continue
            seen.add(v)
            op = _producing_op(conn, v)
            if op:
                for pp in op["parent_versions"]:
                    if pp == potential_vid:
                        return True
                    stack.append(pp)
        return False

    new_rings = [(n["parcel_id"], n["new_ring"], n["version_id"])
                 for n in nodes if n.get("new_ring") is not None]
    affected_pids = {pid for pid, _, _ in new_rings}
    for pv in vs.all_current(conn):
        if pv["parcel_id"] in affected_pids:
            continue
        if is_ancestor_version(pv["id"]):
            continue
        for pid, ring, vid in new_rings:
            ov = geo.overlap_area(ring, pv["ring"])
            if ov > 1e-3:
                node_of_vid[vid]["errors"].append({
                    "code": "REHEARSAL_OVERLAP",
                    "message": f"传导后与无关在版宗地 {pv['parcel_id']} "
                               f"重叠 {ov:.2f} m²"})



# ================================================================ 指纹 / 漂移
def fingerprint(conn, preview: dict) -> dict:
    """建案时刻的世界状态指纹：受影响宗地全部版本哈希、争议、证明、当前版本。"""
    pids = set(preview["affected_parcels"])
    versions = {}
    currents = {}
    for pid in sorted(pids):
        versions[pid] = [
            {"id": v["id"], "hash": v["version_hash"], "status": v["status"],
             "valid_to": v["valid_to"]}
            for v in vs.list_versions(conn, pid)]
        cur = vs.current_version(conn, pid)
        currents[pid] = cur["id"] if cur else None
    disputes = [
        {"id": r["id"], "status": r["status"],
         "decision": r["decision"], "result_versions": r["result_versions"]}
        for r in conn.execute("SELECT * FROM dispute ORDER BY id").fetchall()
        if _dispute_touches(r, pids)]
    certs = [
        {"id": r["id"], "version_id": r["version_id"], "revoked": r["revoked"],
         "signature": r["signature"]}
        for r in conn.execute("SELECT * FROM certificate ORDER BY id").fetchall()
        if r["parcel_id"] in pids]
    return {"versions": versions, "currents": currents,
            "disputes": disputes, "certificates": certs}


def _dispute_touches(row, pids) -> bool:
    return row["parcel_a"] in pids or row["parcel_b"] in pids


def diff_fingerprint(conn, fp_old: dict, fp_now: dict, nodes_by_parcel: dict):
    """比对两份指纹，返回漂移节点列表 []（空=无漂移）。"""
    drift = []
    for pid, vers in fp_old["versions"].items():
        old_by_id = {v["id"]: v for v in vers}
        now_rows = {v["id"]: v for v in fp_now["versions"].get(pid, [])}
        for vid, ov in old_by_id.items():
            nv = now_rows.get(vid)
            if nv is None:
                drift.append({"kind": "VERSION_MISSING", "parcel_id": pid,
                              "version_id": vid,
                              "message": "受影响版本在草案建立后消失"})
            elif nv["hash"] != ov["hash"] or nv["status"] != ov["status"] or \
                    nv["valid_to"] != ov["valid_to"]:
                drift.append({"kind": "VERSION_CHANGED", "parcel_id": pid,
                              "version_id": vid,
                              "message": "受影响后代版本在草案建立后被修改"})
        for vid, nv in now_rows.items():
            if vid not in old_by_id:
                drift.append({"kind": "VERSION_ADDED", "parcel_id": pid,
                              "version_id": vid,
                              "message": "受影响宗地在草案建立后新增了版本"})
        if fp_old["currents"].get(pid) != fp_now["currents"].get(pid):
            drift.append({"kind": "CURRENT_CHANGED", "parcel_id": pid,
                          "old_current": fp_old["currents"].get(pid),
                          "new_current": fp_now["currents"].get(pid),
                          "message": "受影响宗地的当前版本已变化"})
    old_disp = {d["id"]: d for d in fp_old["disputes"]}
    new_disp = {d["id"]: d for d in fp_now["disputes"]}
    # 新建/涉及受影响宗地的争议也要算（指纹 now 已按宗地过滤）
    for did, d in new_disp.items():
        if did not in old_disp:
            drift.append({"kind": "DISPUTE_OPENED", "dispute_id": did,
                          "message": "草案建立后出现新的相关争议"})
        elif d["status"] != old_disp[did]["status"] or \
                d["decision"] != old_disp[did]["decision"]:
            drift.append({"kind": "DISPUTE_CHANGED", "dispute_id": did,
                          "old_status": old_disp[did]["status"],
                          "new_status": d["status"],
                          "message": "相关争议在草案建立后被裁定或改动"})
    for did in old_disp:
        if did not in new_disp:
            drift.append({"kind": "DISPUTE_REMOVED", "dispute_id": did,
                          "message": "相关争议记录消失"})
    old_certs = {c["id"]: c for c in fp_old["certificates"]}
    new_certs = {c["id"]: c for c in fp_now["certificates"]}
    for cid, c in new_certs.items():
        if cid not in old_certs:
            drift.append({"kind": "CERTIFICATE_ISSUED", "cert_id": cid,
                          "version_id": c["version_id"],
                          "message": "草案建立后受影响宗地新签发了证明"})
        elif c["revoked"] != old_certs[cid]["revoked"]:
            drift.append({"kind": "CERTIFICATE_REVOKED", "cert_id": cid,
                          "message": "相关证明在草案建立后被吊销"})
    return drift


# ================================================================ 建草案
def create_draft(conn, payload: dict) -> dict:
    ts = as_of(payload.get("as_of"))
    target = vs.get_version(conn, payload["version_id"])
    if not target:
        raise ValueError("被更正版本不存在")
    raw = payload["corrected"].model_dump() if hasattr(
        payload["corrected"], "model_dump") else payload["corrected"]
    corrected = geo.norm_ring(raw["ring"])
    # 草案阶段只做单环合法性校验（与邻宗重叠等在预演里给出可阅错误）
    ring_errs = val.validate_ring(corrected, raw.get("declared_area"))
    did = ids.new_id("DRAFT")
    conn.execute(
        """INSERT INTO correction_draft
           (id,target_version_id,corrected_ring_json,reason,status,created_by,
            created_at) VALUES(?,?,?,?,'OPEN',?,?)""",
        (did, target["id"], json.dumps(corrected), payload.get("reason") or "",
         payload.get("created_by"), ts))
    preview = rehearse(conn, target["id"], corrected, payload.get("reason") or "")
    # 几何非法也存草案（状态仍 OPEN，releasable=False，用户可看错误）
    _persist_preview(conn, did, preview, ts)
    return {"draft_id": did, "status": "OPEN",
            "releasable": preview["releasable"],
            "hard_errors": ring_errs,
            "preview": preview}


def _persist_preview(conn, did, preview: dict, ts):
    conn.execute(
        "UPDATE correction_draft SET previewed_at=?, preview_json=?, "
        "fingerprint_json=? WHERE id=?",
        (ts, json.dumps(preview, ensure_ascii=False),
         json.dumps(preview["fingerprint"], ensure_ascii=False), did))


def re_rehearse(conn, draft_id: str, _by_plan: str | None = None) -> dict:
    """重新预演（漂移后用户要求刷新）。覆盖 preview/fingerprint。

    草案被生效计划持有时，基线刷新只能由计划的「恢复」流程（_by_plan 指向
    该计划）完成，避免计划指纹与草案指纹产生两个真相来源。
    """
    d = get_draft(conn, draft_id)
    if not d:
        raise ValueError("草案不存在")
    if d["status"] in ("PUBLISHED", "CANCELLED"):
        raise ValueError(f"草案已{d['status']}，不能重新预演")
    _guard_active_plan(conn, draft_id, _by_plan)
    preview = rehearse(conn, d["target_version_id"],
                       d["corrected_ring"], d["reason"])
    _persist_preview(conn, draft_id, preview, as_of(None))
    if d["status"] == "DRIFTED":
        conn.execute("UPDATE correction_draft SET status='OPEN' WHERE id=?",
                     (draft_id,))
        preview["draft_status"] = "OPEN"
    return preview


# ================================================================ 发布
def publish(conn, payload: dict, _by_plan: str | None = None) -> dict:
    """原子发布二阶段更正。返回 {status: PUBLISHED/DRIFTED, ...}。"""
    did = payload["draft_id"]
    d = get_draft(conn, did)
    if not d:
        raise ValueError("草案不存在")
    idem = payload.get("idem_key") or f"draft-publish:{did}"

    # 幂等：全局幂等表（与离线提交同一套机制）
    row = conn.execute("SELECT response_json FROM idempotency WHERE idem_key=?",
                       (idem,)).fetchone()
    if row:
        return json.loads(row["response_json"])

    if d["status"] == "PUBLISHED" and d["result"]:
        return d["result"]
    if d["status"] == "CANCELLED":
        raise ValueError("草案已撤销，不能发布")
    # 被生效计划占用的草案只能由该计划的执行器落账
    _guard_active_plan(conn, did, _by_plan)
    if not d.get("preview"):
        raise ValueError("草案尚未预演")

    ts = as_of(payload.get("as_of"))
    preview = d["preview"]

    # 1) 实时漂移检测（不套用旧预演）
    fp_now = fingerprint(conn, preview)
    drift = diff_fingerprint(conn, d["fingerprint"], fp_now, {})

    # 2) 实时重算预演，检查几何是否仍 releasable（世界变了，传导结果也可能失效）
    live = rehearse(conn, d["target_version_id"],
                    d["corrected_ring"], d["reason"])
    if drift or not live["releasable"]:
        conn.execute("UPDATE correction_draft SET status='DRIFTED' WHERE id=?",
                     (did,))
        return {
            "status": "DRIFTED", "draft_id": did,
            "drift_nodes": drift,
            "live_errors": live["errors"],
            "message": ("草案基线已漂移，未套用旧预演、未产生任何版本；"
                        "请重新预演后再发布"),
            "preview": live,
        }

    # 3) 原子发布：生成整条更正版本链
    result = _materialize(conn, d, live, ts, payload.get("published_by"))
    resp = {"status": "PUBLISHED", "draft_id": did, **result}
    conn.execute(
        "UPDATE correction_draft SET status='PUBLISHED',published_at=?,"
        "publish_idem=?,result_json=? WHERE id=?",
        (ts, idem, json.dumps(resp, ensure_ascii=False), did))
    _store_idem(conn, idem, resp, ts)
    return resp


def _store_idem(conn, key, resp, ts):
    conn.execute(
        "INSERT OR REPLACE INTO idempotency(idem_key,response_json,created_at) "
        "VALUES(?,?,?)", (key, json.dumps(resp, ensure_ascii=False), ts))


def _materialize(conn, draft: dict, preview: dict, ts: str, by: str | None) -> dict:
    """单事务内生成更正版本链（调用方已持有写事务）。"""
    nodes = preview["nodes"]
    # 预生成每个 changed 节点的新版本 id
    new_vid = {}
    for n in nodes:
        if n.get("changed") and n.get("new_ring") is not None:
            new_vid[n["version_id"]] = ids.new_id("PV")

    # 每宗地的新链锚点（该宗地最早一个 changed 节点）
    anchor_old = {}
    for n in sorted(nodes, key=lambda x: (x["depth"], x["version_no"])):
        if n.get("changed") and n["parcel_id"] not in anchor_old:
            anchor_old[n["parcel_id"]] = n["version_id"]

    created = []
    replay_ops = []
    # 拓扑序创建
    for n in sorted(nodes, key=lambda x: (x["depth"], x["version_no"])):
        if not n.get("changed") or n.get("new_ring") is None:
            continue
        old = vs.get_version(conn, n["version_id"])
        pid = n["parcel_id"]
        chain_anchor = vs.get_version(conn, anchor_old[pid])
        # 同宗地新链前驱：同一宗地前一个新生成的版本；新链首版本则挂到旧锚点
        # 的链前驱（旧锚点本身在旧链上，新链从它之前分叉，旧锚点保留在旧链）。
        prev_new = next((c for c in reversed(created)
                         if c["parcel_id"] == pid), None)
        chain_parent = prev_new["id"] if prev_new else \
            (chain_anchor["chain_parent_id"] or None)

        # 跨操作父哈希：优先新父版本，否则旧父哈希
        parent_vids, new_parent_vids, effective_parents = [], [], []
        lin = n.get("lineage")
        if n["op_type"] == "TARGET":
            parent_vids = [n["version_id"]]
            new_parent_vids = []  # 目标自更正，链前驱承载
        elif lin:
            parent_vids = lin["parent_versions"]
            new_parent_vids = [new_vid[p] for p in lin["parent_versions"]
                               if p in new_vid]
            # 实际入哈希/血缘的父：受影响父→新版本，未受影响父→保留旧版本
            effective_parents = [new_vid[p] if p in new_vid else p
                                 for p in lin["parent_versions"]]
        parent_hashes = [vs._hash_of(conn, p) for p in effective_parents]
        parent_hashes = [h for h in parent_hashes if h]

        v = vs.create_version(
            conn, parcel_id=pid, ring=n["new_ring"], area=n["new_area"],
            status="COMMITTED", ts=ts,
            base_version_id=n["version_id"],
            chain_parent_id=chain_parent,
            parent_hashes=parent_hashes,
            supersede=False, vid=new_vid[n["version_id"]])
        vs.link_version_points(conn, v["id"],
                               vs.register_ring(conn, n["new_ring"], None, ts))
        created.append(v)

        if n["op_type"] != "TARGET":
            replay_ops.append({
                "type": "CORRECTION_REPLAY",
                "parents": effective_parents,
                "new_parents": new_parent_vids,
                "child": v["id"],
                "old_child": n["version_id"],
                "op_type": n["op_type"],
                "lineage": lin,
            })

    # 旧链保留全部行与哈希（历史时间点查询、旧证明验真不变）：
    # 1) 关闭受影响宗地当前在版的旧版本（valid_to IS NULL）；
    # 2) 更正分叉在发布时刻重放整条历史——只有血缘**叶子**新版本（不再有
    #    受影响后代）置为当前有效；中间版本（如被更正后分割所取代的目标版本）
    #    在发布时刻即失效。这样已分割父宗不会与其子宗同时在版（避免面积重复）。
    for pid in anchor_old:
        conn.execute(
            "UPDATE parcel_version SET valid_to=?, status='SUPERSEDED' "
            "WHERE parcel_id=? AND valid_to IS NULL", (ts, pid))

    changed_vids = {n["version_id"] for n in nodes if n.get("changed")}
    parent_of_any = set()
    for n in nodes:
        lin = n.get("lineage")
        if lin:
            parent_of_any.update(p for p in lin["parent_versions"]
                                 if p in changed_vids and
                                 p != n["version_id"])
    leaf_old = [n["version_id"] for n in nodes
                if n.get("changed") and n["version_id"] not in parent_of_any]
    # 中间新版本发布即失效
    for old_vid, new in new_vid.items():
        if old_vid not in leaf_old:
            conn.execute(
                "UPDATE parcel_version SET valid_to=?, status='SUPERSEDED' WHERE id=?",
                (ts, new))
    # 叶子新版本在版
    for old_vid in leaf_old:
        conn.execute(
            "UPDATE parcel_version SET valid_to=NULL, status='COMMITTED' WHERE id=?",
            (new_vid[old_vid],))

    # 血缘操作：每个重放原操作一条 + 一条总结
    for ro in replay_ops:
        opid = ids.new_id("OP")
        # parents 存"生效父全集"（受影响父→新版本，未受影响父→旧版本），
        # 与版本入哈希口径一致；new_parents 仅记录其中的新父（明细见 params）。
        parents_json = json.dumps(ro["parents"])
        conn.execute(
            """INSERT INTO parcel_op
               (id,type,parent_versions,child_versions,params_json,job_id,
                dispute_id,area_note,created_at)
               VALUES(?,?,?,?,?,?,?,?,?)""",
            (opid, "CORRECTION_REPLAY",
             parents_json, json.dumps([ro["child"]]),
             json.dumps({"draft_id": draft["id"],
                         "replayed_op": ro["lineage"]["op_id"] if ro["lineage"] else None,
                         "op_type": ro["op_type"],
                         "old_child": ro["old_child"],
                         "new_parents": ro["new_parents"],
                         "old_parents": ro["parents"]}),
             None, None,
             json.dumps({"old_child": ro["old_child"]}), ts))

    target_new = new_vid[draft["target_version_id"]]
    summary_op = ids.new_id("OP")
    conn.execute(
        """INSERT INTO parcel_op
           (id,type,parent_versions,child_versions,params_json,job_id,
            dispute_id,area_note,created_at)
           VALUES(?,?,?,?,?,?,?,?,?)""",
        (summary_op, "CORRECTION_PUBLISH",
         json.dumps([draft["target_version_id"]]),
         json.dumps(list(new_vid.values())),
         json.dumps({"draft_id": draft["id"], "reason": draft["reason"],
                     "published_by": by,
                     "old_to_new": new_vid}),
         None, None,
         json.dumps({"nodes": len(nodes),
                     "changed": len(new_vid)}), ts))

    return {
        "published_at": ts,
        "op_id": summary_op,
        "new_versions": [
            {"parcel_id": v["parcel_id"], "version_id": v["id"],
             "version_no": v["version_no"], "area": v["area"],
             "replaces": next(nid for nid, nvid in new_vid.items()
                              if nvid == v["id"])}
            for v in created],
        "old_to_new": new_vid,
        "target_new_version_id": target_new,
        "chains_forked": sorted(anchor_old),
    }


# ================================================================ 撤销
def cancel(conn, draft_id: str) -> dict:
    d = get_draft(conn, draft_id)
    if not d:
        raise ValueError("草案不存在")
    if d["status"] == "PUBLISHED":
        raise ValueError("草案已发布，不能撤销")
    if d["status"] == "CANCELLED":
        return {"draft_id": draft_id, "status": "CANCELLED", "already": True}
    _guard_active_plan(conn, draft_id, None)
    ts = as_of(None)
    # 草案从未产生版本行，撤销只改草案状态，无任何半成品残留
    conn.execute(
        "UPDATE correction_draft SET status='CANCELLED',cancelled_at=? WHERE id=?",
        (ts, draft_id))
    return {"draft_id": draft_id, "status": "CANCELLED", "cancelled_at": ts}
