"""宗地与不可变版本服务：界址点登记、版本落库、时间点查询。"""
from __future__ import annotations

import json

from .. import geo
from ..config import POINT_SNAP_TOL_M
from . import ids
from .crypto import version_hash


def _jloads(s):
    return json.loads(s) if s else None


# ---------------------------------------------------------------- 宗地
def ensure_parcel(conn, parcel_id: str | None, label: str | None, ts: str) -> str:
    if parcel_id:
        row = conn.execute("SELECT id, label FROM parcel WHERE id=?", (parcel_id,)).fetchone()
        if not row:
            raise ValueError(f"宗地不存在: {parcel_id}")
        return parcel_id
    pid = ids.new_id("P")
    conn.execute("INSERT INTO parcel(id,label,created_at) VALUES(?,?,?)",
                 (pid, label or pid, ts))
    return pid


def list_parcels(conn):
    return [dict(r) for r in conn.execute("SELECT * FROM parcel ORDER BY id")]


# ---------------------------------------------------------------- 界址点
def _nearest_point(conn, x, y, tol=POINT_SNAP_TOL_M):
    rows = conn.execute("SELECT id,x,y FROM point").fetchall()
    best, best_d = None, tol
    for r in rows:
        d = ((r["x"] - x) ** 2 + (r["y"] - y) ** 2) ** 0.5
        if d <= best_d:
            best, best_d = r["id"], d
    return best


def register_point(conn, x, y, kind, origin, ts, override_id=None) -> str:
    near = _nearest_point(conn, x, y)
    if near:
        return near
    pid = override_id or ids.new_id("BP")
    # 采集端 UUID 与平台 BP-* 都允许，但需唯一
    exists = conn.execute("SELECT 1 FROM point WHERE id=?", (pid,)).fetchone()
    if exists:
        return pid
    conn.execute(
        "INSERT INTO point(id,x,y,kind,origin,created_at) VALUES(?,?,?,?,?,?)",
        (pid, x, y, kind or "corner", origin, ts))
    return pid


def register_ring(conn, norm_ring, collected: dict | None, ts: str) -> list[str]:
    """把环上顶点登记为全局界址点并返回有序 point_id。

    collected: {local_id: {...}} 用首点 local_id 可覆盖平台 id（仅新点）。
    """
    point_ids = []
    for idx, (x, y) in enumerate(norm_ring):
        kind, override = "corner", None
        if collected:
            info = _match_collected(collected, x, y)
            if info:
                kind = info.get("kind") or "corner"
                lid = info.get("local_id")
                if lid and not _nearest_point(conn, x, y):
                    override = lid if lid.startswith(("BP-", "DEV-")) else f"DEV-{lid}"
        pid = register_point(conn, x, y, kind, "survey", ts, override_id=override)
        point_ids.append(pid)
    return point_ids


def _match_collected(collected, x, y, tol=POINT_SNAP_TOL_M):
    for info in collected.values():
        if abs(info["x"] - x) <= tol and abs(info["y"] - y) <= tol:
            return info
    return None


# ---------------------------------------------------------------- 版本
def current_version(conn, parcel_id: str) -> dict | None:
    row = conn.execute(
        "SELECT * FROM parcel_version WHERE parcel_id=? AND valid_to IS NULL "
        "ORDER BY version_no DESC LIMIT 1", (parcel_id,)).fetchone()
    return _vrow(row)


def get_version(conn, version_id: str) -> dict | None:
    row = conn.execute("SELECT * FROM parcel_version WHERE id=?",
                       (version_id,)).fetchone()
    return _vrow(row)


def _vrow(row) -> dict | None:
    if not row:
        return None
    d = dict(row)
    d["ring"] = _jloads(d.pop("ring_json"))
    return d


def list_versions(conn, parcel_id: str) -> list[dict]:
    rows = conn.execute(
        "SELECT * FROM parcel_version WHERE parcel_id=? ORDER BY version_no",
        (parcel_id,)).fetchall()
    return [_vrow(r) for r in rows]


def version_at(conn, parcel_id: str, iso_ts: str) -> dict | None:
    """半开区间 [valid_from, valid_to) 时点查询。"""
    row = conn.execute(
        "SELECT * FROM parcel_version WHERE parcel_id=? AND valid_from<=? "
        "AND (valid_to IS NULL OR valid_to>?) ORDER BY version_no DESC LIMIT 1",
        (parcel_id, iso_ts, iso_ts)).fetchone()
    return _vrow(row)


def all_current(conn) -> list[dict]:
    rows = conn.execute(
        "SELECT * FROM parcel_version WHERE valid_to IS NULL ORDER BY parcel_id"
    ).fetchall()
    return [_vrow(r) for r in rows]


def create_version(conn, *, parcel_id: str, ring, area: float,
                   status: str, ts: str, base_version_id: str | None = None,
                   parent_hashes: list[str] | None = None,
                   declared_area: float | None = None,
                   supersede: bool = True,
                   chain_parent_id: str | None = None,
                   vid: str | None = None) -> dict:
    """创建不可变版本。

    * supersede=True 时关闭该宗地旧有效版本（普通登记流程）；
    * 历史更正发布（分叉）传 supersede=False，旧链保持在版/效力区间不变；
    * chain_parent_id 显式指定同宗地版本链前驱；缺省为当前有效版本。
      分叉时由调用方给出新链的锚点版本，构成可独立验真的平行哈希链；
    * vid 允许调用方预生成（更正发布需先确定新/旧版本 id 映射再传导）。
    """
    ring = geo.norm_ring(ring)
    nxt = conn.execute(
        "SELECT COALESCE(MAX(version_no),0)+1 FROM parcel_version WHERE parcel_id=?",
        (parcel_id,)).fetchone()[0]
    vid = vid or ids.new_id("PV")
    prev = current_version(conn, parcel_id)
    chain_parent = get_version(conn, chain_parent_id) if chain_parent_id else prev
    prev_hash = chain_parent["version_hash"] if chain_parent else None
    vh = version_hash(
        parcel_id=parcel_id, version_no=nxt, ring=ring, area=area,
        base_version_id=base_version_id, parent_hashes=parent_hashes or [],
        valid_from=ts, prev_hash=prev_hash, status=status)
    conn.execute(
        """INSERT INTO parcel_version
           (id,parcel_id,version_no,status,ring_json,area,declared_area,
            base_version_id,chain_parent_id,valid_from,valid_to,created_at,version_hash)
           VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (vid, parcel_id, nxt, status, json.dumps(ring), area, declared_area,
         base_version_id, chain_parent["id"] if chain_parent else None,
         ts, None, ts, vh))
    if supersede and prev:
        conn.execute(
            "UPDATE parcel_version SET valid_to=?, status=? WHERE id=? AND valid_to IS NULL",
            (ts, "SUPERSEDED", prev["id"]))
    v = get_version(conn, vid)
    return v


def link_version_points(conn, version_id: str, point_ids: list[str]):
    conn.execute("DELETE FROM version_point WHERE version_id=?", (version_id,))
    conn.executemany(
        "INSERT INTO version_point(version_id,point_id,ord) VALUES(?,?,?)",
        [(version_id, pid, i) for i, pid in enumerate(point_ids)])


def version_point_ids(conn, version_id: str) -> list[str]:
    rows = conn.execute(
        "SELECT point_id FROM version_point WHERE version_id=? ORDER BY ord",
        (version_id,)).fetchall()
    return [r["point_id"] for r in rows]


def active_neighbors(conn, exclude: set[str] | None = None) -> list[dict]:
    exclude = exclude or set()
    out = []
    for v in all_current(conn):
        if v["parcel_id"] not in exclude:
            out.append(v)
    return out


def verify_hash_chain(conn, parcel_id: str) -> list[str]:
    """重算全部版本哈希，返回不匹配的版本 id 列表（用于审计/自检）。

    支持历史更正产生的**分叉链**：每个版本的链前驱由 chain_parent_id 指向，
    按 version_no 排序保证前驱先于后继，每个版本独立重算 prev_hash 与父操作哈希。
    旧链与更正新链因此都可以各自完整验真。
    """
    broken = []
    for v in list_versions(conn, parcel_id):
        prev = get_version(conn, v["chain_parent_id"]) if v.get("chain_parent_id") else None
        expect = version_hash(
            parcel_id=v["parcel_id"], version_no=v["version_no"], ring=v["ring"],
            area=v["area"], base_version_id=v["base_version_id"],
            parent_hashes=_parent_hashes(conn, v["id"]),
            valid_from=v["valid_from"],
            prev_hash=prev["version_hash"] if prev else None, status=v["status"])
        if expect != v["version_hash"]:
            broken.append(v["id"])
    return broken


def _parent_hashes(conn, version_id: str) -> list[str]:
    v = conn.execute("SELECT parcel_id FROM parcel_version WHERE id=?",
                     (version_id,)).fetchone()
    pid = v["parcel_id"] if v else None
    for op in conn.execute("SELECT parent_versions, child_versions, type FROM parcel_op"):
        # CORRECTION_PUBLISH 仅作更正发布的血缘汇总注解，不进入逐版本哈希链
        # （目标版本的分叉关系由 chain_parent_id 承载；下游重放由
        # CORRECTION_REPLAY 承载），否则会把新链父哈希错误计入旧版本。
        if op["type"] == "CORRECTION_PUBLISH":
            continue
        children = _jloads(op["child_versions"])
        if version_id not in children:
            continue
        parents = _jloads(op["parent_versions"])
        # 跨宗地操作：
        #  * ADJUDICATION：只取同一宗地的父版本入哈希（另一宗为邻接宗地，
        #    其哈希由各自宗地链绑定，不重复计入）；
        #  * CORRECTION_REPLAY：保留全部父哈希——分割/合并后代的几何完全
        #    由（可能跨宗地的）更正后父版本决定，必须绑定其哈希。
        if pid and op["type"] == "ADJUDICATION":
            parents = [p for p in parents
                       if conn.execute("SELECT parcel_id FROM parcel_version WHERE id=?",
                                       (p,)).fetchone()["parcel_id"] == pid]
        return [_hash_of(conn, p) for p in parents]
    return []


def _hash_of(conn, vid: str) -> str:
    r = conn.execute("SELECT version_hash FROM parcel_version WHERE id=?",
                     (vid,)).fetchone()
    return r["version_hash"] if r else ""
