"""宗地、版本、时间点查询、地图数据接口。"""
from __future__ import annotations

import json
from fastapi import APIRouter, HTTPException, Query

from ..db import get_conn
from ..services import versions as vs
from ..services import certificates as cert_svc

router = APIRouter(prefix="/api", tags=["parcels"])


@router.get("/parcels")
def parcels():
    conn = get_conn()
    try:
        out = []
        for p in vs.list_parcels(conn):
            cur = vs.current_version(conn, p["id"])
            out.append({**p, "current": cur})
        return out
    finally:
        conn.close()


@router.get("/parcels/{pid}/versions")
def versions(pid: str):
    conn = get_conn()
    try:
        return vs.list_versions(conn, pid)
    finally:
        conn.close()


@router.get("/parcels/{pid}")
def parcel_at(pid: str, at: str | None = Query(None, description="ISO 时间点；省略=当前")):
    conn = get_conn()
    try:
        v = vs.version_at(conn, pid, at) if at else vs.current_version(conn, pid)
        if not v:
            raise HTTPException(404, "该时点无有效版本")
        ops = []
        for r in conn.execute("SELECT * FROM parcel_op ORDER BY created_at"):
            parents = json.loads(r["parent_versions"])
            children = json.loads(r["child_versions"])
            if v["id"] in parents or v["id"] in children:
                ops.append({"id": r["id"], "type": r["type"],
                            "parents": parents, "children": children,
                            "at": r["created_at"]})
        return {"version": v, "lineage": ops}
    finally:
        conn.close()


@router.get("/at/{ts}")
def snapshot(ts: str):
    """时间点地籍快照：所有在该时点有效的宗地版本。"""
    conn = get_conn()
    try:
        rows = conn.execute(
            "SELECT * FROM parcel_version WHERE valid_from<=? "
            "AND (valid_to IS NULL OR valid_to>?) ORDER BY parcel_id",
            (ts, ts)).fetchall()
        return [vs._vrow(r) for r in rows]
    finally:
        conn.close()


@router.get("/map")
def map_data():
    """地图编辑器一次拉取：当前宗地、界址点、未决争议、证明清单。"""
    from ..services import sync as sync_svc
    conn = get_conn()
    try:
        parcels = []
        for p in vs.list_parcels(conn):
            cur = vs.current_version(conn, p["id"])
            versions_rows = vs.list_versions(conn, p["id"])
            parcels.append({
                "id": p["id"], "label": p["label"],
                "current": cur,
                "versions": [
                    {"id": v["id"], "version_no": v["version_no"], "status": v["status"],
                     "valid_from": v["valid_from"], "valid_to": v["valid_to"],
                     "area": v["area"]} for v in versions_rows],
            })
        drafts = [dict(r) for r in conn.execute(
            "SELECT id,target_version_id,reason,status,created_at,previewed_at,"
            "published_at,cancelled_at FROM correction_draft "
            "WHERE status IN ('OPEN','DRIFTED') ORDER BY created_at").fetchall()]
        effect_plans = []
        for r in conn.execute(
                "SELECT * FROM effect_plan "
                "WHERE status IN ('WAITING','PAUSED') ORDER BY execute_at").fetchall():
            pids = json.loads(r["parcels_json"])
            labels = {row["id"]: row["label"]
                      for row in conn.execute("SELECT id,label FROM parcel").fetchall()}
            effect_plans.append({
                "id": r["id"], "draft_id": r["draft_id"], "request_key": r["request_key"],
                "status": r["status"], "execute_at": r["execute_at"],
                "registered_at": r["registered_at"], "pause_reason": r["pause_reason"],
                "occupancy": [{"parcel_id": q, "label": labels.get(q)} for q in pids]})
        return {
            "parcels": parcels,
            "points": [dict(r) for r in conn.execute("SELECT * FROM point")],
            "disputes": sync_svc.list_open_disputes(conn),
            "certificates": cert_svc.list_certificates(conn),
            "correction_drafts": drafts,
            "effect_plans": effect_plans,
        }
    finally:
        conn.close()


@router.get("/ops")
def ops():
    conn = get_conn()
    try:
        rows = conn.execute("SELECT * FROM parcel_op ORDER BY created_at").fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["parent_versions"] = json.loads(d["parent_versions"])
            d["child_versions"] = json.loads(d["child_versions"])
            d["params_json"] = json.loads(d["params_json"])
            d["area_note"] = json.loads(d["area_note"]) if d["area_note"] else None
            out.append(d)
        return out
    finally:
        conn.close()
