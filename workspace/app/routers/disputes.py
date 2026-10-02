"""争议查询与裁定接口。"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException

from ..db import tx, get_conn
from ..schemas import AdjudicationItemIn, Ok
from ..services import sync as sync_svc
from ..services import adjudication as adj
from ..services import versions as vs
import json

router = APIRouter(prefix="/api/disputes", tags=["disputes"])


@router.get("")
def list_disputes(include_resolved: bool = False):
    conn = get_conn()
    try:
        if include_resolved:
            rows = conn.execute("SELECT id FROM dispute ORDER BY created_at").fetchall()
            return [sync_svc.get_dispute(conn, r["id"]) for r in rows]
        return sync_svc.list_open_disputes(conn)
    finally:
        conn.close()


@router.get("/{did}")
def dispute_detail(did: str):
    conn = get_conn()
    try:
        d = sync_svc.get_dispute(conn, did)
        if not d:
            raise HTTPException(404, "争议不存在")
        # 附带双方候选环与当前环，供前端叠加对比
        out = dict(d)
        for key, cid in (("a", d["cand_a"]), ("b", d["cand_b"])):
            r = conn.execute(
                "SELECT c.*, j.surveyor, j.device_id FROM candidate c "
                "JOIN survey_job j ON j.id=c.job_id WHERE c.id=?", (cid,)).fetchone()
            if r:
                out[f"candidate_{key}"] = {
                    "id": r["id"], "job_id": r["job_id"],
                    "surveyor": r["surveyor"], "device_id": r["device_id"],
                    "label": r["label"],
                    "ring": json.loads(r["ring_json"]),
                }
        out["current_a"] = vs.current_version(conn, d["parcel_a"])
        return out
    finally:
        conn.close()


@router.post("/adjudicate")
def do_adjudicate(items: list[AdjudicationItemIn]):
    try:
        with tx() as conn:
            return adj.adjudicate(conn, [i.model_dump() for i in items])
    except ValueError as e:
        raise HTTPException(400, str(e))
