"""生效计划接口：登记未来执行 / 占用冲突清单 / 改期 / 取消 / 暂停恢复。"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException

from ..db import tx, get_conn
from ..schemas import PlanRegisterIn, PlanRescheduleIn
from ..services import plans as ps

router = APIRouter(prefix="/api/effect-plans", tags=["effect-plans"])


@router.post("")
def register(body: PlanRegisterIn):
    """登记生效计划：为全部目标地块建立互斥占用。

    同一 request_key 在计划生效期间只生成一条（重复请求幂等返回）；
    任何占用交集返回 status=CONFLICT 与冲突清单（不建立占用）。
    """
    try:
        with tx() as conn:
            return ps.register_plan(conn, body.model_dump())
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.get("")
def list_plans(status: str | None = None):
    conn = get_conn()
    try:
        return ps.list_plans(conn, status)
    finally:
        conn.close()


@router.get("/{plan_id}")
def get_plan(plan_id: str):
    conn = get_conn()
    try:
        p = ps.get_plan(conn, plan_id)
        if not p:
            raise HTTPException(404, "生效计划不存在")
        return ps.public_detail(conn, p, live_drift=True)
    finally:
        conn.close()


@router.post("/{plan_id}/reschedule")
def reschedule(plan_id: str, body: PlanRescheduleIn):
    """改期（WAITING/PAUSED 均可；PAUSED 改期后仍暂停，需先恢复基线）。"""
    try:
        with tx() as conn:
            return ps.reschedule(conn, plan_id, body.model_dump())
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.post("/{plan_id}/cancel")
def cancel(plan_id: str):
    """取消计划并释放全部地块占用；request_key 随之释放，可重新登记。"""
    try:
        with tx() as conn:
            return ps.cancel(conn, plan_id)
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.post("/{plan_id}/resume")
def resume(plan_id: str):
    """暂停后刷新基线（重新预演）：无冲突且仍 releasable → 回等待；否则保持暂停。"""
    try:
        with tx() as conn:
            return ps.resume(conn, plan_id)
    except ValueError as e:
        raise HTTPException(400, str(e))
