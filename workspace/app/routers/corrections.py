"""二阶段历史更正接口：草案（预演）→ 发布（原子分叉）/ 撤销。"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException

from ..db import tx, get_conn
from ..schemas import CorrectionDraftIn, CorrectionPublishIn
from ..services import corrections as cr

router = APIRouter(prefix="/api/correction-drafts", tags=["correction-drafts"])


@router.post("")
def create_draft(body: CorrectionDraftIn):
    """建立更正草案并立即预演（不产生任何版本，不改变在版宗地）。"""
    try:
        with tx() as conn:
            return cr.create_draft(conn, body.model_dump())
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.get("")
def list_drafts(status: str | None = None):
    conn = get_conn()
    try:
        return cr.list_drafts(conn, status)
    finally:
        conn.close()


@router.get("/{draft_id}")
def get_draft(draft_id: str):
    conn = get_conn()
    try:
        d = cr.get_draft(conn, draft_id)
        if not d:
            raise HTTPException(404, "草案不存在")
        # 附带实时漂移状态（不改动草案；正式漂移判定在发布时原子完成）
        if d["status"] in ("OPEN", "DRIFTED") and d.get("fingerprint"):
            live_fp = cr.fingerprint(conn, d["preview"])
            d["live_drift"] = cr.diff_fingerprint(
                conn, d["fingerprint"], live_fp, {})
        else:
            d["live_drift"] = []
        return d
    finally:
        conn.close()


@router.post("/{draft_id}/rehearse")
def re_rehearse(draft_id: str):
    """漂移后重新预演：刷新受影响后代的新几何/面积差/血缘与指纹。"""
    try:
        with tx() as conn:
            return cr.re_rehearse(conn, draft_id)
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.post("/{draft_id}/publish")
def publish(draft_id: str, body: CorrectionPublishIn | None = None):
    """原子发布；基线漂移则返回 status=DRIFTED 且不写任何版本。

    同一草案/同一 idem_key 的重复提交返回首次发布结果。
    """
    payload = body.model_dump() if body else {}
    payload["draft_id"] = draft_id
    try:
        with tx() as conn:
            return cr.publish(conn, payload)
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.post("/{draft_id}/cancel")
def cancel(draft_id: str):
    """撤销草案；草案从未产生版本，故无半成品残留。"""
    try:
        with tx() as conn:
            return cr.cancel(conn, draft_id)
    except ValueError as e:
        raise HTTPException(400, str(e))
