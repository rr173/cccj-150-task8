"""分割 / 合并 / 历史更正接口。"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException

from ..db import tx
from ..schemas import SplitIn, MergeIn, CorrectionIn
from ..services import lifecycle

router = APIRouter(prefix="/api/ops", tags=["lifecycle"])


@router.post("/split")
def split(body: SplitIn):
    try:
        with tx() as conn:
            return lifecycle.split(conn, body.model_dump())
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.post("/merge")
def merge(body: MergeIn):
    try:
        with tx() as conn:
            return lifecycle.merge(conn, body.model_dump())
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.post("/correction")
def correction(body: CorrectionIn):
    try:
        with tx() as conn:
            return lifecycle.correct(conn, body.model_dump())
    except ValueError as e:
        raise HTTPException(400, str(e))
