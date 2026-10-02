"""离线同步接口：作业单/bundle、照片上传、候选提交（含预校验）。"""
from __future__ import annotations

import json
from fastapi import APIRouter, HTTPException, UploadFile, File, Form

from ..db import tx, get_conn
from ..schemas import SubmissionIn
from ..services import sync as sync_svc
from ..services import validation as val
from ..services import versions as vs

router = APIRouter(prefix="/api/sync", tags=["sync"])


@router.post("/bundle")
def bundle(body: dict):
    """设备回网/出工前下载作业底图与基线版本（离线包）。"""
    parcel_ids = body.get("parcel_ids") or []
    device_id = body.get("device_id", "device-1")
    with tx() as conn:
        j = sync_svc.create_job(
            conn, device_id=device_id, surveyor=body.get("surveyor"),
            parcel_ids=parcel_ids)
    return j


@router.get("/jobs/{job_id}")
def job_status(job_id: str):
    conn = get_conn()
    try:
        j = sync_svc.get_job(conn, job_id)
        if not j:
            raise HTTPException(404, "作业单不存在")
        j["disputes"] = sync_svc.list_open_disputes(conn) if j["status"] == "DISPUTED" else []
        return j
    finally:
        conn.close()


@router.post("/jobs/{job_id}/media")
async def upload_media(job_id: str, file: UploadFile = File(...),
                       point_ref: str | None = Form(None)):
    raw = await file.read()
    with tx() as conn:
        if not sync_svc.get_job(conn, job_id):
            raise HTTPException(404, "作业单不存在")
        mid = sync_svc.save_media(
            conn, job_id=job_id, filename=file.filename or "photo.jpg",
            raw=raw, mime=file.content_type, point_ref=point_ref)
    return {"media_id": mid, "size": len(raw)}


@router.get("/media/{media_id}")
def media(media_id: str):
    from fastapi.responses import FileResponse
    conn = get_conn()
    try:
        r = conn.execute("SELECT filename,mime FROM media WHERE id=?",
                         (media_id,)).fetchone()
    finally:
        conn.close()
    if not r:
        raise HTTPException(404)
    from .. import config
    return FileResponse(config.MEDIA_DIR / r["filename"], media_type=r["mime"])


@router.post("/validate")
def validate_only(body: SubmissionIn):
    """只校验不入库：设备端在弱网/提交前预检。"""
    conn = get_conn()
    try:
        errors, normals = val.validate_submission(
            conn, [c.model_dump() for c in body.candidates],
            [c.model_dump() for c in body.confirmations],
            body.base_version_map or None)
        return {"valid": not errors, "errors": errors,
                "normalized": [{"parcel_id": n["parcel_id"], "label": n["label"],
                                "area": n["area"], "ring": n["ring"]}
                               for n in normals]}
    finally:
        conn.close()


@router.post("/submit")
def submit(body: SubmissionIn):
    """提交候选边界（幂等：相同 idem_key 重放返回同一结果）。"""
    try:
        with tx() as conn:
            return sync_svc.submit(conn, body.model_dump())
    except ValueError as e:
        raise HTTPException(400, str(e))
