"""地籍快照交换包接口：导出 / 建导入会话（负责人+有效期）/ 分块上传（乱序/重复/续传，
仅当前负责人）/ 离线预检 / 终检一次性导入 / 会话查询 /
接收窗口管理（移交 / 续期 / 人工冻结 / 重新开启）/ 保留期清理 / 操作审计。"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, UploadFile, File, Form, Header

from ..db import tx, get_conn
from ..schemas import (
    SnapshotExportIn, SnapshotImportIn, SnapshotPrecheckIn,
    SnapshotHandoverIn, SnapshotRenewIn, SnapshotFreezeIn, SnapshotReopenIn,
    SnapshotFinalizeIn, SnapshotCleanupIn)
from ..services import snapshots as ss

router = APIRouter(prefix="/api/snapshots", tags=["snapshots"])


def _raise_session_error(e: ss.SessionError):
    """把会话服务异常映射为带可定位会话视图的 HTTP 错误。"""
    if isinstance(e, ss.ReplayedDecision):
        # 原操作标识的重放命中首次终局拒绝：原样回放首次拒绝响应（409 +
        # replayed=true），不再重新校验
        raise HTTPException(e.status_code, e.payload)
    raise HTTPException(e.status_code, {
        "message": e.message, "code": e.code,
        **({"reason": e.reason} if isinstance(e, ss.SessionFrozen) else {}),
        **({"conflicts": e.conflicts} if getattr(e, "conflicts", None) else {}),
        **({"session": e.session} if e.session else {})})


# ================================================================ 导出
@router.post("/export")
def export(body: SnapshotExportIn):
    """按时间点导出最小闭包离线交换包（清单 + 分块 base64）。"""
    try:
        with tx() as conn:
            pkg = ss.build_package(conn, body.model_dump())
    except ValueError as e:
        raise HTTPException(400, str(e))
    m = pkg["manifest"]
    return {
        "package_id": m["package_id"],
        "format": m["format"],
        "source_at": m["source_at"],
        "created_at": m["created_at"],
        "payload_sha256": m["payload_sha256"],
        "chunk_count": m["chunk_count"],
        "chunk_size": m["chunk_size"],
        "counts": m["counts"],
        "signature": m["signature"],
        "manifest": m,
        "chunks": pkg["chunks"],
    }


# ================================================================ 导入会话
@router.post("/imports")
def create_import(body: SnapshotImportIn):
    """凭清单创建上传会话；相同包标识+相同清单恢复原会话，不同内容 409。

    可指定负责人 owner 与接收窗口（valid_until / ttl_minutes）。
    """
    try:
        with tx() as conn:
            return ss.create_import(
                conn, body.manifest, body.created_by,
                owner=body.owner, valid_until=body.valid_until,
                ttl_minutes=body.ttl_minutes, as_of=body.as_of)
    except ss.PackageConflict as e:
        raise HTTPException(409, {"message": str(e), "conflicts": e.conflicts})
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.get("/imports")
def list_imports():
    with tx() as conn:
        return ss.list_sessions(conn)


@router.get("/imports/{package_id}")
def get_import(package_id: str):
    with tx() as conn:
        s = ss.session_detail(conn, package_id)
        if not s:
            raise HTTPException(404, "导入会话不存在")
        return s


@router.put("/imports/{package_id}/chunks/{seq}")
async def upload_chunk(package_id: str, seq: int,
                       file: UploadFile | None = File(None),
                       data: str | None = Form(None),
                       actor: str | None = Form(None),
                       x_cadastre_actor: str | None = Header(default=None),
                       as_of: str | None = Form(None)):
    """上传单个分块：可乱序、重复；同序号不同内容记冲突且不覆盖已收正确块。

    支持 multipart 文件（field=file）或 base64 表单字段（field=data）。
    仅**当前负责人**可上传（actor 表单字段或 X-Cadastre-Actor 头）；
    会话到期/冻结后拒绝写入（409），分块与冲突原样保留。
    """
    if file is not None:
        raw = await file.read()
    elif data is not None:
        try:
            raw = ss._b64decode(data)
        except Exception as e:  # noqa: BLE001
            raise HTTPException(400, f"分块 base64 无法解码: {e}")
    else:
        raise HTTPException(400, "需提供 file 文件或 data(base64) 字段")
    try:
        with tx() as conn:
            if not ss.get_session(conn, package_id):
                raise HTTPException(404, "导入会话不存在（请先用清单创建）")
            try:
                return ss.put_chunk(
                    conn, package_id, seq, raw,
                    actor=actor or x_cadastre_actor, as_of=as_of)
            except ValueError as e:
                raise HTTPException(400, str(e))
            except ss.SessionError as e:
                _raise_session_error(e)
    except HTTPException:
        raise


# ================================================================ 接收窗口管理（幂等 + 版本号）
@router.post("/imports/{package_id}/handover")
def handover(package_id: str, body: SnapshotHandoverIn):
    """负责人移交：必须携带 request_key（幂等）与 version（会话版本号防并发覆盖）。"""
    try:
        with tx() as conn:
            if not ss.get_session(conn, package_id):
                raise HTTPException(404, "导入会话不存在")
            try:
                return ss.handover(conn, package_id, body.model_dump())
            except ss.SessionError as e:
                _raise_session_error(e)
    except HTTPException:
        raise


@router.post("/imports/{package_id}/renew")
def renew(package_id: str, body: SnapshotRenewIn):
    """续期（延长接收窗口）：窗口开启期间、仅当前负责人；幂等请求键 + 版本号。"""
    try:
        with tx() as conn:
            if not ss.get_session(conn, package_id):
                raise HTTPException(404, "导入会话不存在")
            try:
                return ss.renew(conn, package_id, body.model_dump())
            except ss.SessionError as e:
                _raise_session_error(e)
    except HTTPException:
        raise


@router.post("/imports/{package_id}/freeze")
def freeze(package_id: str, body: SnapshotFreezeIn):
    """人工冻结：保留已验真分块、缺块与冲突，拒绝继续写入；幂等请求键 + 版本号。"""
    try:
        with tx() as conn:
            if not ss.get_session(conn, package_id):
                raise HTTPException(404, "导入会话不存在")
            try:
                return ss.manual_freeze(conn, package_id, body.model_dump())
            except ss.SessionError as e:
                _raise_session_error(e)
    except HTTPException:
        raise


@router.post("/imports/{package_id}/reopen")
def reopen(package_id: str, body: SnapshotReopenIn):
    """重新开启：重新核验清单与现存分块，失配保持冻结并返回可定位原因。"""
    try:
        with tx() as conn:
            if not ss.get_session(conn, package_id):
                raise HTTPException(404, "导入会话不存在")
            try:
                return ss.reopen(conn, package_id, body.model_dump())
            except ss.SessionError as e:
                _raise_session_error(e)
    except HTTPException:
        raise


@router.get("/imports/{package_id}/events")
def events(package_id: str):
    """会话操作审计（创建/移交/续期/冻结/重开/分块/终检/写入拒绝/清理）。"""
    conn = get_conn()
    try:
        if not ss.get_session(conn, package_id):
            raise HTTPException(404, "导入会话不存在")
        return ss.list_events(conn, package_id)
    finally:
        conn.close()


@router.post("/imports-cleanup")
def cleanup(body: SnapshotCleanupIn):
    """保留期清理：只清理冻结超过保留期且从未导入的会话；已导入永不清理。"""
    try:
        with tx() as conn:
            return ss.cleanup_expired(
                conn, retention_days=body.retention_days, as_of=body.as_of)
    except ValueError as e:
        raise HTTPException(400, str(e))


# ================================================================ 离线预检
@router.post("/precheck")
def precheck(body: SnapshotPrecheckIn):
    """接收方预检：无分块时只做清单结构核验；带分块做完整离线核验；
    local=false 时完全不接触本地数据库（纯无网络环境预检）。"""
    conn = get_conn()
    try:
        return ss.precheck(conn, body.manifest, body.chunks or None, body.local)
    except ValueError as e:
        raise HTTPException(400, str(e))
    finally:
        conn.close()


@router.post("/imports/{package_id}/finalize")
def finalize(package_id: str, body: SnapshotFinalizeIn | None = None,
             x_cadastre_actor: str | None = Header(default=None)):
    """终检并一次性导入：全部分块与引用关系都匹配才落库；冲突返回可定位明细，
    数据库保持原样。仅当前负责人可终检（body.actor 或 X-Cadastre-Actor 头）；
    到期/冻结拒绝。相同包标识再次导入返回首次结果（已导入重放无需负责人）。"""
    body = body or SnapshotFinalizeIn()
    with tx() as conn:
        if not ss.get_session(conn, package_id):
            raise HTTPException(404, "导入会话不存在")
        try:
            return ss.finalize(conn, package_id,
                               actor=body.actor or x_cadastre_actor,
                               as_of=body.as_of)
        except ss.SessionError as e:
            _raise_session_error(e)
