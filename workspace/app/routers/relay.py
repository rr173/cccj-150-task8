"""交换包交付回执中继 —— HTTP API。"""
from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from ..services.ids import now_iso
from ..relay import service, crypto, trust as trust_svc
from ..relay import demo as demo_svc
from ..relay.store import init_relay_db
from ..relay.verifier import (
    verify_receipt_package, verify_trust_package, ReceiptError)

router = APIRouter(prefix="/api/relay", tags=["relay"])


def _err(exc: service.RelayError) -> JSONResponse:
    payload = {"error": exc.code, "message": str(exc)}
    payload.update(exc.extra)
    return JSONResponse(payload, status_code=exc.status)


def _trust_err(exc: trust_svc.TrustError) -> JSONResponse:
    payload = {"error": exc.code, "message": str(exc)}
    payload.update(exc.extra)
    return JSONResponse(payload, status_code=exc.status)


@router.get("/health")
def health():
    return {"ok": True, "service": "delivery-receipt-relay"}


# ---- 机构密钥（演示/部署引导） ------------------------------------------

@router.post("/institutions")
def create_institution(body: dict):
    code = body.get("institution_code")
    if not code:
        return JSONResponse({"error": "BAD_REQUEST",
                             "message": "institution_code 必填"}, 400)
    try:
        result = crypto.create_institution_keys(
            code, overwrite=bool(body.get("overwrite")))
        trust_svc.init_institution_state(code, body.get("title"))
        return result
    except (crypto.KeyExistsError, trust_svc.TrustError) as exc:
        if isinstance(exc, trust_svc.TrustError):
            return _trust_err(exc)
        return _err(service.RelayError(str(exc), "INSTITUTION_EXISTS", 409))


# ---- 机构密钥轮换 / 撤销 / 信任包 -----------------------------------------

@router.get("/institutions/{code}/trust")
def institution_trust(code: str):
    try:
        return trust_svc.institution_trust_status(code)
    except trust_svc.TrustError as e:
        return _trust_err(e)


@router.post("/institutions/{code}/rotations/preview")
def rotation_preview(code: str, body: dict | None = None):
    body = body or {}
    try:
        return trust_svc.rotation_preview(
            code, effective_watermark=body["effective_watermark"],
            public_key=body.get("public_key"))
    except trust_svc.TrustError as e:
        return _trust_err(e)
    except KeyError as e:
        return JSONResponse({"error": "BAD_REQUEST",
                             "message": f"缺少字段: {e}"}, 400)


@router.post("/institutions/{code}/rotations")
def register_rotation(code: str, body: dict):
    try:
        return trust_svc.register_rotation(
            institution_code=code, request_key=body["request_key"],
            effective_watermark=body["effective_watermark"],
            public_key=body.get("public_key"),
            new_key_self_signature=body.get("new_key_self_signature"),
            registered_by=body.get("registered_by"),
            title=body.get("title"))
    except trust_svc.TrustError as e:
        return _trust_err(e)
    except KeyError as e:
        return JSONResponse({"error": "BAD_REQUEST",
                             "message": f"缺少字段: {e}"}, 400)


@router.post("/institutions/{code}/rotations/{key_seq}/approve")
def approve_rotation(code: str, key_seq: int, body: dict):
    try:
        return trust_svc.approve_rotation(
            institution_code=code, key_seq=key_seq,
            approver=body.get("approver", "admin"),
            request_key=body["request_key"])
    except trust_svc.TrustError as e:
        return _trust_err(e)
    except KeyError as e:
        return JSONResponse({"error": "BAD_REQUEST",
                             "message": f"缺少字段: {e}"}, 400)


@router.post("/institutions/{code}/rotations/{key_seq}/activate")
def activate_rotation(code: str, key_seq: int, body: dict | None = None):
    body = body or {}
    try:
        return trust_svc.activate_rotation(
            institution_code=code, key_seq=key_seq,
            request_key=body.get("request_key"), actor=body.get("actor"))
    except trust_svc.TrustError as e:
        return _trust_err(e)


@router.post("/institutions/{code}/revocations")
def publish_revocation(code: str, body: dict):
    try:
        return trust_svc.publish_revocation(
            institution_code=code, request_key=body["request_key"],
            receipt_ids=body.get("receipt_ids"),
            issued_from=body.get("issued_from"),
            issued_to=body.get("issued_to"),
            reason=body.get("reason", "REVOKED"),
            published_by=body.get("published_by"))
    except trust_svc.TrustError as e:
        return _trust_err(e)
    except KeyError as e:
        return JSONResponse({"error": "BAD_REQUEST",
                             "message": f"缺少字段: {e}"}, 400)


@router.get("/institutions/{code}/receipts/{receipt_id}/status")
def receipt_status(code: str, receipt_id: str, at: str | None = None):
    try:
        return trust_svc.receipt_status(code, receipt_id, at)
    except trust_svc.TrustError as e:
        return _trust_err(e)


@router.post("/institutions/{code}/trust-packages")
def export_trust(code: str, body: dict):
    try:
        return trust_svc.export_trust_package(
            institution_code=code, request_key=body["request_key"],
            ttl_seconds=body.get("ttl_seconds"),
            issued_by=body.get("issued_by"))
    except trust_svc.TrustError as e:
        return _trust_err(e)
    except KeyError as e:
        return JSONResponse({"error": "BAD_REQUEST",
                             "message": f"缺少字段: {e}"}, 400)


@router.post("/trust-packages/verify")
def verify_trust(body: dict, at: str | None = None):
    package = body.get("package", body)
    try:
        return verify_trust_package(package, now=at,
                                    min_trust_version=body.get("min_trust_version"))
    except ReceiptError as e:
        return JSONResponse(
            {"valid": False, "code": e.code, "message": str(e),
             "problems": e.problems}, 422)


@router.post("/trust-packages/import")
def import_trust(body: dict):
    package = body.get("package", body)
    try:
        return trust_svc.import_trust_package(
            package, request_key=body.get("request_key"), at=body.get("at"))
    except trust_svc.TrustError as e:
        return _trust_err(e)

# ---- 发送方 -------------------------------------------------------------

@router.post("/senders")
def register_sender(body: dict):
    try:
        return service.register_sender(
            body["sender_id"], body["public_key"], body.get("title"))
    except service.RelayError as e:
        return _err(e)
    except KeyError as e:
        return JSONResponse({"error": "BAD_REQUEST",
                             "message": f"缺少字段: {e}"}, 400)


@router.get("/sessions")
def list_sessions(sender_id: str | None = None):
    return {"sessions": service.list_sessions(sender_id)}


@router.get("/sessions/{sender_id}/{session_id}")
def session_detail(sender_id: str, session_id: str):
    try:
        return service.session_detail(sender_id, session_id)
    except service.RelayError as e:
        return _err(e)


# ---- 事件推送（乱序/重复/批量重放） --------------------------------------

@router.post("/events/{sender_id}")
def push_events(sender_id: str, body: dict):
    try:
        return service.push_events(
            sender_id, body.get("events", []),
            batch_id=body.get("batch_id"))
    except service.RelayError as e:
        return _err(e)


@router.post("/sessions/{sender_id}/{session_id}/release-quarantine")
def release_quarantine(sender_id: str, session_id: str, body: dict | None = None):
    body = body or {}
    try:
        return service.release_quarantine(
            sender_id, session_id, body.get("note"),
            discard_event_hashes=body.get("discard_event_hashes"))
    except service.RelayError as e:
        return _err(e)


# ---- 工作实例领取租约 ----------------------------------------------------

@router.post("/claim")
def claim(body: dict):
    try:
        return service.claim_session(
            body["session_id"], body["worker_id"],
            body.get("sender_id"), ttl=body.get("ttl_seconds"))
    except service.RelayError as e:
        return _err(e)
    except KeyError as e:
        return JSONResponse({"error": "BAD_REQUEST",
                             "message": f"缺少字段: {e}"}, 400)


@router.post("/release-lease")
def release_lease(body: dict):
    try:
        return service.release_session_lease(
            body["session_id"], body["worker_id"], body.get("sender_id"))
    except KeyError as e:
        return JSONResponse({"error": "BAD_REQUEST",
                             "message": f"缺少字段: {e}"}, 400)


# ---- 回执导出 / 列表 / 上传核验 ------------------------------------------

@router.post("/receipts")
def export_receipt(body: dict):
    try:
        return service.export_receipt(
            request_key=body["request_key"],
            institution_code=body["institution_code"],
            sender_id=body["sender_id"],
            institution_title=body.get("institution_title"),
            ttl_seconds=body.get("ttl_seconds"),
            session_ids=body.get("session_ids"))
    except service.RelayError as e:
        return _err(e)
    except crypto.KeyExistsError:
        return JSONResponse({"error": "INSTITUTION_KEY_MISSING",
                             "message": "机构密钥未初始化"}, 409)
    except FileNotFoundError:
        return JSONResponse({"error": "INSTITUTION_KEY_MISSING",
                             "message": "机构密钥未初始化"}, 409)
    except KeyError as e:
        return JSONResponse({"error": "BAD_REQUEST",
                             "message": f"缺少字段: {e}"}, 400)


@router.get("/receipts")
def list_receipts(sender_id: str | None = None):
    return {"receipts": service.list_receipts(sender_id)}


@router.post("/receipts/verify")
def verify_uploaded_receipt(body: dict, at: str | None = None):
    """上传一个回执包做在线/离线核验（也可用独立核验器命令行）。"""
    package = body.get("package", body)
    try:
        return verify_receipt_package(
            package, now=at, min_watermark=body.get("min_watermark"),
            trust_package=body.get("trust_package"))
    except ReceiptError as e:
        return JSONResponse(
            {"valid": False, "code": e.code, "message": str(e),
             "problems": e.problems}, 422)


# ---- 清理授权 -----------------------------------------------------------

@router.post("/cleanup-authorization")
def cleanup_authorization(body: dict):
    package = body.get("package")
    if package is None:
        return JSONResponse({"error": "BAD_REQUEST",
                             "message": "package 必填"}, 400)
    return service.authorize_cleanup(
        package=package, local_events=body.get("local_events", []),
        at=body.get("at"))


# ---- 网页演示端点（持有演示发送方私钥、本地签名后走同一推送管线）-----------
# 生产环境不应暴露；仅供零外部依赖的浏览器界面联调使用。

@router.post("/demo/ensure")
def demo_ensure(body: dict | None = None):
    body = body or {}
    ctx = demo_svc.ensure_demo_sender(body.get("sender_id", demo_svc.HAPPY_SENDER))
    return {"sender_id": ctx["sender_id"], "public_key": ctx["public_key"],
            "institution": demo_svc.DEMO_INSTITUTION}


@router.post("/demo/happy-init")
def demo_happy_init(body: dict | None = None):
    body = body or {}
    return demo_svc.happy_init(body.get("sender_id", demo_svc.HAPPY_SENDER),
                               body.get("session_id", demo_svc.HAPPY_SESSION))


@router.post("/demo/happy-fill-gap")
def demo_happy_fill_gap(body: dict | None = None):
    body = body or {}
    return demo_svc.happy_fill_gap(
        body.get("revision", 2), body.get("sender_id", demo_svc.HAPPY_SENDER),
        body.get("session_id", demo_svc.HAPPY_SESSION))


@router.post("/demo/happy-finish")
def demo_happy_finish(body: dict | None = None):
    body = body or {}
    return demo_svc.happy_finish(body.get("sender_id", demo_svc.HAPPY_SENDER),
                                 body.get("session_id", demo_svc.HAPPY_SESSION))


@router.post("/demo/conflict-init")
def demo_conflict_init(body: dict | None = None):
    body = body or {}
    return demo_svc.conflict_init(body.get("sender_id", demo_svc.HAPPY_SENDER),
                                  body.get("session_id", demo_svc.CONFLICT_SESSION))


@router.post("/demo/conflict-recover")
def demo_conflict_recover(body: dict | None = None):
    body = body or {}
    return demo_svc.conflict_recover(
        body.get("sender_id", demo_svc.HAPPY_SENDER),
        body.get("session_id", demo_svc.CONFLICT_SESSION))


@router.post("/demo/signed-push")
def demo_signed_push(body: dict):
    try:
        return demo_svc.signed_push(
            sender_id=body.get("sender_id", demo_svc.HAPPY_SENDER),
            session_id=body["session_id"], revision=int(body["revision"]),
            event_type=body["event_type"],
            session_version=int(body.get("session_version", 1)),
            state=body.get("state", "UPLOADING"),
            prev=body.get("prev", "auto"),
            occurred_at=body.get("occurred_at", now_iso()),
            detail=body.get("detail"), batch_id=body.get("batch_id"))
    except service.RelayError as e:
        return _err(e)
    except (KeyError, TypeError, ValueError) as e:
        return JSONResponse({"error": "BAD_REQUEST", "message": str(e)}, 400)
