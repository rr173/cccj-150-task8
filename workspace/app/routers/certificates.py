"""证明签发与验真接口。"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException

from ..db import tx, get_conn
from ..schemas import IssueCertIn
from ..services import certificates as cert_svc

router = APIRouter(prefix="/api/certificates", tags=["certificates"])


@router.post("")
def issue(body: IssueCertIn):
    try:
        with tx() as conn:
            return cert_svc.issue(conn, body.version_id, body.as_of)
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.get("")
def list_certs():
    conn = get_conn()
    try:
        return cert_svc.list_certificates(conn)
    finally:
        conn.close()


@router.get("/{cert_id}")
def get_cert(cert_id: str):
    conn = get_conn()
    try:
        c = cert_svc.get_certificate(conn, cert_id)
        if not c:
            raise HTTPException(404, "证明不存在")
        return c
    finally:
        conn.close()


@router.get("/{cert_id}/verify")
def verify_cert(cert_id: str):
    conn = get_conn()
    try:
        return cert_svc.verify(conn, cert_id)
    finally:
        conn.close()
