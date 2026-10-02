"""地籍证明签发与验证。

证明绑定的是**签发那一刻的版本哈希**；即便宗地日后被分割/合并/更正，
版本行及其哈希链不变，历史证明始终可以离线验真。
"""
from __future__ import annotations

import json

from .. import config
from . import ids
from .ids import as_of
from .crypto import canonical, sign_document, verify_signature
from . import versions as vs


def issue(conn, version_id: str, ts: str | None = None) -> dict:
    ts = as_of(ts)
    v = vs.get_version(conn, version_id)
    if not v:
        raise ValueError("版本不存在")
    p = conn.execute("SELECT label FROM parcel WHERE id=?", (v["parcel_id"],)).fetchone()
    year = ts[:4]
    seq = conn.execute(
        "SELECT COUNT(*)+1 FROM certificate WHERE id LIKE ?",
        (f"CERT-{year}-%",)).fetchone()[0]
    cert_id = f"CERT-{year}-{seq:04d}"

    document = {
        "cert_id": cert_id,
        "issuer": config.CERT_ISSUER,
        "issued_at": ts,
        "parcel_id": v["parcel_id"],
        "parcel_label": p["label"] if p else v["parcel_id"],
        "version_id": v["id"],
        "version_no": v["version_no"],
        "area": v["area"],
        "ring": v["ring"],
        "valid_from": v["valid_from"],
        "version_hash": v["version_hash"],
    }
    sig = sign_document(document)
    conn.execute(
        """INSERT INTO certificate(id,version_id,parcel_id,area,issued_at,
           document_json,signature) VALUES(?,?,?,?,?,?,?)""",
        (cert_id, v["id"], v["parcel_id"], v["area"], ts,
         json.dumps(document, ensure_ascii=False), sig))
    return {"cert_id": cert_id, "document": document, "signature": sig}


def get_certificate(conn, cert_id: str) -> dict | None:
    r = conn.execute("SELECT * FROM certificate WHERE id=?", (cert_id,)).fetchone()
    if not r:
        return None
    doc = json.loads(r["document_json"])
    return {"cert_id": r["id"], "document": doc, "signature": r["signature"],
            "revoked": bool(r["revoked"])}


def list_certificates(conn):
    rows = conn.execute(
        "SELECT id,version_id,parcel_id,area,issued_at,revoked FROM certificate ORDER BY issued_at").fetchall()
    return [dict(r) for r in rows]


def verify(conn, cert_id: str) -> dict:
    c = get_certificate(conn, cert_id)
    if not c:
        return {"valid": False, "reason": "CERT_NOT_FOUND", "cert_id": cert_id}
    sig_ok = verify_signature(c["document"], c["signature"])
    v = vs.get_version(conn, c["document"]["version_id"])
    version_ok = bool(v) and v["version_hash"] == c["document"]["version_hash"]
    ring_ok = bool(v) and c["document"]["ring"] == v["ring"] and \
        abs(c["document"]["area"] - v["area"]) < 1e-6

    # 重新独立计算版本哈希链，证明版本未被库内篡改
    chain_broken = vs.verify_hash_chain(conn, c["document"]["parcel_id"]) if v else ["missing"]

    return {
        "valid": sig_ok and version_ok and ring_ok and not chain_broken,
        "cert_id": cert_id,
        "checks": {
            "signature": sig_ok,
            "version_hash_match": version_ok,
            "ring_area_match": ring_ok,
            "hash_chain_intact": not chain_broken,
            "not_revoked": not c["revoked"],
        },
        "document": c["document"],
        "note": ("历史证明：宗地当前状态可能已变化，但本证明仍真实绑定于签发时版本"
                 if v and v["valid_to"] else "该版本仍为当前有效版本"),
    }
