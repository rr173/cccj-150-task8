"""版本哈希链与证明签章。"""
from __future__ import annotations

import hashlib
import hmac
import json

from .. import config


def canonical(obj) -> str:
    """排序键、紧凑分隔的确定性 JSON。"""
    return json.dumps(obj, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), default=str)


def version_hash(*, parcel_id: str, version_no: int, ring, area: float,
                 base_version_id: str | None, parent_hashes: list[str],
                 valid_from: str, prev_hash: str | None, status: str) -> str:
    # 注意：status 会随合法生命周期流转（COMMITTED→SUPERSEDED/ANNULLED），
    # 不属于"不可变内容"，故**不计入哈希**；哈希只绑定几何/面积/血缘/生效时间。
    payload = {
        "parcel_id": parcel_id,
        "version_no": version_no,
        "ring": ring,
        "area": round(float(area), 6),
        "base_version_id": base_version_id,
        "parent_hashes": parent_hashes,
        "valid_from": valid_from,
        "prev_hash": prev_hash,
    }
    return hashlib.sha256(canonical(payload).encode("utf-8")).hexdigest()


def sign_document(document: dict) -> str:
    return hmac.new(config.CERT_KEY.encode("utf-8"),
                    canonical(document).encode("utf-8"),
                    hashlib.sha256).hexdigest()


def verify_signature(document: dict, signature: str) -> bool:
    expect = sign_document(document)
    return hmac.compare_digest(expect, signature)
