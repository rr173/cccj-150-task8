"""中继加密层：规范化哈希、事件哈希链、发送方签章、机构回执签章。"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from . import config, ed25519

# 事件进入哈希/签名的字段（event_hash 与 sender_signature 不在其中）。
EVENT_HASH_FIELDS = (
    "sender_id", "session_id", "revision", "event_type",
    "session_version", "state", "prev_event_hash", "occurred_at", "detail",
)

RECEIPT_FORMAT = "relay-receipt/v1"
TRUST_FORMAT = "relay-trust/v1"


def canonical(obj) -> bytes:
    """排序键、紧凑分隔、无多余空白的确定性 JSON（UTF-8 字节）。"""
    return json.dumps(obj, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), default=str).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# 事件哈希链
# ---------------------------------------------------------------------------

def event_message(event: dict) -> dict:
    """抽取参与哈希的规范化字段子集（缺字段显式为 None）。"""
    return {k: event.get(k) for k in EVENT_HASH_FIELDS}


def compute_event_hash(event: dict) -> str:
    """事件哈希 = SHA256(canonical(哈希字段子集))。

    哈希链：每个事件携带 ``prev_event_hash``（revision=1 时为 None），
    任一前序事件被改动都会让后续链接失效。
    """
    return sha256_hex(canonical(event_message(event)))


def verify_event_hash(event: dict) -> bool:
    return event.get("event_hash") == compute_event_hash(event)


def verify_event_signature(event: dict, sender_pubkey_hex: str) -> bool:
    """发送方对 event_hash（hex 字节）做 Ed25519 签章。"""
    sig = event.get("sender_signature")
    if not sig:
        return False
    try:
        return ed25519.verify(
            event["event_hash"].encode("ascii"),
            bytes.fromhex(sig),
            bytes.fromhex(sender_pubkey_hex),
        )
    except (ValueError, TypeError, ed25519.SignatureError,
            ed25519.PublicKeyError):
        return False


def sign_event_hash(event_hash_hex: str, seed: bytes) -> str:
    return ed25519.sign(event_hash_hex.encode("ascii"), seed).hex()


# ---------------------------------------------------------------------------
# 机构密钥库（接收机构 = 回执签发方）
# ---------------------------------------------------------------------------

class KeyExistsError(Exception):
    pass


def institution_seed_path(code: str, seq: int | None = None) -> Path:
    if seq is None:
        return config.key_dir() / f"{code}.seed"
    return config.key_dir() / f"{code}.{seq}.seed"


def institution_pub_path(code: str, seq: int | None = None) -> Path:
    if seq is None:
        return config.key_dir() / f"{code}.pub"
    return config.key_dir() / f"{code}.{seq}.pub"


def create_institution_keys(code: str, *, overwrite: bool = False,
                            seq: int = 0) -> dict:
    """生成机构 Ed25519 密钥：seed 写 0600 文件，公钥另存并返回。"""
    seed_p, pub_p = institution_seed_path(code, seq), institution_pub_path(code, seq)
    if seed_p.exists() and not overwrite:
        raise KeyExistsError(f"机构密钥已存在: {code}")
    seed, pub = ed25519.keypair()
    config.ensure_dirs()
    seed_p.write_text(seed.hex(), encoding="ascii")
    seed_p.chmod(0o600)
    pub_p.write_text(pub.hex(), encoding="ascii")
    return {"institution_code": code,
            "key_seq": seq,
            "public_key": pub.hex(),
            "seed_path": str(seed_p)}


def load_institution_seed(code: str, seq: int | None = None) -> bytes:
    return bytes.fromhex(
        institution_seed_path(code, seq).read_text(encoding="ascii").strip())


def load_institution_public(code: str, seq: int | None = None) -> str:
    return institution_pub_path(code, seq).read_text(encoding="ascii").strip()


# ---------------------------------------------------------------------------
# 回执包
# ---------------------------------------------------------------------------

RECEIPT_FIELDS_V1 = (
    "format", "request_key", "institution_code", "institution_title",
    "sender_id", "issued_at", "expires_at", "sessions",
)
RECEIPT_FIELDS_V2 = RECEIPT_FIELDS_V1 + (
    "receipt_id", "receipt_serial", "signing_public_key",
)


def receipt_body_fields(body: dict | None = None) -> tuple:
    # 旧包正文没有序号/签发钥字段；验签时必须沿用 v1 字段集。
    if body is not None and "receipt_serial" not in body:
        return RECEIPT_FIELDS_V1
    return RECEIPT_FIELDS_V2


def sign_receipt(body: dict, seed: bytes) -> str:
    msg = canonical({k: body.get(k) for k in receipt_body_fields(body)})
    return ed25519.sign(msg, seed).hex()


def verify_receipt_signature(body: dict, signature_hex: str,
                             public_key_hex: str) -> bool:
    """仅凭回执正文 + 公钥即可离线验签（不访问中继/数据库）。"""
    try:
        msg = canonical({k: body.get(k) for k in receipt_body_fields(body)})
        return ed25519.verify(msg, bytes.fromhex(signature_hex),
                              bytes.fromhex(public_key_hex))
    except (ValueError, TypeError, ed25519.SignatureError,
            ed25519.PublicKeyError):
        return False




# ---------------------------------------------------------------------------
# 机构密钥轮换链 / 版本化撤销清单 / 离线信任包
# ---------------------------------------------------------------------------

ROTATION_FIELDS = (
    "institution_code", "key_seq", "public_key", "effective_watermark",
    "register_request_key", "registered_at", "status", "approved_by",
    "approved_at", "activated_at", "previous_record_hash",
    "new_key_self_signature",
)
ROTATION_GENESIS_FIELDS = (
    "institution_code", "key_seq", "public_key", "registered_at", "status",
)
REVOCATION_FIELDS = (
    "institution_code", "version", "entries", "previous_list_hash",
    "published_at",
)
TRUST_BODY_FIELDS = (
    "format", "institution_code", "trust_version", "current_key_seq",
    "issued_at", "expires_at",
    "rotation_records", "revocation_lists", "revocation_entries",
    "revocation_digest", "previous_trust_digest",
)


def _sign_canonical(obj: dict, fields: tuple, seed: bytes) -> str:
    return ed25519.sign(canonical({k: obj.get(k) for k in fields}), seed).hex()


def _verify_canonical(obj: dict, fields: tuple, signature_hex: str,
                      public_key_hex: str) -> bool:
    try:
        return ed25519.verify(
            canonical({k: obj.get(k) for k in fields}),
            bytes.fromhex(signature_hex), bytes.fromhex(public_key_hex))
    except (ValueError, TypeError, ed25519.SignatureError,
            ed25519.PublicKeyError):
        return False


def rotation_genesis_record(code: str, public_key: str, at: str) -> dict:
    rec = {"institution_code": code, "key_seq": 0, "public_key": public_key,
           "registered_at": at, "status": "ACTIVE"}
    rec["record_hash"] = sha256_hex(
        canonical({k: rec.get(k) for k in ROTATION_GENESIS_FIELDS}))
    # 根记录自签，作为机构信任锚；后续记录必须由上一把有效机构钥签名。
    seed = load_institution_seed(code, 0)
    rec["signature"] = ed25519.sign(
        canonical({k: rec.get(k) for k in ROTATION_GENESIS_FIELDS}),
        seed).hex()
    return rec


def rotation_record_hash(rec: dict) -> str:
    if rec.get("key_seq") == 0:
        fields = ROTATION_GENESIS_FIELDS
    else:
        fields = ROTATION_FIELDS
    return sha256_hex(canonical({k: rec.get(k) for k in fields}))


def sign_rotation_record(rec: dict, old_seed: bytes) -> str:
    return _sign_canonical(rec, ROTATION_FIELDS, old_seed)


def verify_rotation_record(rec: dict, public_key: str) -> bool:
    if rec.get("key_seq") == 0:
        fields = ROTATION_GENESIS_FIELDS
        expected_pub = rec.get("public_key")
        if expected_pub != public_key:
            return False
    else:
        fields = ROTATION_FIELDS
    if rec.get("record_hash") != rotation_record_hash(rec):
        return False
    return _verify_canonical(rec, fields, rec.get("signature", ""), public_key)


def revocation_entries_digest(entries: list[dict]) -> str:
    normalized = sorted(entries,
                        key=lambda e: (e.get("receipt_id", ""),
                                       e.get("receipt_serial", 0)))
    return sha256_hex(canonical(normalized))


def revocation_list_hash(obj: dict, entries_digest: str) -> str:
    signed = {k: obj.get(k) for k in REVOCATION_FIELDS}
    return sha256_hex(canonical({"signed": signed,
                                 "entries_digest": entries_digest}))


def sign_revocation_list(obj: dict, seed: bytes) -> str:
    return _sign_canonical(obj, REVOCATION_FIELDS, seed)


def verify_revocation_list(obj: dict, signature_hex: str,
                           public_key_hex: str) -> bool:
    return _verify_canonical(obj, REVOCATION_FIELDS, signature_hex,
                             public_key_hex)


def sign_trust_body(body: dict, seed: bytes) -> str:
    return _sign_canonical(body, TRUST_BODY_FIELDS, seed)


def verify_trust_signature(body: dict, signature_hex: str,
                           public_key_hex: str) -> bool:
    return _verify_canonical(body, TRUST_BODY_FIELDS, signature_hex,
                             public_key_hex)
