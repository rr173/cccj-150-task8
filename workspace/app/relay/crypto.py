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


def institution_seed_path(code: str) -> Path:
    return config.key_dir() / f"{code}.seed"


def institution_pub_path(code: str) -> Path:
    return config.key_dir() / f"{code}.pub"


def create_institution_keys(code: str, *, overwrite: bool = False) -> dict:
    """生成机构 Ed25519 密钥：seed 写 0600 文件，公钥另存并返回。"""
    seed_p, pub_p = institution_seed_path(code), institution_pub_path(code)
    if seed_p.exists() and not overwrite:
        raise KeyExistsError(f"机构密钥已存在: {code}")
    seed, pub = ed25519.keypair()
    config.ensure_dirs()
    seed_p.write_text(seed.hex(), encoding="ascii")
    seed_p.chmod(0o600)
    pub_p.write_text(pub.hex(), encoding="ascii")
    return {"institution_code": code,
            "public_key": pub.hex(),
            "seed_path": str(seed_p)}


def load_institution_seed(code: str) -> bytes:
    return bytes.fromhex(institution_seed_path(code).read_text(encoding="ascii").strip())


def load_institution_public(code: str) -> str:
    return institution_pub_path(code).read_text(encoding="ascii").strip()


# ---------------------------------------------------------------------------
# 回执包
# ---------------------------------------------------------------------------

def receipt_body_fields() -> tuple:
    # 签章覆盖的回执正文键（签名/机构公钥之外的全部正文）
    return (
        "format", "request_key", "institution_code", "institution_title",
        "sender_id", "issued_at", "expires_at", "sessions",
    )


def sign_receipt(body: dict, seed: bytes) -> str:
    msg = canonical({k: body.get(k) for k in receipt_body_fields()})
    return ed25519.sign(msg, seed).hex()


def verify_receipt_signature(body: dict, signature_hex: str,
                             public_key_hex: str) -> bool:
    """仅凭回执正文 + 公钥即可离线验签（不访问中继/数据库）。"""
    try:
        msg = canonical({k: body.get(k) for k in receipt_body_fields()})
        return ed25519.verify(msg, bytes.fromhex(signature_hex),
                              bytes.fromhex(public_key_hex))
    except (ValueError, TypeError, ed25519.SignatureError,
            ed25519.PublicKeyError):
        return False
