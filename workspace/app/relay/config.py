"""回执中继配置（路径、过期、租约、批处理）。"""
from __future__ import annotations

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent.parent


def data_dir() -> Path:
    return Path(os.environ.get("RELAY_DATA_DIR", str(BASE_DIR / "data" / "relay")))


def key_dir() -> Path:
    return Path(os.environ.get("RELAY_KEY_DIR", str(data_dir() / "keys")))


def receipt_dir() -> Path:
    return Path(os.environ.get("RELAY_RECEIPT_DIR", str(data_dir() / "receipts")))


# 向后兼容的模块级属性（首次导入时的默认路径）
DATA_DIR = BASE_DIR / "data" / "relay"
KEY_DIR = DATA_DIR / "keys"
RECEIPT_DIR = DATA_DIR / "receipts"


def db_path() -> str:
    return os.environ.get("RELAY_DB", str(data_dir() / "relay.db"))


# 回执包默认有效期（秒）。过期回执不能再用于清理本地事件。
RECEIPT_TTL_SECONDS = int(os.environ.get("RELAY_RECEIPT_TTL_SECONDS", str(7 * 86400)))

# 离线信任包默认有效期（秒）：核验方导入的信任包过期后必须拒绝并要求重新导入。
TRUST_BUNDLE_TTL_SECONDS = int(
    os.environ.get("RELAY_TRUST_BUNDLE_TTL_SECONDS", str(30 * 86400)))

# 两个工作实例并发"领取"同一会话处理权的互斥租约（秒）。
# 持久租约写进 SQLite；实例崩溃后，超过 TTL 的租约会被其他实例安全接管。
LEASE_TTL_SECONDS = float(os.environ.get("RELAY_LEASE_TTL_SECONDS", "30"))

# 支持的事件类型（与快照接收服务的审计动作对应）。
EVENT_TYPES = frozenset({
    "CREATE",              # 接收会话创建
    "CHUNK_ACCEPTED",      # 分块被接受（首次或重复幂等）
    "CHUNK_REJECTED",      # 分块被拒绝（同序号异内容等）
    "HANDOVER",            # 负责人移交
    "FINALIZE_ACCEPTED",   # 终检通过、一次性导入
    "FINALIZE_REJECTED",   # 终检拒绝（冲突可定位）
})

# 允许的会话状态（对应快照会话状态）；事件里的状态跃迁合法性据此校验。
SESSION_STATES = frozenset({
    "UPLOADING", "READY", "FROZEN", "IMPORTED", "CONFLICT",
})

# 合法的会话状态跃迁（源状态 -> 允许的目标状态集合）。
# 事件必须把会话从 version_no 对应的旧状态推进到一个合法新状态；
# CREATE 事件没有前驱（在中继侧自动注册初始状态）。
LEGAL_TRANSITIONS = {
    "CREATE": {"UPLOADING", "READY"},
    "CHUNK_ACCEPTED": {"UPLOADING", "READY"},
    "CHUNK_REJECTED": {"UPLOADING", "CONFLICT"},
    "HANDOVER": {"UPLOADING", "READY", "FROZEN"},
    "FINALIZE_ACCEPTED": {"IMPORTED"},
    "FINALIZE_REJECTED": {"CONFLICT", "READY"},
}

# 终态：到了 IMPORTED 之后不再接受任何事件（链闭合）。
TERMINAL_STATE = "IMPORTED"

def ensure_dirs():
    for _d in (data_dir(), key_dir(), receipt_dir()):
        _d.mkdir(parents=True, exist_ok=True)
