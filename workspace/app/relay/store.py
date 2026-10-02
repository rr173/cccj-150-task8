"""回执中继 SQLite 持久层。

与主平台库**完全隔离**（独立文件，默认 ``data/relay/relay.db``）。

关键表
------
* ``relay_sender``      发送方注册（公钥用于验证事件签章）
* ``relay_session``     每 (sender, session) 的连续水位 / 隔离状态 / 处理租约
* ``relay_raw_event``   只追加的原始事件落地（乱序/重复/分叉内容都留证）
* ``relay_event``       已进入连续哈希链（已确认水位）的规范化事件
* ``relay_quarantine``  隔离原因与可定位差异（同序号异内容/分叉链/坏签名/非法跃迁）
* ``relay_receipt``     导出请求键 -> 已签发回执包（同键重放原样返回）
* ``relay_audit``       中继自身操作留痕
"""
from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager

from . import config
from ..services.ids import new_id, now_iso

_lock = threading.RLock()


def get_conn() -> sqlite3.Connection:
    config.ensure_dirs()
    conn = sqlite3.connect(config.db_path(), timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA busy_timeout = 30000")
    conn.execute("PRAGMA synchronous = FULL")
    return conn


@contextmanager
def tx():
    """进程内串行化写事务（BEGIN IMMEDIATE 立即拿写锁）。"""
    with _lock:
        conn = get_conn()
        try:
            conn.execute("BEGIN IMMEDIATE")
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()


SCHEMA = """
CREATE TABLE IF NOT EXISTS relay_sender (
    sender_id    TEXT PRIMARY KEY,           -- 发送方标识（如快照接收站点编号）
    title        TEXT,
    public_key   TEXT NOT NULL,              -- Ed25519 公钥（hex），验证事件签章
    created_at   TEXT NOT NULL
);

-- 每个 (发送方, 交换包接收会话) 一行；水位与会话状态在此维护。
CREATE TABLE IF NOT EXISTS relay_session (
    sender_id      TEXT NOT NULL,
    session_id     TEXT NOT NULL,            -- 对应快照接收会话 package_id
    watermark      INTEGER NOT NULL DEFAULT 0,  -- 连续已确认修订号（1..watermark 全部合法）
    state          TEXT,                        -- 水位事件所确认的最新会话状态
    quarantined    INTEGER NOT NULL DEFAULT 0,
    quarantine_reason TEXT,                    -- SAME_REV_DIFFERENT_CONTENT/FORKED_CHAIN/BAD_SIGNATURE/INVALID_TRANSITION
    quarantine_detail_json TEXT,
    quarantined_at TEXT,
    lease_owner    TEXT,                        -- 工作实例领取租约（持久，崩溃后 TTL 回收）
    lease_at       TEXT,
    closed_at      TEXT,                        -- 收到终态（IMPORTED）闭合后设置
    created_at     TEXT NOT NULL,
    updated_at     TEXT NOT NULL,
    PRIMARY KEY (sender_id, session_id)
);
CREATE INDEX IF NOT EXISTS idx_relay_sess_wm ON relay_session(sender_id, watermark);

-- 原始事件：只追加。乱序/重复都安全；同序号异内容产生两行（(rev,hash) 不冲突）。
CREATE TABLE IF NOT EXISTS relay_raw_event (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id     TEXT NOT NULL,
    session_id    TEXT NOT NULL,
    revision      INTEGER NOT NULL,
    event_hash    TEXT NOT NULL,
    payload_json  TEXT NOT NULL,
    batch_id      TEXT,
    received_at   TEXT NOT NULL,
    UNIQUE(sender_id, session_id, revision, event_hash)
);
CREATE INDEX IF NOT EXISTS idx_relay_raw_next
    ON relay_raw_event(sender_id, session_id, revision);

-- 已确认（进入连续哈希链）的事件：每个修订号至多一条。
CREATE TABLE IF NOT EXISTS relay_event (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id     TEXT NOT NULL,
    session_id    TEXT NOT NULL,
    revision      INTEGER NOT NULL,
    event_type    TEXT NOT NULL,
    session_version INTEGER NOT NULL,
    state         TEXT NOT NULL,
    prev_event_hash TEXT,
    event_hash    TEXT NOT NULL,
    sender_signature TEXT NOT NULL,
    occurred_at   TEXT NOT NULL,
    detail_json   TEXT,
    confirmed_at  TEXT NOT NULL,
    UNIQUE(sender_id, session_id, revision)
);
CREATE INDEX IF NOT EXISTS idx_relay_ev_lookup
    ON relay_event(sender_id, session_id, revision);

-- 隔离记录（隔离后该会话后续事件只入库留证、不再推进水位）。
CREATE TABLE IF NOT EXISTS relay_quarantine (
    id            TEXT PRIMARY KEY,
    sender_id     TEXT NOT NULL,
    session_id    TEXT NOT NULL,
    reason        TEXT NOT NULL,
    detail_json   TEXT NOT NULL,             -- 可定位差异（修订号/期望 vs 实际哈希等）
    quarantined_at TEXT NOT NULL,
    released_at   TEXT,
    release_note  TEXT,
    UNIQUE(sender_id, session_id)
);

-- 回执导出请求键 -> 已签发包（相同 request_key 永远返回原包字节）。
CREATE TABLE IF NOT EXISTS relay_receipt (
    request_key     TEXT PRIMARY KEY,
    institution_code TEXT NOT NULL,
    sender_id       TEXT NOT NULL,
    sessions_json   TEXT NOT NULL,           -- 导出时覆盖的会话清单（快照）
    package_json    TEXT NOT NULL,           -- 完整可离线核验回执包（含签名）
    signature       TEXT NOT NULL,
    issued_at       TEXT NOT NULL,
    expires_at      TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    receipt_serial  INTEGER,                 -- 机构内单调签发水位
    signing_key_seq INTEGER,
    signing_public_key TEXT
);
CREATE INDEX IF NOT EXISTS idx_relay_receipt_sender
    ON relay_receipt(sender_id, institution_code);

-- 机构签发密钥轮换状态。根公钥 seq=0；current_key_seq 永远不回退。
CREATE TABLE IF NOT EXISTS relay_institution_state (
    institution_code TEXT PRIMARY KEY,
    title            TEXT,
    current_key_seq  INTEGER NOT NULL DEFAULT 0,
    next_receipt_serial INTEGER NOT NULL DEFAULT 1,
    revocation_version INTEGER NOT NULL DEFAULT 0,
    revocation_digest TEXT,
    trust_version    INTEGER NOT NULL DEFAULT 0,
    previous_trust_digest TEXT,
    last_trust_digest TEXT,
    created_at       TEXT NOT NULL,
    updated_at       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS relay_key_rotation (
    institution_code TEXT NOT NULL,
    key_seq          INTEGER NOT NULL,
    public_key       TEXT NOT NULL,
    effective_watermark INTEGER,
    register_request_key TEXT NOT NULL,
    registered_by    TEXT,
    registered_at    TEXT NOT NULL,
    status           TEXT NOT NULL,           -- PROPOSED / APPROVED / ACTIVE / REJECTED
    approved_by      TEXT,
    approved_at      TEXT,
    activated_at     TEXT,
    previous_record_hash TEXT,
    record_hash      TEXT,
    signature        TEXT,
    new_key_self_signature TEXT,
    PRIMARY KEY (institution_code, key_seq)
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_relay_rot_register
    ON relay_key_rotation(register_request_key);
CREATE INDEX IF NOT EXISTS idx_relay_rot_active
    ON relay_key_rotation(institution_code, status);
CREATE UNIQUE INDEX IF NOT EXISTS uq_relay_rot_open
    ON relay_key_rotation(institution_code)
    WHERE status IN ('PROPOSED','APPROVED');

CREATE TABLE IF NOT EXISTS relay_admin_action (
    request_key TEXT PRIMARY KEY,
    institution_code TEXT NOT NULL,
    action_type TEXT NOT NULL,                -- ROTATION_REGISTER/APPROVE/ACTIVATE/REVOKE/TRUST_EXPORT/TRUST_IMPORT
    target_type TEXT,                         -- ROTATION/REVOCATION/TRUST
    target_id TEXT,
    fingerprint TEXT NOT NULL,
    status_code INTEGER NOT NULL,
    response_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS relay_revocation_list (
    institution_code TEXT NOT NULL,
    version INTEGER NOT NULL,
    entries_json TEXT NOT NULL,
    entries_digest TEXT NOT NULL,
    previous_list_hash TEXT,
    list_hash TEXT NOT NULL,
    signature TEXT NOT NULL,
    signing_key_seq INTEGER NOT NULL,
    published_by TEXT,
    published_at TEXT NOT NULL,
    PRIMARY KEY (institution_code, version)
);

CREATE TABLE IF NOT EXISTS relay_revocation_entry (
    institution_code TEXT NOT NULL,
    version INTEGER NOT NULL,
    receipt_id TEXT,
    receipt_serial INTEGER,
    issued_from TEXT,
    issued_to TEXT,
    reason TEXT NOT NULL,
    revoked_by TEXT,
    revoked_at TEXT NOT NULL,
    entry_json TEXT NOT NULL,
    PRIMARY KEY (institution_code, version, receipt_id, receipt_serial,
                 issued_from, issued_to, reason)
);
CREATE INDEX IF NOT EXISTS idx_relay_rev_lookup
    ON relay_revocation_entry(institution_code, receipt_id, receipt_serial,
                              issued_from, issued_to);

CREATE TABLE IF NOT EXISTS relay_trust_export (
    request_key TEXT PRIMARY KEY,
    institution_code TEXT NOT NULL,
    trust_version INTEGER NOT NULL,
    package_json TEXT NOT NULL,
    trust_digest TEXT NOT NULL,
    issued_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_relay_trust_version
    ON relay_trust_export(institution_code, trust_version);

CREATE TABLE IF NOT EXISTS relay_trust_import (
    institution_code TEXT PRIMARY KEY,
    trust_version INTEGER NOT NULL,
    trust_digest TEXT NOT NULL,
    previous_trust_digest TEXT,
    package_json TEXT NOT NULL,
    imported_at TEXT NOT NULL
);

-- 中继自身操作审计（推送批次/隔离/解除/导出/清理授权判定/租约领取/轮换/撤销/信任导入）。
CREATE TABLE IF NOT EXISTS relay_audit (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    action      TEXT NOT NULL,
    sender_id   TEXT,
    session_id  TEXT,
    detail_json TEXT,
    created_at  TEXT NOT NULL
);
"""


def init_relay_db():
    config.ensure_dirs()
    conn = get_conn()
    try:
        conn.executescript(SCHEMA)
        rot_cols = {r[1] for r in conn.execute("PRAGMA table_info(relay_key_rotation)")}
        if rot_cols and "new_key_self_signature" not in rot_cols:
            conn.execute(
                "ALTER TABLE relay_key_rotation ADD COLUMN new_key_self_signature TEXT")
        conn.execute("DROP INDEX IF EXISTS uq_relay_rot_active")
        rcols = {r[1] for r in conn.execute("PRAGMA table_info(relay_receipt)")}
        for col, ddl in (
                ("receipt_serial",
                 "ALTER TABLE relay_receipt ADD COLUMN receipt_serial INTEGER"),
                ("signing_key_seq",
                 "ALTER TABLE relay_receipt ADD COLUMN signing_key_seq INTEGER"),
                ("signing_public_key",
                 "ALTER TABLE relay_receipt ADD COLUMN signing_public_key TEXT")):
            if rcols and col not in rcols:
                conn.execute(ddl)
        conn.commit()
    finally:
        conn.close()


def audit(conn, action: str, *, sender_id=None, session_id=None, detail=None):
    conn.execute(
        "INSERT INTO relay_audit(action,sender_id,session_id,detail_json,created_at)"
        " VALUES(?,?,?,?,?)",
        (action, sender_id, session_id,
         json.dumps(detail, ensure_ascii=False, default=str), now_iso()))


def get_or_create_session(conn, sender_id: str, session_id: str) -> sqlite3.Row:
    row = conn.execute(
        "SELECT * FROM relay_session WHERE sender_id=? AND session_id=?",
        (sender_id, session_id)).fetchone()
    if row is None:
        now = now_iso()
        conn.execute(
            "INSERT INTO relay_session(sender_id,session_id,created_at,updated_at)"
            " VALUES(?,?,?,?)", (sender_id, session_id, now, now))
        row = conn.execute(
            "SELECT * FROM relay_session WHERE sender_id=? AND session_id=?",
            (sender_id, session_id)).fetchone()
    return row


def reset_database():
    """测试辅助：删除中继库文件。"""
    for suffix in ("", "-wal", "-shm"):
        p = config.db_path() + suffix
        try:
            Path(p).unlink()
        except FileNotFoundError:
            pass


from pathlib import Path  # noqa: E402  (reset_database 使用；放末尾避免打断 schema 阅读)
