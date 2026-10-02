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
    created_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_relay_receipt_sender
    ON relay_receipt(sender_id, institution_code);

-- 中继自身操作审计（推送批次/隔离/解除/导出/清理授权判定/租约领取）。
CREATE TABLE IF NOT EXISTS relay_audit (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    action      TEXT NOT NULL,
    sender_id   TEXT,
    session_id  TEXT,
    detail_json TEXT,
    created_at  TEXT NOT NULL
);

-- 机构签发信任根：每机构一行，维护当前生效签发纪元与单调回执序号。
--  genesis 纪元（epoch=0）的公钥来自既有 {code}.pub，向下兼容。
CREATE TABLE IF NOT EXISTS relay_institution (
    institution_code TEXT PRIMARY KEY,
    active_epoch     INTEGER NOT NULL DEFAULT 0,   -- 当前生效的签发纪元
    next_serial      INTEGER NOT NULL DEFAULT 1,   -- 机构内单调回执序号（只增）
    next_bundle_serial INTEGER NOT NULL DEFAULT 1, -- 离线信任包单调版本号
    created_at       TEXT NOT NULL,
    updated_at       TEXT NOT NULL
);

-- 机构签发密钥轮换记录：连续签名链（旧钥签新钥）。
--  状态机 PROPOSED -> APPROVED -> ACTIVE；链只包含 APPROVED/ACTIVE 记录。
CREATE TABLE IF NOT EXISTS relay_key_rotation (
    id              TEXT PRIMARY KEY,
    institution_code TEXT NOT NULL,
    epoch           INTEGER NOT NULL,             -- 新钥纪元号（旧钥 epoch+1）
    public_key      TEXT NOT NULL,                 -- 下一把公钥（hex）
    activate_serial INTEGER NOT NULL,              -- 生效水位：新钥首张序号；旧钥可签 < 此值
    proposed_by     TEXT NOT NULL,
    approved_by     TEXT,
    proposer_request_key TEXT,                     -- 登记幂等请求键
    approver_request_key TEXT,                     -- 批准幂等请求键
    pop_signature   TEXT NOT NULL,                 -- 新钥对登记挑战的持有证明（PoP）
    approval_signature TEXT,                       -- 旧钥对整条轮换记录的批准签章
    record_hash     TEXT NOT NULL,                 -- 固定内容哈希（提案时确定）
    status          TEXT NOT NULL,                 -- PROPOSED / APPROVED / ACTIVE
    proposed_at     TEXT NOT NULL,
    approved_at     TEXT,
    activated_at    TEXT,
    UNIQUE(institution_code, epoch),
    UNIQUE(institution_code, public_key)
);
-- 同一机构至多一条未生效（PROPOSED/APPROVED）轮换：并发登记只允许一条胜出。
CREATE UNIQUE INDEX IF NOT EXISTS idx_relay_rot_pending
    ON relay_key_rotation(institution_code)
    WHERE status IN ('PROPOSED', 'APPROVED');
-- 登记/批准请求键全局幂等（重复请求返回首次结果）。
CREATE UNIQUE INDEX IF NOT EXISTS idx_relay_rot_proposer_key
    ON relay_key_rotation(proposer_request_key)
    WHERE proposer_request_key IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_relay_rot_approver_key
    ON relay_key_rotation(approver_request_key)
    WHERE approver_request_key IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_relay_rot_inst
    ON relay_key_rotation(institution_code, epoch);

-- 版本化撤销清单（机构级，只追加）：每版一个完整撤销条目集合。
CREATE TABLE IF NOT EXISTS relay_revocation (
    institution_code TEXT NOT NULL,
    version         INTEGER NOT NULL,
    request_key     TEXT,
    entries_json    TEXT NOT NULL,                 -- 完整撤销条目（全量并集）
    entry_count     INTEGER NOT NULL,
    prev_digest     TEXT,                          -- 上一版摘要（v1 为 null）
    digest          TEXT NOT NULL,                 -- 本版摘要
    signer_epoch    INTEGER NOT NULL,              -- 签发时生效的机构密钥纪元
    signature       TEXT NOT NULL,                 -- 机构生效钥签章
    published_at    TEXT NOT NULL,
    note            TEXT,
    PRIMARY KEY (institution_code, version)
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_relay_rev_reqkey
    ON relay_revocation(request_key)
    WHERE request_key IS NOT NULL;

-- 离线导入的信任包（机构公钥链/撤销摘要/单调版本号；重导幂等）。
CREATE TABLE IF NOT EXISTS relay_trust_import (
    institution_code TEXT NOT NULL,
    bundle_serial   INTEGER NOT NULL,              -- 信任包自身单调版本号
    bundle_json     TEXT NOT NULL,
    active_epoch    INTEGER NOT NULL,
    revocation_version INTEGER NOT NULL,
    imported_at     TEXT NOT NULL,
    PRIMARY KEY (institution_code, bundle_serial)
);

-- 本地导出的信任包（导出请求键 -> 原包；同键永远返回同一包）。
CREATE TABLE IF NOT EXISTS relay_trust_export (
    request_key      TEXT PRIMARY KEY,
    institution_code TEXT NOT NULL,
    bundle_serial    INTEGER NOT NULL,
    package_json     TEXT NOT NULL,
    created_at       TEXT NOT NULL
);
"""


def _migrate(conn):
    """增量迁移：为既有库追加新列（幂等）。"""
    cols = {r["name"] for r in conn.execute(
        "PRAGMA table_info(relay_receipt)").fetchall()}
    if "serial_no" not in cols:
        conn.execute("ALTER TABLE relay_receipt ADD COLUMN serial_no INTEGER")
    if "signer_epoch" not in cols:
        conn.execute("ALTER TABLE relay_receipt ADD COLUMN signer_epoch INTEGER")


def init_relay_db():
    config.ensure_dirs()
    conn = get_conn()
    try:
        conn.executescript(SCHEMA)
        _migrate(conn)
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
