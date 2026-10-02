"""SQLite 持久层。

设计要点
--------
* parcel_version 一旦 COMMITTED / ADJUDICATED 即**不可变**，新版本另起一行；
* 时间点查询由 valid_from / valid_to 半开区间 [from, to) 支持；
* version_hash 构成"哈希链"：每个版本包含上一版本与所有父版本的哈希；
* candidate 保存外业提交快照；dispute 保存差异几何与裁定状态。
"""
import sqlite3
import threading
from contextlib import contextmanager

from .config import _db_path

_lock = threading.RLock()


def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(_db_path(), timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA busy_timeout = 30000")
    return conn


@contextmanager
def tx():
    """串行化写事务（SQLite 单库，进程内加锁即可保证并发提交的正确性）。"""
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
CREATE TABLE IF NOT EXISTS parcel (
    id           TEXT PRIMARY KEY,           -- P-xxx
    label        TEXT NOT NULL,
    created_at   TEXT NOT NULL
);

-- 已登记的全局界址点
CREATE TABLE IF NOT EXISTS point (
    id         TEXT PRIMARY KEY,             -- BP-xxx（或采集端 UUID）
    x          REAL NOT NULL,
    y          REAL NOT NULL,
    kind       TEXT NOT NULL DEFAULT 'corner', -- corner / intermediate
    origin     TEXT NOT NULL DEFAULT 'survey',
    created_at TEXT NOT NULL
);

-- 宗地版本（不可变）
CREATE TABLE IF NOT EXISTS parcel_version (
    id              TEXT PRIMARY KEY,        -- PV-xxx
    parcel_id       TEXT NOT NULL REFERENCES parcel(id),
    version_no      INTEGER NOT NULL,
    status          TEXT NOT NULL,           -- PROPOSED / COMMITTED / ADJUDICATED / SUPERSEDED / ANNULLED
    ring_json       TEXT NOT NULL,           -- [[x,y],...]（闭合环，不含重复终点）
    area            REAL NOT NULL,
    declared_area   REAL,
    base_version_id TEXT REFERENCES parcel_version(id),
    chain_parent_id TEXT REFERENCES parcel_version(id), -- 同一宗地版本链上的前驱（支持更正分叉）
    valid_from      TEXT NOT NULL,
    valid_to        TEXT,                    -- NULL = 当前有效
    created_at      TEXT NOT NULL,
    version_hash    TEXT NOT NULL,
    UNIQUE(parcel_id, version_no)
);
CREATE INDEX IF NOT EXISTS idx_pv_parcel ON parcel_version(parcel_id);
CREATE INDEX IF NOT EXISTS idx_pv_valid ON parcel_version(valid_from, valid_to);

CREATE TABLE IF NOT EXISTS version_point (
    version_id TEXT NOT NULL REFERENCES parcel_version(id),
    point_id   TEXT NOT NULL REFERENCES point(id),
    ord        INTEGER NOT NULL,
    PRIMARY KEY (version_id, point_id)
);

-- 外业作业单（离线采集会话）
CREATE TABLE IF NOT EXISTS survey_job (
    id                 TEXT PRIMARY KEY,     -- JOB-uuid
    device_id          TEXT NOT NULL,
    surveyor           TEXT,
    status             TEXT NOT NULL DEFAULT 'OPEN', -- OPEN / SUBMITTED / COMMITTED / DISPUTED / REJECTED
    base_version_map   TEXT NOT NULL,        -- JSON {parcel_id: base_version_id}
    base_parcel_ids    TEXT NOT NULL,        -- JSON [parcel_id...]（新宗地为 null）
    payload            TEXT,                 -- JSON 提交快照
    error_json         TEXT,
    created_at         TEXT NOT NULL,
    submitted_at       TEXT,
    committed_at       TEXT
);

-- 候选边界（一个作业单内每宗地一条）
CREATE TABLE IF NOT EXISTS candidate (
    id          TEXT PRIMARY KEY,            -- CAND-uuid
    job_id      TEXT NOT NULL REFERENCES survey_job(id),
    parcel_id   TEXT,                        -- NULL = 新宗地
    label       TEXT,
    ring_json   TEXT NOT NULL,
    points_json TEXT NOT NULL,              -- 采集点（含精度、照片、确认信息）
    declared_area REAL,
    status      TEXT NOT NULL DEFAULT 'PENDING', -- PENDING / ACCEPTED / IN_DISPUTE / REJECTED
    created_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cand_job ON candidate(job_id);

-- 相邻权利人确认
CREATE TABLE IF NOT EXISTS owner_confirmation (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id       TEXT REFERENCES survey_job(id),
    parcel_id    TEXT,                       -- 被确认的相邻宗地
    owner_name   TEXT NOT NULL,
    owner_id_no  TEXT,
    segment_desc TEXT,
    confirmed    INTEGER NOT NULL DEFAULT 0,
    confirmed_at TEXT
);

-- 界标照片
CREATE TABLE IF NOT EXISTS media (
    id         TEXT PRIMARY KEY,             -- MED-uuid
    job_id     TEXT REFERENCES survey_job(id),
    point_ref  TEXT,                         -- 采集点本地标识
    point_id   TEXT REFERENCES point(id),
    filename   TEXT NOT NULL,
    mime       TEXT,
    size       INTEGER,
    created_at TEXT NOT NULL
);

-- 争议：两组测量同时修改同一共享片段
CREATE TABLE IF NOT EXISTS dispute (
    id              TEXT PRIMARY KEY,        -- DISP-uuid
    parcel_a        TEXT NOT NULL,
    parcel_b        TEXT NOT NULL,
    job_a           TEXT NOT NULL,
    job_b           TEXT NOT NULL,
    cand_a          TEXT NOT NULL,
    cand_b          TEXT NOT NULL,
    base_chain_json TEXT NOT NULL,           -- 原始（基线）片段几何
    geom_a_json     TEXT NOT NULL,           -- A 方案片段
    geom_b_json     TEXT NOT NULL,           -- B 方案片段
    anchor_start    TEXT NOT NULL,           -- 折点坐标 "x,y"（固定端点）
    anchor_end      TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'OPEN', -- OPEN / RESOLVED
    decision        TEXT,                    -- A / B / REVISED
    decided_chain_json TEXT,
    decided_by      TEXT,
    decided_at      TEXT,
    result_versions TEXT,                    -- JSON [version_id...]
    created_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_disp_status ON dispute(status);

-- 宗地生命周期操作（血缘）
CREATE TABLE IF NOT EXISTS parcel_op (
    id           TEXT PRIMARY KEY,           -- OP-uuid
    type         TEXT NOT NULL,              -- SURVEY / SPLIT / MERGE / CORRECTION / ADJUDICATION
    parent_versions TEXT NOT NULL,           -- JSON [version_id...]
    child_versions  TEXT NOT NULL,           -- JSON [version_id...]
    params_json  TEXT NOT NULL,
    job_id       TEXT REFERENCES survey_job(id),
    dispute_id   TEXT REFERENCES dispute(id),
    area_note    TEXT,                       -- 面积守恒核验记录
    created_at   TEXT NOT NULL
);

-- 已签发的历史证明
CREATE TABLE IF NOT EXISTS certificate (
    id           TEXT PRIMARY KEY,           -- CERT-yyyy-NNNN
    version_id   TEXT NOT NULL REFERENCES parcel_version(id),
    parcel_id    TEXT NOT NULL,
    area         REAL NOT NULL,
    issued_at    TEXT NOT NULL,
    document_json TEXT NOT NULL,
    signature    TEXT NOT NULL,              -- HMAC-SHA256(document)
    revoked      INTEGER NOT NULL DEFAULT 0
);

-- 幂等键（离线重连后重放提交）
CREATE TABLE IF NOT EXISTS idempotency (
    idem_key    TEXT PRIMARY KEY,
    response_json TEXT NOT NULL,
    created_at  TEXT NOT NULL
);

-- ============================================================
-- 二阶段历史更正：草案（DRAFT）阶段只存预演结果，不产生任何版本行
-- * status: OPEN（可预演/可发布/可撤销） / DRIFTED（基线漂移，需重新预演） /
--           PUBLISHED（已发布） / CANCELLED（已撤销，无任何半成品版本）
-- * preview_json: 每个受影响后代的新几何、面积差、血缘变化（预演快照）
-- * fingerprint_json: 建案/上次预演时的世界状态指纹（版本链/争议/证明）
-- * result_json: 首次成功发布的结果（发布幂等：重放返回同一结果）
-- ============================================================
CREATE TABLE IF NOT EXISTS correction_draft (
    id              TEXT PRIMARY KEY,        -- DRAFT-xxx
    target_version_id TEXT NOT NULL REFERENCES parcel_version(id),
    corrected_ring_json TEXT NOT NULL,       -- 目标版本的更正环（草案几何，不影响任何在版宗地）
    reason          TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'OPEN',
    created_by      TEXT,
    created_at      TEXT NOT NULL,
    previewed_at    TEXT,
    preview_json    TEXT,
    fingerprint_json TEXT,
    published_at    TEXT,
    publish_idem    TEXT,                    -- 发布幂等键
    result_json     TEXT,
    cancelled_at    TEXT
);
CREATE INDEX IF NOT EXISTS idx_cdraft_status ON correction_draft(status);

-- ============================================================
-- 生效计划（Effective Plan）：完成影响计算的校正草案可登记未来执行
-- * status: WAITING（等待执行）/ PAUSED（基线变化暂停）/
--           COMPLETED（已完成，不可二次落账）/ CANCELLED（已取消，占用释放）
-- * request_key: 相同请求键在 WAITING/PAUSED 期间全局唯一（部分唯一索引），
--   取消后释放，允许用同键重新登记；
-- * lease_owner/lease_at: 执行器租约（持久化），崩溃/重启后靠租约失效补跑；
-- * completion_token: 完成令牌（登记时生成并持久化），同时作为发布幂等键，
--   保证同一条计划至多落账一次。
-- ============================================================
CREATE TABLE IF NOT EXISTS effect_plan (
    id               TEXT PRIMARY KEY,        -- PLAN-xxx
    draft_id         TEXT NOT NULL REFERENCES correction_draft(id),
    request_key      TEXT NOT NULL,
    status           TEXT NOT NULL DEFAULT 'WAITING',
    execute_at       TEXT NOT NULL,           -- 计划生效（落账）时刻，UTC ISO
    registered_at    TEXT NOT NULL,
    created_by       TEXT,
    parcels_json     TEXT NOT NULL,           -- 登记时全部目标地块（互斥占用对象）
    fingerprint_json TEXT,                    -- 登记/上次恢复时的世界基线指纹
    lease_owner      TEXT,
    lease_at         TEXT,
    attempts         INTEGER NOT NULL DEFAULT 0,
    completion_token TEXT,                    -- 完成令牌（登记即持久化）
    completed_at     TEXT,
    result_json      TEXT,
    paused_at        TEXT,
    pause_reason     TEXT,                    -- SNAPSHOT_DRIFT / BASELINE_INVALID / OCCUPANCY_CONFLICT
    pause_detail_json TEXT,
    cancelled_at     TEXT
);
CREATE INDEX IF NOT EXISTS idx_plan_status_time ON effect_plan(status, execute_at);
CREATE INDEX IF NOT EXISTS idx_plan_draft ON effect_plan(draft_id);
-- 同一请求键在计划生效期间只能存在一条；取消/完成后释放，可重新登记
CREATE UNIQUE INDEX IF NOT EXISTS uq_active_plan_reqkey
    ON effect_plan(request_key) WHERE status IN ('WAITING', 'PAUSED');

-- 计划对目标地块的互斥占用（WAITING/PAUSED 持有；完成/取消删除）
CREATE TABLE IF NOT EXISTS plan_occupancy (
    plan_id   TEXT NOT NULL REFERENCES effect_plan(id),
    parcel_id TEXT NOT NULL,
    PRIMARY KEY (plan_id, parcel_id)
);
CREATE INDEX IF NOT EXISTS idx_planocc_parcel ON plan_occupancy(parcel_id);

-- ============================================================
-- 地籍快照交换包（Cadastral Snapshot Exchange Package）
-- 接收侧的分块上传会话：一个 package_id 一行（清单中的包标识即主键，
-- 相同包标识再次导入直接返回原会话/原结果）。
-- * status: UPLOADING（分块未齐或曾有同序号异内容）/ READY（全块齐）/
--           CONFLICT（终检发现链/引用/本地冲突，数据库原样）/
--           FROZEN（到期/人工冻结/重开重验失败；保留已收分块与冲突，拒绝继续写入）/
--           IMPORTED（已一次性导入；不可重开、不可清理导入结果）
-- * 接收窗口：owner（当前负责人；上传分块/终检只允许当前负责人）+
--   valid_until（有效期截止，UTC ISO；NULL = 不限期）；
--   到期惰性冻结，已验真分块、缺块状态、冲突记录全部保留。
-- * version_no：会话版本号，移交/续期/冻结/重开须携带，防止并发覆盖（乐观锁）。
-- * frozen_reason: EXPIRED（到期）/ MANUAL（人工冻结）/ REOPEN_MISMATCH（重开重验失败）。
-- * chunk_conflicts_json: 同序号不同内容的可定位冲突（重传正确内容即清除）
-- * result_json: 首次成功导入的结果（同包重放返回原结果，不可二次落账）
-- ============================================================
CREATE TABLE IF NOT EXISTS snapshot_session (
    package_id   TEXT PRIMARY KEY,        -- 清单包标识 PKG-xxx
    manifest_sha TEXT NOT NULL,           -- 清单整体 sha256（同 id 不同清单即冲突）
    manifest_json TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'UPLOADING',
    chunk_count  INTEGER NOT NULL,
    chunk_size   INTEGER NOT NULL,
    created_by   TEXT,
    created_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL,
    chunk_conflicts_json TEXT,     -- 同序号异内容（可重传纠正）
    verify_conflicts_json TEXT,    -- 最近一次终检的内部/本地冲突（可定位明细）
    result_json  TEXT,
    owner        TEXT,                       -- 当前负责人（NULL = 未指定负责人，不做写入限制）
    valid_until  TEXT,                       -- 接收窗口截止（UTC ISO）；NULL = 不限期
    version_no   INTEGER NOT NULL DEFAULT 1, -- 会话版本号（乐观锁；管理动作成功后递增）
    frozen       INTEGER NOT NULL DEFAULT 0, -- 1 = 已冻结（到期/人工/重开失败），拒绝写入
    frozen_reason TEXT,                      -- EXPIRED / MANUAL / REOPEN_MISMATCH
    frozen_at    TEXT,
    frozen_detail_json TEXT,                 -- 冻结可定位原因（重开重验失败明细等）
    reopened_at  TEXT
);

CREATE TABLE IF NOT EXISTS snapshot_chunk (
    package_id TEXT NOT NULL REFERENCES snapshot_session(package_id),
    seq        INTEGER NOT NULL,
    sha256     TEXT NOT NULL,
    content    BLOB NOT NULL,            -- 收到的正确分块字节（乱序/重复上传安全）
    PRIMARY KEY (package_id, seq)
);
CREATE INDEX IF NOT EXISTS idx_snapchunk_pkg ON snapshot_chunk(package_id);

-- 接收会话操作审计（移交/续期/冻结/重开/写入拒绝/终检/清理等全留痕）
CREATE TABLE IF NOT EXISTS snapshot_session_event (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    package_id TEXT NOT NULL,
    seq        INTEGER NOT NULL,             -- 会话内事件序号（审计顺序）
    action     TEXT NOT NULL,                -- CREATE/CHUNK_UPLOAD/FINALIZE/...
    actor      TEXT,                          -- 操作人（负责人标识）
    detail_json TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_snapevt_pkg ON snapshot_session_event(package_id, seq);

-- 管理动作（移交/续期/冻结/重开）的幂等请求键：
-- 同一 request_key 重复请求返回首次结果；期望版本号不匹配 → VERSION_CONFLICT。
-- outcome: ACCEPTED（首次成功，重放返回首次响应）/ REJECTED（首次判定即终局——
--   如重开重验因分块损坏等失配被拒；后台文件随后修复，原 request_key 的任何重放
--   仍原样返回这次拒绝，不产生新的状态变更；操作者必须改用**新 request_key 与
--   最新会话版本号**重新发起校验）。
CREATE TABLE IF NOT EXISTS snapshot_request (
    request_key TEXT PRIMARY KEY,
    package_id  TEXT NOT NULL,
    action      TEXT NOT NULL,
    expect_version INTEGER NOT NULL,
    fingerprint TEXT NOT NULL,                -- 请求内容指纹（同键不同内容 → 400）
    outcome     TEXT NOT NULL DEFAULT 'ACCEPTED',
    status_code INTEGER,                      -- REJECTED 首次拒绝的 HTTP 状态码
    response_json TEXT NOT NULL,
    created_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_snapreq_pkg ON snapshot_request(package_id);
"""


def init_db():
    from .config import DATA_DIR
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = get_conn()
    try:
        conn.executescript(SCHEMA)
        # 老库迁移：chain_parent_id 列（旧数据 = 同宗 version_no-1）
        cols = {r[1] for r in conn.execute("PRAGMA table_info(parcel_version)")}
        if "chain_parent_id" not in cols:
            conn.execute(
                "ALTER TABLE parcel_version ADD COLUMN chain_parent_id TEXT REFERENCES parcel_version(id)")
            conn.execute(
                """UPDATE parcel_version
                   SET chain_parent_id = (
                       SELECT p.id FROM parcel_version p
                       WHERE p.parcel_id = parcel_version.parcel_id
                         AND p.version_no = parcel_version.version_no - 1)""")
        # 交换包会话：终检冲突明细列（老库迁移）
        scols = {r[1] for r in conn.execute("PRAGMA table_info(snapshot_session)")}
        if scols and "verify_conflicts_json" not in scols:
            conn.execute(
                "ALTER TABLE snapshot_session ADD COLUMN verify_conflicts_json TEXT")
        # 接收窗口与移交（老库迁移）
        if scols:
            for ddl in (
                    "ALTER TABLE snapshot_session ADD COLUMN owner TEXT",
                    "ALTER TABLE snapshot_session ADD COLUMN valid_until TEXT",
                    "ALTER TABLE snapshot_session ADD COLUMN version_no INTEGER NOT NULL DEFAULT 1",
                    "ALTER TABLE snapshot_session ADD COLUMN frozen INTEGER NOT NULL DEFAULT 0",
                    "ALTER TABLE snapshot_session ADD COLUMN frozen_reason TEXT",
                    "ALTER TABLE snapshot_session ADD COLUMN frozen_at TEXT",
                    "ALTER TABLE snapshot_session ADD COLUMN frozen_detail_json TEXT",
                    "ALTER TABLE snapshot_session ADD COLUMN reopened_at TEXT"):
                col = ddl.split("ADD COLUMN")[1].strip().split()[0]
                if col not in scols:
                    conn.execute(ddl)
        # 幂等请求记录：首次拒绝终局化（老库迁移）
        rcols = {r[1] for r in conn.execute(
            "PRAGMA table_info(snapshot_request)")}
        if rcols and "outcome" not in rcols:
            conn.execute(
                "ALTER TABLE snapshot_request ADD COLUMN outcome TEXT NOT NULL DEFAULT 'ACCEPTED'")
        if rcols and "status_code" not in rcols:
            conn.execute(
                "ALTER TABLE snapshot_request ADD COLUMN status_code INTEGER")
        conn.commit()
    finally:
        conn.close()
