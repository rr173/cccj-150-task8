"""地籍快照交换包（Cadastral Snapshot Exchange Package）。

导出（build_package）
    用户按**时间点** `at` 选取一组宗地（种子取各宗在该时点的有效版本），
    服务端计算可独立核验的**最小闭包**：
      * 版本链：种子版本沿同宗 chain_parent_id 与跨宗地 parcel_op 血缘
        （SPLIT/MERGE/CORRECTION/ADJUDICATION 的父版本）做不动点扩张；
      * 共享边：闭包内各宗在 `at` 时点版本两两之间的重合界址边；
      * 争议：涉及闭包宗地、且在 `at` 前形成的 dispute（含其作业单/候选）；
      * 证明：闭包宗地在 `at` 前签发的 certificate（签章自带）；
      * 生效计划：占用对象与闭包宗地相交的 effect_plan（连同 correction_draft、
        占用行；仅被占用而未入选的宗地以存根 parcel 行补全）。
    闭包内容规范化为 payload，整体 SHA-256 后切块；清单逐项登记内容哈希并用
    HMAC-SHA256 签发，接收方**无网络即可独立核验**。

接收（session / 预检 / 终检 / 一次性导入 / 接收窗口与移交）
    * POST /imports 凭清单建上传会话，可指定**负责人 owner** 与**接收窗口**
      （valid_until 绝对时刻或 ttl_minutes 时长；均缺省不限期）：
      相同包标识+相同清单可续传/重放，同标识不同清单直接 409（PACKAGE_ID_CONFLICT）；
    * **上传分块与终检只允许当前负责人**（未指定负责人的会话不限制，向后兼容）；
    * 分块可乱序、重复上传：同序号重复相同内容幂等；同序号不同内容记为
      CHUNK_CONTENT_MISMATCH 且**不覆盖已收正确块**，重传正确内容即清除；
    * **到期或人工冻结**（FROZEN/EXPIRED/MANUAL）：惰性落冻结，已经验真的分块、
      缺块状态、冲突记录全部保留，但拒绝继续写入（409 SESSION_FROZEN，审计留痕）；
    * **移交 / 续期 / 冻结 / 重开必须携带 request_key（幂等请求键）与 version
      （会话版本号）**：版本号不匹配 → VERSION_CONFLICT（失败不消费请求键）；
      同键重放返回首次结果；同键异内容 → REQUEST_KEY_CONFLICT；成功动作版本号 +1；
    * **重开校验拒绝是终局判定**：一次 reopen 若因磁盘分块损坏等失配被拒
      （REOPEN_MISMATCH，保持冻结），该 request_key 被**永久绑定**到这次拒绝
      响应——之后同键重放（连续点击、网络重试）一律原样回放首次拒绝，即使后台
      文件后来被修正、会话已被其他操作标识推进，原标识也不再重新校验、不产生
      任何新状态变更（不重复冻结、不重复记审计）；操作者必须提交**新 request_key
      与最新 version** 才能再次校验；
    * 移交在冻结期间也允许（不解除冻结）；续期仅在窗口开启期间允许；
    * **重新开启（reopen）前重新核验清单与现存分块**（全块齐备时含完整终检口径）：
      失配保持冻结（REOPEN_MISMATCH）并返回可定位原因，版本/请求键不变；
      通过才解冻续传；已 IMPORTED 的会话不得重开/移交/续期/冻结；
    * /precheck 纯离线（不依赖本地库时）或只读比对本地库，返回可定位条目；
    * /finalize 只有「全部分块 + 清单 + 链 + 引用关系 + 本地版本」全部匹配时，
      才在**单事务内一次性导入**；任何冲突都回滚、数据库原样；
    * 同包再次 finalize 返回首次结果（IMPORTED 结果持久化，不可二次落账）；
    * POST /imports-cleanup 只清理冻结超过保留期且从未导入的会话（含分块/审计/
      幂等键）；已导入会话与其导入结果永不清理。
"""
from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timedelta, timezone

from .. import config
from .. import geo
from . import ids
from . import versions as vs
from . import plans as plans_svc
from .crypto import canonical, sign_document, verify_signature, version_hash

FORMAT = "cadastre-snapshot-pkg/1"
DEFAULT_CHUNK = 16 * 1024

# 会话状态
UPLOADING, READY, CONFLICT, FROZEN, IMPORTED = (
    "UPLOADING", "READY", "CONFLICT", "FROZEN", "IMPORTED")
# 冻结原因
FR_EXPIRED, FR_MANUAL, FR_REOPEN = "EXPIRED", "MANUAL", "REOPEN_MISMATCH"
# 需要幂等请求键 + 会话版本号的管理动作
MGMT_ACTIONS = ("HANDOVER", "RENEW", "FREEZE", "REOPEN")
_ACTION_TEXT = {"HANDOVER": "移交", "RENEW": "续期", "FREEZE": "冻结",
                "REOPEN": "重开（恢复校验）"}


class SessionError(Exception):
    """接收会话操作错误（路由层映射 HTTP 状态码）。"""

    status_code = 400

    def __init__(self, message: str, *, code: str, session: dict | None = None,
                 conflicts=None):
        super().__init__(message)
        self.message = message
        self.code = code
        self.session = session
        self.conflicts = conflicts


class SessionFrozen(SessionError):
    """会话已冻结（到期/人工/重开失败）：只读，拒绝继续写入。"""
    status_code = 409

    def __init__(self, message, *, code="SESSION_FROZEN", reason=None,
                 session=None):
        super().__init__(message, code=code, session=session)
        self.reason = reason


class NotOwner(SessionError):
    """上传分块/终检/管理动作的操作人不是当前负责人。"""
    status_code = 403

    def __init__(self, message="只有当前负责人可以执行此操作", *, session=None,
                 actor=None):
        super().__init__(message, code="NOT_OWNER", session=session)
        self.actor = actor


class VersionConflict(SessionError):
    """会话版本号不匹配（并发覆盖被乐观锁挡下）。"""
    status_code = 409

    def __init__(self, message, *, session=None):
        super().__init__(message, code="VERSION_CONFLICT", session=session)


class ReopenMismatch(SessionError):
    """重开重验失败：保持冻结，返回可定位原因。"""
    status_code = 409

    def __init__(self, message, *, conflicts=None, session=None):
        super().__init__(message, code="REOPEN_MISMATCH",
                         session=session, conflicts=conflicts)


class ReplayedDecision(SessionError):
    """原 request_key 的重放命中**首次终局判定**（首次请求被拒绝）。

    重开校验一旦因分块损坏等失配被拒，该操作标识（request_key）永久对应这次
    拒绝响应：即使后台文件后来被修正、世界状态已变化，同键重放也只原样返回
    首次拒绝，**不再重新校验、不产生新的状态变更**。操作者必须提交新的
    request_key 与最新会话版本号才能再次校验。
    """

    def __init__(self, message, *, code, status_code=409, payload=None,
                 reason=None):
        super().__init__(message, code=code)
        self.status_code = status_code
        self.payload = payload or {}      # 首次拒绝响应体（含 conflicts/session）
        self.reason = reason


# ================================================================ 时间
def _parse_dt(s: str) -> datetime:
    s = str(s).strip()
    if s.endswith("Z"):
        dt = datetime.fromisoformat(s[:-1])
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def canon_iso(v: str) -> str:
    """把入参时间归一为 UTC 的 ...Z 串（词序可比较），非法则 ValueError。"""
    try:
        return _iso(_parse_dt(v))
    except ValueError as e:
        raise ValueError(f"无效时间（需 ISO-8601）: {v}") from e


def _resolve_window(valid_until, ttl_minutes, now: str) -> str | None:
    """计算接收窗口截止时刻：显式时刻优先，否则 ttl 分钟；均缺省返回 None（不限期）。"""
    if valid_until is not None:
        ts = canon_iso(valid_until)
        if ts <= now:
            raise ValueError("有效期截止时刻必须是未来时刻")
        return ts
    if ttl_minutes is not None:
        minutes = float(ttl_minutes)
        if minutes <= 0:
            raise ValueError("ttl_minutes 必须为正数")
        return _iso(_parse_dt(now) + timedelta(minutes=minutes))
    return None


# ================================================================ 基础工具
def sha256_hex(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def item_hash(item: dict) -> str:
    return sha256_hex(canonical(item).encode("utf-8"))


def _b64encode(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64decode(s: str) -> bytes:
    s = s.strip().translate(str.maketrans("-_", "+/"))
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s)


def _jloads(v, default=None):
    if v is None:
        return default
    return json.loads(v)


# ================================================================ 导出：最小闭包
def build_package(conn, payload: dict) -> dict:
    """按时间点导出快照交换包（信封：清单 + base64 分块）。"""
    at = plans_svc.canon_iso(payload["at"])
    created_at = ids.as_of(payload.get("as_of"))
    seed_pids = sorted(dict.fromkeys(payload.get("parcel_ids") or []))
    chunk_size = int(payload.get("chunk_size") or DEFAULT_CHUNK)
    if chunk_size < 256:
        raise ValueError("chunk_size 过小（≥256 字节）")
    include_plans = payload.get("include_plans", True)

    for pid in seed_pids:
        if not conn.execute("SELECT 1 FROM parcel WHERE id=?", (pid,)).fetchone():
            raise ValueError(f"宗地不存在: {pid}")
        if not vs.version_at(conn, pid, at):
            raise ValueError(f"宗地 {pid} 在来源时间点 {at} 无有效版本")

    items, kinds = _collect_closure(conn, seed_pids, at, include_plans)
    manifest = _manifest(conn, items, kinds, seed_pids=seed_pids, at=at,
                         created_at=created_at, created_by=payload.get("created_by"),
                         chunk_size=chunk_size)
    return {"manifest": manifest, "chunks": manifest.pop("_chunks_b64")}


def _version_item(conn, r) -> dict:
    return {
        "id": r["id"], "parcel_id": r["parcel_id"], "version_no": r["version_no"],
        "status": r["status"], "ring": json.loads(r["ring_json"]),
        "area": r["area"], "declared_area": r["declared_area"],
        "base_version_id": r["base_version_id"],
        "chain_parent_id": r["chain_parent_id"],
        "valid_from": r["valid_from"], "valid_to": r["valid_to"],
        "created_at": r["created_at"], "version_hash": r["version_hash"],
    }


def _collect_closure(conn, seed_pids, at, include_plans):
    """不动点扩张，返回 (items_by_key, kinds)。

    items: {kind: {id: logical_item}}；逻辑项即后续核验/落库的统一口径。
    扩张规则（对同一快照时间 `at`）：
      * 版本 → 同宗链前驱/基线、产生它的跨宗地操作的全部父版本；
      * 版本 → 界址点与挂接；
      * 版本 → 以它为子版本的操作（含作业单/争议引用）；
      * 宗地 → 涉及它的争议（含作业单/候选/裁定结果版本）；
      * 宗地 → 它在 `at` 前签发的证明；
      * 宗地 → 占用它的生效计划（连同草案、占用对象宗地存根）。
    """
    K = {k: {} for k in (
        "parcel", "point", "version", "version_point", "op", "dispute",
        "certificate", "job", "candidate", "draft", "plan", "occupancy")}

    def add(kind, key, val):
        K[kind].setdefault(key, val)

    all_ops = [
        {"row": r, "parents": _jloads(r["parent_versions"]),
         "children": _jloads(r["child_versions"])}
        for r in conn.execute("SELECT * FROM parcel_op WHERE created_at<=? ORDER BY id",
                              (at,)).fetchall()]
    all_disputes = conn.execute(
        "SELECT * FROM dispute WHERE created_at<=? ORDER BY id", (at,)).fetchall()
    all_certs = conn.execute(
        "SELECT * FROM certificate WHERE issued_at<=? ORDER BY id", (at,)).fetchall()
    all_plans = conn.execute(
        "SELECT * FROM effect_plan WHERE registered_at<=? ORDER BY id",
        (at,)).fetchall() if include_plans else []

    def add_parcel(pid):
        if pid in K["parcel"]:
            return
        r = conn.execute("SELECT * FROM parcel WHERE id=?", (pid,)).fetchone()
        add("parcel", pid,
            {"id": r["id"], "label": r["label"], "created_at": r["created_at"]}
            if r else {"id": pid, "label": None, "created_at": at, "stub": True})

    def add_version(vid):
        if vid in K["version"]:
            return
        r = conn.execute("SELECT * FROM parcel_version WHERE id=?",
                         (vid,)).fetchone()
        if not r or r["valid_from"] > at:
            return
        add("version", r["id"], _version_item(conn, r))
        add_parcel(r["parcel_id"])
        for ppid in (r["chain_parent_id"], r["base_version_id"]):
            if ppid:
                add_version(ppid)
        for rvp in conn.execute(
                "SELECT point_id,ord FROM version_point WHERE version_id=? ORDER BY ord",
                (r["id"],)).fetchall():
            add("version_point", f"{r['id']}:{rvp['point_id']}",
                {"version_id": r["id"], "point_id": rvp["point_id"], "ord": rvp["ord"]})
            pr = conn.execute("SELECT * FROM point WHERE id=?",
                              (rvp["point_id"],)).fetchone()
            if pr:
                add("point", pr["id"], {"id": pr["id"], "x": pr["x"], "y": pr["y"],
                                        "kind": pr["kind"], "origin": pr["origin"],
                                        "created_at": pr["created_at"]})
        for op in all_ops:
            if r["id"] not in op["children"]:
                continue
            add_op(op["row"])

    def add_op(r):
        if r["id"] in K["op"]:
            return
        add("op", r["id"], {
            "id": r["id"], "type": r["type"],
            "parent_versions": _jloads(r["parent_versions"]),
            "child_versions": _jloads(r["child_versions"]),
            "params": _jloads(r["params_json"]),
            "job_id": r["job_id"], "dispute_id": r["dispute_id"],
            "area_note": _jloads(r["area_note"]), "created_at": r["created_at"]})
        for pv in _jloads(r["parent_versions"]):
            add_version(pv)
        if r["job_id"]:
            _absorb_job(conn, K, r["job_id"])
        if r["dispute_id"]:
            dr = conn.execute("SELECT * FROM dispute WHERE id=?",
                              (r["dispute_id"],)).fetchone()
            if dr:
                add_dispute(dr)

    def add_dispute(r):
        if r["id"] in K["dispute"]:
            return
        add("dispute", r["id"], _dispute_item(r))
        for pid0 in (r["parcel_a"], r["parcel_b"]):
            add_parcel(pid0)
        for jid in (r["job_a"], r["job_b"]):
            _absorb_job(conn, K, jid)
        for cid in (r["cand_a"], r["cand_b"]):
            _absorb_candidate(conn, K, cid)
        for vid in _jloads(r["result_versions"]) or []:
            add_version(vid)

    def add_plan(r):
        if r["id"] in K["plan"]:
            return
        add("plan", r["id"], _plan_item(r))
        for pid0 in _jloads(r["parcels_json"]):
            add_parcel(pid0)
            add("occupancy", f"{r['id']}:{pid0}",
                {"plan_id": r["id"], "parcel_id": pid0})
        d = conn.execute("SELECT * FROM correction_draft WHERE id=?",
                         (r["draft_id"],)).fetchone()
        if d:
            add("draft", d["id"], _draft_item(d))

    # 种子：各宗在 at 时点的有效版本
    for pid in seed_pids:
        add_parcel(pid)
        add_version(vs.version_at(conn, pid, at)["id"])

    # 不动点：争议/证明/计划从宗地侧引入后，可能带来新的版本→操作链
    for _ in range(64):
        before = sum(len(v) for v in K.values())
        closure_pids = set(K["parcel"])
        for r in all_disputes:
            if r["parcel_a"] in closure_pids or r["parcel_b"] in closure_pids:
                add_dispute(r)
        for r in all_certs:
            if r["parcel_id"] in closure_pids:
                add("certificate", r["id"], {
                    "id": r["id"], "version_id": r["version_id"],
                    "parcel_id": r["parcel_id"], "area": r["area"],
                    "issued_at": r["issued_at"], "document": _jloads(r["document_json"]),
                    "signature": r["signature"], "revoked": bool(r["revoked"])})
                add_version(r["version_id"])
        for r in all_plans:
            if set(_jloads(r["parcels_json"])) & closure_pids:
                add_plan(r)
        if sum(len(v) for v in K.values()) == before:
            break

    out_kinds = {k: dict(v) for k, v in K.items()}
    payload_items = {}
    for kind, table in out_kinds.items():
        for key, val in table.items():
            # 载荷项内联 kind，与清单条目哈希口径保持一致（同一份规范化字节）
            payload_items[f"{kind}:{key}"] = {"kind": kind, **val}
    return payload_items, out_kinds


def _parcel_item(conn, pid) -> dict:
    r = conn.execute("SELECT * FROM parcel WHERE id=?", (pid,)).fetchone()
    return {"id": r["id"], "label": r["label"], "created_at": r["created_at"]}


def _absorb_job(conn, K, jid):
    r = conn.execute("SELECT * FROM survey_job WHERE id=?", (jid,)).fetchone()
    if not r or jid in K["job"]:
        return
    K["job"][jid] = {
        "id": r["id"], "device_id": r["device_id"], "surveyor": r["surveyor"],
        "status": r["status"], "base_version_map": _jloads(r["base_version_map"]),
        "base_parcel_ids": _jloads(r["base_parcel_ids"]),
        "payload": _jloads(r["payload"]), "error": _jloads(r["error_json"]),
        "created_at": r["created_at"], "submitted_at": r["submitted_at"],
        "committed_at": r["committed_at"]}


def _absorb_candidate(conn, K, cid):
    r = conn.execute("SELECT * FROM candidate WHERE id=?", (cid,)).fetchone()
    if not r or cid in K["candidate"]:
        return
    K["candidate"][cid] = {
        "id": r["id"], "job_id": r["job_id"], "parcel_id": r["parcel_id"],
        "label": r["label"], "ring": _jloads(r["ring_json"]),
        "points": _jloads(r["points_json"]),
        "declared_area": r["declared_area"], "status": r["status"],
        "created_at": r["created_at"]}


def _dispute_item(r) -> dict:
    return {
        "id": r["id"], "parcel_a": r["parcel_a"], "parcel_b": r["parcel_b"],
        "job_a": r["job_a"], "job_b": r["job_b"], "cand_a": r["cand_a"],
        "cand_b": r["cand_b"], "base_chain": _jloads(r["base_chain_json"]),
        "geom_a": _jloads(r["geom_a_json"]), "geom_b": _jloads(r["geom_b_json"]),
        "anchor_start": _jloads(r["anchor_start"]),
        "anchor_end": _jloads(r["anchor_end"]),
        "status": r["status"], "decision": r["decision"],
        "decided_chain": _jloads(r["decided_chain_json"]),
        "decided_by": r["decided_by"], "decided_at": r["decided_at"],
        "result_versions": _jloads(r["result_versions"]),
        "created_at": r["created_at"]}


def _draft_item(r) -> dict:
    return {
        "id": r["id"], "target_version_id": r["target_version_id"],
        "corrected_ring": _jloads(r["corrected_ring_json"]),
        "reason": r["reason"], "status": r["status"],
        "created_by": r["created_by"], "created_at": r["created_at"],
        "previewed_at": r["previewed_at"], "preview": _jloads(r["preview_json"]),
        "fingerprint": _jloads(r["fingerprint_json"]),
        "published_at": r["published_at"], "publish_idem": r["publish_idem"],
        "result": _jloads(r["result_json"]), "cancelled_at": r["cancelled_at"]}


def _plan_item(r) -> dict:
    return {
        "id": r["id"], "draft_id": r["draft_id"], "request_key": r["request_key"],
        "status": r["status"], "execute_at": r["execute_at"],
        "registered_at": r["registered_at"], "created_by": r["created_by"],
        "parcels": _jloads(r["parcels_json"]),
        "fingerprint": _jloads(r["fingerprint_json"]),
        "attempts": r["attempts"], "completion_token": r["completion_token"],
        "completed_at": r["completed_at"], "result": _jloads(r["result_json"]),
        "paused_at": r["paused_at"], "pause_reason": r["pause_reason"],
        "pause_detail": _jloads(r["pause_detail_json"]),
        "cancelled_at": r["cancelled_at"]}


# ================================================================ 清单 / 切块
def _entry_id(kind: str, key) -> str:
    """kinds 字典的键在清单条目中的登记形态（复合键保持 'a:b' 串）。"""
    return key if isinstance(key, str) else str(key)


def _shared_edges(kinds) -> list[dict]:
    """闭包内各宗在来源时点的有效版本两两之间的重合界址边。"""
    current = {}
    for v in kinds["version"].values():
        if v["valid_to"] is None:
            current[v["parcel_id"]] = v
    edges, seen = [], set()
    pids = sorted(current)
    for i in range(len(pids)):
        for j in range(i + 1, len(pids)):
            va, vb = current[pids[i]], current[pids[j]]
            for seg in geo.shared_segments(va["ring"], vb["ring"]):
                a, b = sorted((va["id"], vb["id"]))
                key = (a, b, round(seg["length"], 3),
                       tuple(seg["midpoint"]))
                if key in seen:
                    continue
                seen.add(key)
                edges.append({"version_a": va["id"], "version_b": vb["id"],
                              "parcel_a": va["parcel_id"], "parcel_b": vb["parcel_id"],
                              "length": seg["length"], "midpoint": seg["midpoint"]})
    edges.sort(key=lambda e: (e["version_a"], e["version_b"], e["length"]))
    return edges


def _manifest(conn, items_by_key, kinds, *, seed_pids, at, created_at,
              created_by, chunk_size):
    shared = _shared_edges(kinds)
    payload = {
        "format": FORMAT,
        "source_at": at,
        "seed_parcel_ids": seed_pids,
        "shared_edges": shared,
        "items": {k: items_by_key[k] for k in sorted(items_by_key)},
    }
    raw = canonical(payload).encode("utf-8")
    payload_sha = sha256_hex(raw)
    chunks = [raw[i:i + chunk_size] for i in range(0, len(raw), chunk_size)]
    chunks_b64 = [_b64encode(c) for c in chunks]
    chunk_shas = [sha256_hex(c) for c in chunks]

    def entries(kind, tag):
        return [{"t": tag, "id": _entry_id(kind, i), "sha256": item_hash({"kind": kind, **v})}
                for i, v in sorted(kinds.get(kind, {}).items())]

    ent = []
    ent += entries("parcel", "PARCEL")
    ent += entries("point", "POINT")
    ent += entries("version", "VERSION")
    ent += [{"t": "VERSION_POINT", "id": _entry_id("version_point", i),
             "sha256": item_hash({"kind": "version_point", **v})}
            for i, v in sorted(kinds["version_point"].items())]
    ent += entries("op", "OP")
    ent += entries("dispute", "DISPUTE")
    ent += entries("certificate", "CERTIFICATE")
    ent += entries("job", "JOB")
    ent += entries("candidate", "CANDIDATE")
    ent += entries("draft", "DRAFT")
    ent += entries("plan", "PLAN")
    ent += [{"t": "PLAN_OCCUPANCY", "id": _entry_id("occupancy", i),
             "sha256": item_hash({"kind": "occupancy", **v})}
            for i, v in sorted(kinds["occupancy"].items())]
    ent += [{"t": "SHARED_EDGE",
             "id": f"{e['version_a']}|{e['version_b']}|{e['length']}",
             "sha256": item_hash(e)} for e in shared]
    ent.sort(key=lambda x: (x["t"], x["id"]))

    counts = {k: len(kinds.get(k, {})) for k in (
        "parcel", "point", "version", "version_point", "op", "dispute",
        "certificate", "job", "candidate", "draft", "plan", "occupancy")}
    counts["shared_edge"] = len(shared)

    package_id = ids.new_id("PKG")
    m = {
        "format": FORMAT,
        "package_id": package_id,
        "created_at": created_at,
        "created_by": created_by,
        "source_at": at,
        "seed_parcel_ids": seed_pids,
        "payload_sha256": payload_sha,
        "payload_size": len(raw),
        "chunk_size": chunk_size,
        "chunk_count": len(chunk_shas),
        "chunks_sha256": chunk_shas,
        "counts": counts,
        "entries": ent,
    }
    m["signature"] = sign_document(_signable(m))
    m["_chunks_b64"] = chunks_b64  # 信封随包返回，不参与签章
    return m


def _signable(manifest: dict) -> dict:
    return {k: v for k, v in manifest.items()
            if k not in ("signature", "_chunks_b64")}


def manifest_digest(manifest: dict) -> str:
    """清单（除签章外）的整体哈希：同包标识再导入时用于识别内容是否一致。"""
    return sha256_hex(canonical(_signable(manifest)).encode("utf-8"))


def verify_manifest_signature(manifest: dict) -> bool:
    sig = manifest.get("signature")
    return bool(sig) and verify_signature(_signable(manifest), sig)


# ================================================================ 组包 / 离线核验
def assemble(manifest: dict, chunks_b64: list[str | None]):
    """按序号拼回 payload 字节。返回 (raw|None, chunk_errors, missing)。"""
    n = int(manifest["chunk_count"])
    expected = manifest["chunks_sha256"]
    missing, errors, raws = [], [], []
    by_seq = {i: None for i in range(n)}
    for i, c in enumerate(chunks_b64[:n]):
        by_seq[i] = c
    for seq in range(n):
        c = by_seq.get(seq)
        if c is None or c == "":
            missing.append(seq)
            raws.append(b"")
            continue
        try:
            raw = _b64decode(c)
        except Exception as e:  # noqa: BLE001
            errors.append(_err("CHUNK_NOT_DECODABLE", "CHUNK", seq,
                               f"分块 {seq} base64 无法解码", {"error": str(e)}))
            raws.append(b"")
            continue
        if sha256_hex(raw) != expected[seq]:
            errors.append(_err(
                "CHUNK_HASH_MISMATCH", "CHUNK", seq,
                f"分块 {seq} 内容与清单哈希不一致",
                {"expected": expected[seq], "actual": sha256_hex(raw)}))
        raws.append(raw)
    if missing or errors:
        return None, errors, missing
    return b"".join(raws), [], []


def _err(code, entity, eid, message, detail=None) -> dict:
    return {"code": code, "entity": entity, "id": eid, "message": message,
            **({"detail": detail} if detail else {})}


def parse_payload(manifest: dict, raw: bytes):
    """解码并整体校验 payload，返回 (payload|None, errors)。"""
    if sha256_hex(raw) != manifest["payload_sha256"]:
        return None, [_err("PAYLOAD_HASH_MISMATCH", "PAYLOAD",
                           manifest.get("package_id"),
                           "拼回载荷的 SHA-256 与清单不一致")]
    try:
        payload = json.loads(raw.decode("utf-8"))
    except Exception as e:  # noqa: BLE001
        return None, [_err("PAYLOAD_NOT_DECODABLE", "PAYLOAD",
                           manifest.get("package_id"), f"载荷无法解析: {e}")]
    return payload, []


# ---------------------------------------------------------------- 包内闭包核验
def _item_id(kind: str, item: dict) -> str:
    if "id" in item:
        return str(item["id"])
    if kind == "version_point":
        return f"{item['version_id']}:{item['point_id']}"
    if kind == "occupancy":
        return f"{item['plan_id']}:{item['parcel_id']}"
    raise KeyError(f"{kind} 项缺少 id")


def _index(payload: dict) -> dict:
    idx: dict[str, dict] = {}
    for key, item0 in (payload.get("items") or {}).items():
        kind = key.split(":", 1)[0]  # 项内 kind 是业务字段（如 point.kind=corner），类型以键前缀为准
        item = {**item0, "_kind": kind}
        idx[(kind, _item_id(kind, item))] = item
    return idx


def _has(idx, kind, i) -> bool:
    return (kind, str(i)) in idx


def _parent_hashes_pkg(idx, vid) -> list[str]:
    """包内口径重算跨操作父哈希（对齐 versions._parent_hashes）。"""
    v = idx.get(("version", str(vid)))
    pid = v["parcel_id"] if v else None
    for item in idx.values():
        if item["_kind"] != "op" or item["type"] == "CORRECTION_PUBLISH":
            continue
        if str(vid) not in [str(c) for c in item["child_versions"]]:
            continue
        parents = item["parent_versions"]
        if item["type"] == "ADJUDICATION":
            kept = []
            for p in parents:
                pv = idx.get(("version", str(p)))
                if pv and pv["parcel_id"] == pid:
                    kept.append(p)
            parents = kept
        return [idx[("version", str(p))]["version_hash"]
                for p in parents if _has(idx, "version", p)]
    return []


def check_entries(manifest: dict, payload: dict) -> list[dict]:
    """逐项内容哈希 + 数量 + 项/清单双向齐备。"""
    errs = []
    have = {}
    for key, item in (payload.get("items") or {}).items():
        kind = key.split(":", 1)[0]
        i = _item_id(kind, item)
        have[(kind, i)] = item
    tags = {
        "PARCEL": "parcel", "POINT": "point", "VERSION": "version",
        "VERSION_POINT": "version_point", "OP": "op", "DISPUTE": "dispute",
        "CERTIFICATE": "certificate", "JOB": "job", "CANDIDATE": "candidate",
        "DRAFT": "draft", "PLAN": "plan", "PLAN_OCCUPANCY": "occupancy"}
    entry_tags = {**tags, "SHARED_EDGE": "shared_edge"}
    listed = set()
    for e in manifest.get("entries", []):
        kind = entry_tags.get(e["t"])
        if kind is None:
            errs.append(_err("ENTRY_TYPE_UNKNOWN", "ENTRY", e.get("id"),
                             f"未知条目类型 {e['t']}"))
            continue
        i = str(e["id"])
        listed.add((kind, i))
        if kind == "shared_edge":
            continue  # 共享边条目的内容在 payload.shared_edges，单独核对
        item = have.get((kind, i))
        if item is None:
            errs.append(_err("ENTRY_MISSING", kind, i, "清单登记的内容项不在载荷中"))
            continue
        if e.get("sha256") != item_hash(item):
            errs.append(_err("ENTRY_HASH_MISMATCH", kind, i,
                             "内容项哈希与清单登记不一致"))
    for (kind, i) in have:
        if (kind, i) not in listed:
            errs.append(_err("ENTRY_UNLISTED", kind, i, "载荷内容项未在清单登记"))
    counts = manifest.get("counts") or {}
    for tag, kind in tags.items():
        n = sum(1 for k in have if k[0] == kind)
        if counts.get(kind) is not None and counts[kind] != n:
            errs.append(_err("COUNTS_MISMATCH", kind, None,
                             f"{kind} 数量 {n} 与清单登记 {counts[kind]} 不一致"))
    edges = payload.get("shared_edges") or []
    if counts.get("shared_edge") is not None and counts["shared_edge"] != len(edges):
        errs.append(_err("COUNTS_MISMATCH", "shared_edge", None,
                         f"共享边数量 {len(edges)} 与清单登记 {counts['shared_edge']} 不一致"))
    listed_edges = {e["id"] for e in manifest.get("entries", [])
                    if e["t"] == "SHARED_EDGE"}
    for e in edges:
        eid = f"{e['version_a']}|{e['version_b']}|{e['length']}"
        if eid not in listed_edges:
            errs.append(_err("ENTRY_UNLISTED", "SHARED_EDGE", eid,
                             "共享边未在清单登记"))
    return errs


def check_references(manifest: dict, payload: dict) -> list[dict]:
    """引用关系最小闭包完整性（缺任何一个都定位到具体引用方）。"""
    idx = _index(payload)
    errs = []

    def req(kind, i, owner_kind, owner_id, rel):
        if i is None:
            return
        if not _has(idx, kind, i):
            errs.append(_err("REFERENCE_MISSING", owner_kind, owner_id,
                             f"{owner_kind} {owner_id} 引用的 {kind} {i}（{rel}）不在包内"))

    for v in idx.values():
        if v["_kind"] != "version":
            continue
        vid = v["id"]
        req("parcel", v["parcel_id"], "version", vid, "所属宗地")
        req("version", v["chain_parent_id"], "version", vid, "链前驱")
        req("version", v["base_version_id"], "version", vid, "基线版本")

    for item in idx.values():
        k = item["_kind"]
        if k == "version_point":
            iid = _item_id(k, item)
            req("version", item["version_id"], "version_point", iid, "版本")
            req("point", item["point_id"], "version_point", iid, "界址点")
        elif k == "op":
            for p in item["parent_versions"]:
                req("version", p, "op", item["id"], "父版本")
            for c in item["child_versions"]:
                req("version", c, "op", item["id"], "子版本")
            req("job", item["job_id"], "op", item["id"], "作业单")
            req("dispute", item["dispute_id"], "op", item["id"], "争议")
        elif k == "dispute":
            for f in ("job_a", "job_b"):
                req("job", item[f], "dispute", item["id"], f)
            for f in ("cand_a", "cand_b"):
                req("candidate", item[f], "dispute", item["id"], f)
            for x in item.get("result_versions") or []:
                req("version", x, "dispute", item["id"], "裁定结果版本")
        elif k == "candidate":
            req("job", item["job_id"], "candidate", item["id"], "作业单")
        elif k == "certificate":
            req("version", item["version_id"], "certificate", item["id"], "绑定版本")
        elif k == "draft":
            req("version", item["target_version_id"], "draft", item["id"], "目标版本")
        elif k == "plan":
            req("draft", item["draft_id"], "plan", item["id"], "生效草案")
        elif k == "occupancy":
            iid = _item_id(k, item)
            req("plan", item["plan_id"], "occupancy", iid, "计划")
            req("parcel", item["parcel_id"], "occupancy", iid, "占用地块")
    return errs


def check_chains_and_proofs(manifest: dict, payload: dict) -> list[dict]:
    """重算版本哈希链（含跨宗地父哈希）与证明签章、证明绑定。"""
    idx = _index(payload)
    errs = []
    versions = sorted((v for v in idx.values() if v["_kind"] == "version"),
                      key=lambda x: x["version_no"])
    for v in versions:
        prev = idx.get(("version", str(v["chain_parent_id"]))) \
            if v.get("chain_parent_id") else None
        expect = version_hash(
            parcel_id=v["parcel_id"], version_no=v["version_no"], ring=v["ring"],
            area=v["area"], base_version_id=v.get("base_version_id"),
            parent_hashes=_parent_hashes_pkg(idx, v["id"]),
            valid_from=v["valid_from"],
            prev_hash=prev["version_hash"] if prev else None,
            status=v["status"])
        if expect != v["version_hash"]:
            errs.append(_err("CHAIN_BROKEN", "version", v["id"],
                             "版本哈希链重算不一致（几何/血缘/前驱被改动）",
                             {"expected": expect, "actual": v["version_hash"]}))

    for c in (x for x in idx.values() if x["_kind"] == "certificate"):
        doc = c["document"]
        if not verify_signature(doc, c["signature"]):
            errs.append(_err("CERT_SIGNATURE_INVALID", "certificate", c["id"],
                             "证明文书 HMAC 签章无效"))
            continue
        v = idx.get(("version", c["version_id"]))
        if v and (doc.get("version_hash") != v["version_hash"]
                  or doc.get("ring") != v["ring"]):
            errs.append(_err("CERT_BINDING_MISMATCH", "certificate", c["id"],
                             "证明绑定的版本哈希/环与包内版本不一致"))
    return errs


def check_shared_edges(manifest: dict, payload: dict) -> list[dict]:
    """按包内当前版本环重算共享边，核对清单登记。"""
    idx = _index(payload)
    current = {}
    for v in idx.values():
        if v["_kind"] == "version" and v["valid_to"] is None:
            current[v["parcel_id"]] = v
    listed = {(e["version_a"], e["version_b"]): e
              for e in payload.get("shared_edges") or []}
    errs = []
    seen = set()
    pids = sorted(current)
    for i in range(len(pids)):
        for j in range(i + 1, len(pids)):
            va, vb = current[pids[i]], current[pids[j]]
            for seg in geo.shared_segments(va["ring"], vb["ring"]):
                key = (va["id"], vb["id"])
                e = listed.get(key) or listed.get((vb["id"], va["id"]))
                if not e:
                    errs.append(_err("SHARED_EDGE_MISSING", "shared_edge",
                                     f"{va['id']}|{vb['id']}",
                                     "重算出的共享边未在包内登记"))
                    continue
                if abs(e["length"] - seg["length"]) > 1e-6:
                    errs.append(_err("SHARED_EDGE_MISMATCH", "shared_edge",
                                     f"{va['id']}|{vb['id']}",
                                     "共享边长度与当前几何不符",
                                     {"listed": e["length"], "actual": seg["length"]}))
                seen.add((e["version_a"], e["version_b"]))
    for key in listed:
        if key not in seen:
            errs.append(_err("SHARED_EDGE_STALE", "shared_edge", "|".join(key),
                             "登记的共享边在当前几何上已不存在"))
    return errs


def internal_checks(manifest: dict, payload: dict) -> list[dict]:
    """完全离线的包内核验：清单/项/引用/链/证明/共享边。"""
    errs = []
    errs += check_entries(manifest, payload)
    errs += check_references(manifest, payload)
    errs += check_chains_and_proofs(manifest, payload)
    errs += check_shared_edges(manifest, payload)
    return errs


# ================================================================ 本地库冲突（只读）
def local_conflicts(conn, payload: dict) -> list[dict]:
    """本地已有同 id 但内容不同的版本/实体（可定位；不做任何写入）。"""
    idx = _index(payload)
    errs = []

    # ---- 宗地
    for p in (x for x in idx.values() if x["_kind"] == "parcel"):
        r = conn.execute("SELECT * FROM parcel WHERE id=?", (p["id"],)).fetchone()
        if r and r["label"] != p["label"]:
            errs.append(_err("PARCEL_CONFLICT", "parcel", p["id"],
                             "本地已有同号宗地但名称不同",
                             {"local_label": r["label"], "source_label": p["label"]}))

    # ---- 界址点
    for pt in (x for x in idx.values() if x["_kind"] == "point"):
        r = conn.execute("SELECT * FROM point WHERE id=?", (pt["id"],)).fetchone()
        if r and (abs(r["x"] - pt["x"]) > 1e-9 or abs(r["y"] - pt["y"]) > 1e-9):
            errs.append(_err("POINT_CONFLICT", "point", pt["id"],
                             "本地已有同号界址点但坐标不同",
                             {"local": [r["x"], r["y"]], "source": [pt["x"], pt["y"]]}))

    # ---- 版本（同 id 不同内容）+ 本地在版差异
    source_current = {}
    for v in (x for x in idx.values() if x["_kind"] == "version"):
        if v["valid_to"] is None:
            source_current[v["parcel_id"]] = v
    for v in (x for x in idx.values() if x["_kind"] == "version"):
        r = conn.execute("SELECT * FROM parcel_version WHERE id=?",
                         (v["id"],)).fetchone()
        if r and r["version_hash"] != v["version_hash"]:
            errs.append(_err("VERSION_CONFLICT", "version", v["id"],
                             "本地已有同 id 版本但哈希不同（内容分叉）",
                             {"local_hash": r["version_hash"],
                              "source_hash": v["version_hash"]}))
    for pid, sv in source_current.items():
        lv = vs.current_version(conn, pid)
        if lv is None:
            continue
        if lv["id"] == sv["id"] and lv["version_hash"] == sv["version_hash"]:
            continue
        in_pkg = _has(idx, "version", lv["id"])
        errs.append(_err("CURRENT_DIVERGED", "parcel", pid,
                         "本地该宗地的在版版本与来源时间点不一致",
                         {"local_current": lv["id"],
                          "source_current": sv["id"],
                          "local_version_in_package": in_pkg}))

    # ---- 挂接
    for vp in (x for x in idx.values() if x["_kind"] == "version_point"):
        r = conn.execute(
            "SELECT ord FROM version_point WHERE version_id=? AND point_id=?",
            (vp["version_id"], vp["point_id"])).fetchone()
        if r and r["ord"] != vp["ord"]:
            errs.append(_err("VERSION_POINT_CONFLICT", "version_point", vp["id"],
                             "本地挂接序号不同",
                             {"local_ord": r["ord"], "source_ord": vp["ord"]}))

    # ---- 争议
    for d in (x for x in idx.values() if x["_kind"] == "dispute"):
        r = conn.execute("SELECT * FROM dispute WHERE id=?", (d["id"],)).fetchone()
        if not r:
            continue
        local_sig = canonical([r["parcel_a"], r["parcel_b"], r["status"],
                               r["decision"], r["anchor_start"], r["anchor_end"],
                               r["geom_a_json"], r["geom_b_json"],
                               r["result_versions"]])
        source_sig = canonical([d["parcel_a"], d["parcel_b"], d["status"],
                                d["decision"], canonical(d["anchor_start"]),
                                canonical(d["anchor_end"]),
                                canonical(d["geom_a"]), canonical(d["geom_b"]),
                                canonical(d.get("result_versions"))])
        if local_sig != source_sig:
            errs.append(_err("DISPUTE_CONFLICT", "dispute", d["id"],
                             "本地已有同 id 争议但状态/几何/裁定不同"))

    # ---- 作业单 / 候选
    for j in (x for x in idx.values() if x["_kind"] == "job"):
        r = conn.execute("SELECT status,base_version_map FROM survey_job WHERE id=?",
                         (j["id"],)).fetchone()
        if r and (r["status"] != j["status"]
                  or _jloads(r["base_version_map"]) != j["base_version_map"]):
            errs.append(_err("JOB_CONFLICT", "job", j["id"],
                             "本地已有同号作业单但状态/基线不同"))
    for c in (x for x in idx.values() if x["_kind"] == "candidate"):
        r = conn.execute("SELECT status,ring_json FROM candidate WHERE id=?",
                         (c["id"],)).fetchone()
        if r and (r["status"] != c["status"]
                  or _jloads(r["ring_json"]) != c["ring"]):
            errs.append(_err("CANDIDATE_CONFLICT", "candidate", c["id"],
                             "本地已有同号候选但状态/环不同"))

    # ---- 操作血缘
    for o in (x for x in idx.values() if x["_kind"] == "op"):
        r = conn.execute(
            "SELECT type,parent_versions,child_versions FROM parcel_op WHERE id=?",
            (o["id"],)).fetchone()
        if not r:
            continue
        if (r["type"] != o["type"]
                or _jloads(r["parent_versions"]) != o["parent_versions"]
                or _jloads(r["child_versions"]) != o["child_versions"]):
            errs.append(_err("OP_CONFLICT", "op", o["id"],
                             "本地已有同 id 血缘操作但父子版本不同"))

    # ---- 证明
    for c in (x for x in idx.values() if x["_kind"] == "certificate"):
        r = conn.execute("SELECT signature,version_id,revoked FROM certificate WHERE id=?",
                         (c["id"],)).fetchone()
        if r and (r["signature"] != c["signature"]
                  or r["version_id"] != c["version_id"]):
            errs.append(_err("CERTIFICATE_CONFLICT", "certificate", c["id"],
                             "本地已有同号证明但签章/绑定版本不同"))

    # ---- 草案
    for d in (x for x in idx.values() if x["_kind"] == "draft"):
        r = conn.execute(
            "SELECT status,target_version_id,corrected_ring_json FROM correction_draft WHERE id=?",
            (d["id"],)).fetchone()
        if not r:
            continue
        if (r["status"] != d["status"]
                or r["target_version_id"] != d["target_version_id"]
                or _jloads(r["corrected_ring_json"]) != d["corrected_ring"]):
            errs.append(_err("DRAFT_CONFLICT", "draft", d["id"],
                             "本地已有同 id 草案但状态/目标/更正环不同"))

    # ---- 生效计划：同 id 内容差异 / request_key 占用 / 地块互斥
    for p in (x for x in idx.values() if x["_kind"] == "plan"):
        r = conn.execute(
            "SELECT status,draft_id,execute_at,request_key FROM effect_plan WHERE id=?",
            (p["id"],)).fetchone()
        if r and (r["status"] != p["status"] or r["draft_id"] != p["draft_id"]
                  or r["execute_at"] != p["execute_at"]
                  or r["request_key"] != p["request_key"]):
            errs.append(_err("PLAN_CONFLICT", "plan", p["id"],
                             "本地已有同 id 计划但状态/草案/时间/请求键不同"))
        if p["status"] in ("WAITING", "PAUSED"):
            other = plans_svc.get_plan_by_request_key(conn, p["request_key"], True)
            if other and other["id"] != p["id"]:
                errs.append(_err("PLAN_REQUEST_KEY_CONFLICT", "plan", p["id"],
                                 "相同 request_key 已被本地另一条活动计划占用",
                                 {"local_plan_id": other["id"],
                                  "local_status": other["status"]}))
            local_holders = {}
            for pid0 in p["parcels"]:
                for row in conn.execute(
                        "SELECT plan_id FROM plan_occupancy WHERE parcel_id=?",
                        (pid0,)).fetchall():
                    lp = conn.execute(
                        "SELECT status FROM effect_plan WHERE id=?",
                        (row["plan_id"],)).fetchone()
                    if lp and lp["status"] in ("WAITING", "PAUSED") \
                            and row["plan_id"] != p["id"]:
                        local_holders.setdefault(row["plan_id"], []).append(pid0)
            for lpid0, pids in local_holders.items():
                errs.append(_err("OCCUPANCY_CONFLICT", "plan", p["id"],
                                 "计划占用的地块与本地活动计划互斥",
                                 {"local_plan_id": lpid0, "parcels": sorted(pids)}))
    return errs


# ================================================================ 上传会话
def _session_row(conn, package_id):
    return conn.execute("SELECT * FROM snapshot_session WHERE package_id=?",
                        (package_id,)).fetchone()


def get_session(conn, package_id, *, now: str | None = None) -> dict | None:
    r = _session_row(conn, package_id)
    if not r:
        return None
    d = dict(r)
    d["manifest"] = json.loads(d["manifest_json"])
    d["chunk_conflicts"] = json.loads(d["chunk_conflicts_json"]) if d["chunk_conflicts_json"] else []
    d["verify_conflicts"] = json.loads(d["verify_conflicts_json"]) if d["verify_conflicts_json"] else None
    d["frozen_detail"] = json.loads(d["frozen_detail_json"]) if d["frozen_detail_json"] else None
    d["result"] = json.loads(d["result_json"]) if d["result_json"] else None
    return _with_window(d, now or ids.now_iso())


def _with_window(d: dict, now: str) -> dict:
    """附加窗口派生字段（剩余秒数/窗口是否开启），不写库。"""
    d["now"] = now
    if d.get("valid_until"):
        d["remaining_seconds"] = max(
            0, int((_parse_dt(d["valid_until"]) - _parse_dt(now)).total_seconds()))
        d["window_open"] = d["valid_until"] > now
    else:
        d["remaining_seconds"] = None
        d["window_open"] = True
    return d


def materialize_expiry(conn, package_id, *, now: str | None = None) -> dict | None:
    """惰性到期：窗口已过且尚未冻结 → 冻结（EXPIRED）。返回（可能更新后的）会话。"""
    s = get_session(conn, package_id, now=now)
    if not s:
        return None
    if s["status"] == IMPORTED or s["frozen"]:
        return s
    if s["valid_until"] and s["valid_until"] <= (now or s["now"]):
        return _freeze_session(
            conn, s, FR_EXPIRED, "接收窗口已到期，会话冻结；已验真分块、缺块与冲突已保留",
            {"valid_until": s["valid_until"], "expired_at": now or s["now"]},
            now=now, actor="system", bump_version=False)
    return s


def materialize_all_expiry(conn, *, now: str | None = None) -> int:
    """把所有已到期但未冻结/未导入的会话置为冻结；返回处理条数。"""
    now = now or ids.now_iso()
    rows = conn.execute(
        "SELECT package_id FROM snapshot_session "
        "WHERE COALESCE(frozen,0)=0 AND status<>? AND valid_until IS NOT NULL "
        "AND valid_until<=?", (IMPORTED, now)).fetchall()
    for r in rows:
        materialize_expiry(conn, r["package_id"], now=now)
    return len(rows)


def list_sessions(conn, *, now: str | None = None, materialize: bool = True):
    now = now or ids.now_iso()
    if materialize:
        materialize_all_expiry(conn, now=now)
    out = []
    for r in conn.execute(
            "SELECT package_id,status,chunk_count,created_at,updated_at,"
            "created_by,result_json,owner,valid_until,version_no,frozen,"
            "frozen_reason,frozen_at,reopened_at FROM snapshot_session "
            "ORDER BY created_at"):
        if r["valid_until"]:
            remaining = max(
                0, int((_parse_dt(r["valid_until"]) - _parse_dt(now)).total_seconds()))
            window_open = r["valid_until"] > now
        else:
            remaining = None
            window_open = True
        out.append({"package_id": r["package_id"], "status": r["status"],
                    "chunk_count": r["chunk_count"], "created_at": r["created_at"],
                    "updated_at": r["updated_at"], "created_by": r["created_by"],
                    "imported": bool(r["result_json"]),
                    "owner": r["owner"], "valid_until": r["valid_until"],
                    "version": r["version_no"],
                    "frozen": bool(r["frozen"]), "frozen_reason": r["frozen_reason"],
                    "frozen_at": r["frozen_at"], "reopened_at": r["reopened_at"],
                    "remaining_seconds": remaining, "window_open": window_open})
    return out


def _received(conn, package_id) -> dict[int, str]:
    return {r["seq"]: r["sha256"]
            for r in conn.execute(
                "SELECT seq,sha256 FROM snapshot_chunk WHERE package_id=?",
                (package_id,))}


def _chunk_conflict_report(conn, package_id):
    s = get_session(conn, package_id)
    return s["chunk_conflicts"] if s and s["chunk_conflicts"] else []


# ------------------------------------------------ 操作审计
def _event_seq(conn, package_id) -> int:
    r = conn.execute(
        "SELECT COALESCE(MAX(seq),0)+1 n FROM snapshot_session_event WHERE package_id=?",
        (package_id,)).fetchone()
    return r["n"]


def log_event(conn, package_id, action, *, actor=None, detail=None,
              ts: str | None = None):
    """登记一条会话操作审计（在调用方写事务内）。"""
    ts = ts or ids.now_iso()
    conn.execute(
        "INSERT INTO snapshot_session_event(package_id,seq,action,actor,detail_json,"
        "created_at) VALUES(?,?,?,?,?,?)",
        (package_id, _event_seq(conn, package_id), action, actor,
         json.dumps(detail, ensure_ascii=False) if detail is not None else None, ts))


def list_events(conn, package_id) -> list[dict]:
    return [{"seq": r["seq"], "action": r["action"], "actor": r["actor"],
             "detail": json.loads(r["detail_json"]) if r["detail_json"] else None,
             "created_at": r["created_at"]}
            for r in conn.execute(
                "SELECT seq,action,actor,detail_json,created_at "
                "FROM snapshot_session_event WHERE package_id=? ORDER BY seq",
                (package_id,)).fetchall()]


# ------------------------------------------------ 冻结
def _freeze_session(conn, s: dict, reason: str, message: str, detail: dict | None,
                    *, now: str | None = None, actor=None,
                    bump_version: bool) -> dict:
    """把会话置为 FROZEN：保留已收分块/缺块/冲突，拒绝继续写入。"""
    ts = now or ids.now_iso()
    sets = ["status='FROZEN'", "frozen=1", "frozen_reason=?", "frozen_at=?",
            "frozen_detail_json=?", "updated_at=?"]
    args: list = [reason, ts,
                  json.dumps({"message": message, **(detail or {})},
                             ensure_ascii=False), ts]
    if bump_version:
        sets.append("version_no=version_no+1")
    conn.execute(
        f"UPDATE snapshot_session SET {', '.join(sets)} WHERE package_id=?",
        (*args, s["package_id"]))
    log_event(conn, s["package_id"], "FREEZE", actor=actor, ts=ts,
              detail={"reason": reason, "message": message, **(detail or {})})
    return get_session(conn, s["package_id"], now=ts)


# ------------------------------------------------ 写入守卫
def _commit_before_raise(conn):
    """拒绝路径（冻结/失配/非负责人）在抛异常前先落库只增不改的状态。

    路由层 tx() 对异常统一 rollback；此处提前 commit 使惰性到期冻结、
    写入拒绝审计、重开失配记录得以保留（随后 rollback 为空操作，无害）。
    """
    conn.commit()


def _check_writable(conn, package_id, actor=None, *, now: str | None = None) -> dict:
    """上传分块/终检前：到期惰性冻结 → 冻结拒绝写入 → 负责人校验。"""
    ts = now or ids.now_iso()
    s = materialize_expiry(conn, package_id, now=ts)
    if not s:
        raise KeyError(package_id)
    if s["frozen"] or s["status"] == FROZEN:
        log_event(conn, package_id, "WRITE_DENIED", actor=actor, ts=ts,
                  detail={"reason": s["frozen_reason"], "state": s["status"]})
        pub = _public_session(conn, s)
        _commit_before_raise(conn)
        raise SessionFrozen(
            f"会话已冻结（{s['frozen_reason']}）：保留已收分块与冲突，但拒绝继续写入",
            reason=s["frozen_reason"], session=pub)
    if s["owner"] and actor != s["owner"]:
        log_event(conn, package_id, "WRITE_DENIED", actor=actor, ts=ts,
                  detail={"reason": "NOT_OWNER", "owner": s["owner"]})
        pub = _public_session(conn, s)
        _commit_before_raise(conn)
        raise NotOwner(session=pub, actor=actor)
    return s


def _check_owner(s: dict, actor):
    """管理动作的操作人必须是当前负责人（未指定负责人的会话不限制）。"""
    if s["owner"] and actor != s["owner"]:
        raise NotOwner(session=None, actor=actor)


# ------------------------------------------------ 管理动作幂等
def _request_fingerprint(action: str, payload: dict) -> str:
    """请求内容指纹（不含 request_key/version/actor/as_of，重放人仍是同一负责人）。"""
    keys = {
        "HANDOVER": ("new_owner",),
        "RENEW": ("valid_until", "ttl_minutes"),
        "FREEZE": ("reason",),
        "REOPEN": ("valid_until", "ttl_minutes"),
    }[action]
    return sha256_hex(canonical(
        {"action": action, **{k: payload.get(k) for k in keys}}).encode("utf-8"))


def _idempotent_begin(conn, package_id, action: str, payload: dict,
                      *, now: str) -> dict | None:
    """管理动作的公共前置：幂等重放 / 版本号校验 / 负责人校验。

    返回 {"mode":"replay","response": ...}（重复的**成功**请求）或
    {"mode":"run","session": s}（首次请求）。首次即被拒绝的动作（outcome=
    REJECTED，如重开重验失配）重放时抛 ReplayedDecision，原样回放首次拒绝；
    其他失败（版本冲突等）直接抛异常，且**不消费** request_key——
    客户端可携带新的版本号以同键重试成功。
    """
    key = (payload.get("request_key") or "").strip()
    if not key:
        raise SessionError("request_key 必填（管理动作必须携带幂等请求键）",
                           code="REQUEST_KEY_REQUIRED")
    expect_version = payload.get("version")
    if expect_version is None:
        raise SessionError("version 必填（会话版本号，防止并发覆盖）",
                           code="VERSION_REQUIRED")
    try:
        expect_version = int(expect_version)
    except (TypeError, ValueError):
        raise SessionError("version 必须是整数会话版本号", code="VERSION_INVALID")

    req = conn.execute("SELECT * FROM snapshot_request WHERE request_key=?",
                       (key,)).fetchone()
    s = materialize_expiry(conn, package_id, now=now)
    if not s:
        raise KeyError(package_id)

    if req:
        if req["package_id"] != package_id or req["action"] != action:
            raise SessionError(
                f"request_key 已用于另一个动作：{req['action']} {req['package_id']}",
                code="REQUEST_KEY_CONFLICT")
        fp = _request_fingerprint(action, payload)
        if req["fingerprint"] != fp:
            raise SessionError("相同 request_key 对应不同请求内容",
                               code="REQUEST_KEY_CONFLICT")
        first = json.loads(req["response_json"])
        if req["outcome"] == "REJECTED":
            # 首次判定即终局：不重新校验、不产生新状态，原样回放首次拒绝。
            # 该判定先于版本号/状态/负责人/已导入等一切现行检查——哪怕会话已被
            # 其他操作标识推进（解冻、甚至已完成导入），原操作标识仍永远对应
            # 这次拒绝响应（先提交可能由 materialize_expiry 落库的到期冻结——
            # 那是独立的系统状态；随后路由层的 rollback 即空操作）。
            _commit_before_raise(conn)
            raise ReplayedDecision(
                f"该操作标识（request_key）的首次{_ACTION_TEXT.get(action, action)}"
                "请求已被拒绝；判定为终局结果，重放只返回首次拒绝响应。"
                "后台文件修复也不会改变本标识的结果——请使用**新的 request_key 与"
                "最新会话版本号**重新发起",
                code=first.get("code", "REQUEST_REJECTED"),
                status_code=req["status_code"] or 409,
                payload={**first, "replayed": True},
                reason=first.get("reason"))
        if req["expect_version"] != expect_version:
            raise VersionConflict(
                "重复请求携带的版本号与首次请求不一致",
                session=_public_session(conn, s))
        return {"mode": "replay", "response": {**first, "replayed": True}}

    # 首次请求：会话版本号乐观锁（导入后的会话版本不再变化但一切管理动作被拒）
    if s["status"] == IMPORTED or s["result"]:
        log_event(conn, package_id, "MANAGE_DENIED", actor=payload.get("actor"),
                  ts=now, detail={"action": action, "reason": "SESSION_IMPORTED"})
        _commit_before_raise(conn)
        raise SessionFrozen(
            "会话已一次性导入：不得移交/续期/冻结/重开，导入结果不可变更",
            code="SESSION_IMPORTED", reason="IMPORTED",
            session=_public_session(conn, s))
    if s["version_no"] != expect_version:
        log_event(conn, package_id, "MANAGE_DENIED", actor=payload.get("actor"),
                  ts=now, detail={"action": action, "reason": "VERSION_CONFLICT",
                                  "expect_version": expect_version,
                                  "actual_version": s["version_no"]})
        pub = _public_session(conn, s)
        _commit_before_raise(conn)
        raise VersionConflict(
            f"会话版本号不匹配：客户端 {expect_version}，服务端当前 {s['version_no']}"
            "（会话已被其他操作更新，请刷新后重试）", session=pub)
    if s["owner"] and payload.get("actor") != s["owner"]:
        log_event(conn, package_id, "MANAGE_DENIED", actor=payload.get("actor"),
                  ts=now, detail={"action": action, "reason": "NOT_OWNER",
                                  "owner": s["owner"]})
        _commit_before_raise(conn)
        raise NotOwner(session=_public_session(conn, s),
                       actor=payload.get("actor"))
    return {"mode": "run", "session": s, "fingerprint":
            _request_fingerprint(action, payload)}


def _idempotent_commit(conn, package_id, action, payload, *, expect_version: int,
                       fingerprint: str, response: dict, ts: str,
                       outcome: str = "ACCEPTED", status_code: int | None = None):
    """动作首次判定后持久化幂等结果（与业务更新在同一写事务内）。

    outcome=REJECTED 表示首次请求即被拒绝（如重开重验失配）：该记录成为
    request_key 的**终局判定**，之后同键重放只回放本次拒绝，不再重新校验。
    """
    conn.execute(
        "INSERT INTO snapshot_request(request_key,package_id,action,expect_version,"
        "fingerprint,outcome,status_code,response_json,created_at) "
        "VALUES(?,?,?,?,?,?,?,?,?)",
        (payload["request_key"], package_id, action, expect_version, fingerprint,
         outcome, status_code,
         json.dumps(response, ensure_ascii=False), ts))


def _refresh_status(conn, package_id, ts):
    s = get_session(conn, package_id)
    if s["status"] in (IMPORTED, FROZEN) or s["frozen"]:
        return s["status"]
    conflicts = s["chunk_conflicts"]
    received = _received(conn, package_id)
    missing = [i for i in range(s["chunk_count"]) if i not in received]
    status = READY if not missing and not conflicts else UPLOADING
    conn.execute("UPDATE snapshot_session SET status=?,updated_at=? WHERE package_id=?",
                 (status, ts, package_id))
    return status


def create_import(conn, manifest: dict, created_by=None, *, owner=None,
                  valid_until=None, ttl_minutes=None, as_of=None) -> dict:
    """凭清单创建（或恢复/重放）上传会话。

    创建时可指定负责人 owner 与接收窗口（valid_until 绝对时刻或 ttl_minutes 时长，
    均缺省为不限期）。相同包标识 + 相同清单的重复请求恢复原会话。
    """
    if manifest.get("format") != FORMAT:
        raise ValueError("不支持的交换包格式（需 cadastre-snapshot-pkg/1）")
    package_id = manifest.get("package_id")
    digest = manifest_digest(manifest)
    ts = ids.as_of(as_of)
    existing = _session_row(conn, package_id) if package_id else None
    if existing:
        # 包标识相同：内容一致才允许恢复/续传；任何不同（含改后未重签）→ 409
        if existing["manifest_sha"] != digest:
            raise PackageConflict(f"包标识 {package_id} 已存在但清单内容不同", [{
                "code": "PACKAGE_ID_CONFLICT", "entity": "package",
                "id": package_id,
                "message": "相同包标识对应不同内容；拒绝覆盖原会话",
                "detail": {"existing_manifest_sha": existing["manifest_sha"],
                           "incoming_manifest_sha": digest}}])
        s = materialize_expiry(conn, package_id, now=ts)
        log_event(conn, package_id, "RESUME_SESSION", actor=created_by or owner,
                  ts=ts, detail={"replayed": True})
        return {"package_id": package_id, "status": s["status"], "replayed": True,
                "version": s["version_no"], "session": _public_session(conn, s)}
    if not verify_manifest_signature(manifest):
        raise ValueError("清单签章无效：MANIFEST_SIGNATURE_INVALID")
    owner = (owner or "").strip() or None
    window = _resolve_window(valid_until, ttl_minutes, ts)
    conn.execute(
        """INSERT INTO snapshot_session
           (package_id,manifest_sha,manifest_json,status,chunk_count,chunk_size,
            created_by,created_at,updated_at,owner,valid_until,version_no)
           VALUES(?,?,?,'UPLOADING',?,?,?,?,?,?,?,1)""",
        (package_id, digest, json.dumps(manifest, ensure_ascii=False),
         manifest["chunk_count"], manifest["chunk_size"], created_by, ts, ts,
         owner, window))
    log_event(conn, package_id, "CREATE", actor=owner or created_by, ts=ts,
              detail={"owner": owner, "valid_until": window,
                      "ttl_minutes": ttl_minutes})
    s = get_session(conn, package_id, now=ts)
    return {"package_id": package_id, "status": UPLOADING, "replayed": False,
            "version": 1, "session": _public_session(conn, s)}


class PackageConflict(Exception):
    """可定位的交换包冲突（路由层映射 409）。"""

    def __init__(self, message: str, conflicts: list[dict]):
        super().__init__(message)
        self.conflicts = conflicts


def put_chunk(conn, package_id: str, seq: int, raw: bytes, *, actor=None,
              as_of=None) -> dict:
    ts = ids.as_of(as_of)
    # 窗口/冻结/负责人守卫：到期或人工冻结后拒绝继续写入（分块/冲突原样保留）
    s = _check_writable(conn, package_id, actor, now=ts)
    manifest = s["manifest"]
    if seq < 0 or seq >= s["chunk_count"]:
        raise ValueError(
            f"分块序号越界：{seq}（应在 0..{s['chunk_count'] - 1}）")

    conflicts = [c for c in s["chunk_conflicts"] if c.get("seq") != seq]
    expected = manifest["chunks_sha256"][seq]
    actual = sha256_hex(raw)
    duplicate = False

    row = conn.execute(
        "SELECT sha256 FROM snapshot_chunk WHERE package_id=? AND seq=?",
        (package_id, seq)).fetchone()
    if actual == expected:
        if row:
            duplicate = True  # 同序号相同内容重复上传：幂等
        else:
            conn.execute(
                "INSERT INTO snapshot_chunk(package_id,seq,sha256,content) "
                "VALUES(?,?,?,?)", (package_id, seq, actual, raw))
    else:
        if row and row["sha256"] == expected:
            # 已收正确块：冲突上传不得覆盖
            conflicts.append({
                "code": "CHUNK_CONTENT_MISMATCH", "entity": "chunk", "id": seq,
                "seq": seq,
                "message": f"分块 {seq} 上传内容与已收正确块不一致（拒绝覆盖）",
                "detail": {"expected": expected, "incoming": actual,
                           "stored": "correct"}})
        else:
            conflicts.append({
                "code": "CHUNK_CONTENT_MISMATCH", "entity": "chunk", "id": seq,
                "seq": seq,
                "message": f"分块 {seq} 内容与清单哈希不一致",
                "detail": {"expected": expected, "incoming": actual}})

    conn.execute("UPDATE snapshot_session SET chunk_conflicts_json=?,updated_at=? "
                 "WHERE package_id=?",
                 (json.dumps(conflicts, ensure_ascii=False), ts, package_id))
    status = _refresh_status(conn, package_id, ts)
    if actual == expected and not duplicate:
        log_event(conn, package_id, "CHUNK_ACCEPTED", actor=actor, ts=ts,
                  detail={"seq": seq, "sha256": actual})
    elif actual != expected:
        log_event(conn, package_id, "CHUNK_CONFLICT", actor=actor, ts=ts,
                  detail={"seq": seq, "expected": expected, "incoming": actual})
    s = get_session(conn, package_id, now=ts)
    return {"package_id": package_id, "seq": seq, "sha256": actual,
            "expected_sha256": expected, "duplicate": duplicate,
            "accepted": actual == expected and not duplicate,
            "conflict": actual != expected,
            "status": status,
            "session": _public_session(conn, s)}


def _public_session(conn, s: dict) -> dict:
    received = _received(conn, s["package_id"])
    expected = s["manifest"]["chunks_sha256"]
    missing = [i for i in range(s["chunk_count"]) if i not in received]
    return {
        "package_id": s["package_id"], "status": s["status"],
        "chunk_count": s["chunk_count"], "chunk_size": s["chunk_size"],
        "received_seqs": sorted(received), "missing_seqs": missing,
        "received_count": len(received),
        "chunk_conflicts": s["chunk_conflicts"],
        "verify_conflicts": s.get("verify_conflicts"),
        "source_at": s["manifest"].get("source_at"),
        "created_at": s["created_at"], "updated_at": s["updated_at"],
        "created_by": s["created_by"],
        "result": s["result"],
        # ---- 接收窗口与移交 ----
        "owner": s.get("owner"),
        "valid_until": s.get("valid_until"),
        "remaining_seconds": s.get("remaining_seconds"),
        "window_open": s.get("window_open", True),
        "version": s.get("version_no", 1),
        "frozen": bool(s.get("frozen")),
        "frozen_reason": s.get("frozen_reason"),
        "frozen_at": s.get("frozen_at"),
        "frozen_detail": s.get("frozen_detail"),
        "reopened_at": s.get("reopened_at"),
        "imported": bool(s.get("result")),
        "manifest_summary": {
            "seed_parcel_ids": s["manifest"].get("seed_parcel_ids"),
            "counts": s["manifest"].get("counts"),
            "created_at": s["manifest"].get("created_at"),
            "created_by": s["manifest"].get("created_by")},
    }


def session_detail(conn, package_id, *, now: str | None = None,
                   materialize: bool = False) -> dict | None:
    """会话详情。默认**只读**——不因查看而落库到期冻结；
    窗口剩余时间按实时口径派生（已过期但尚未落冻结的会话仍显示 window_open=False）。
    materialize=True 时顺带惰性到期落库（写入路径/列表使用）。"""
    if materialize:
        s = materialize_expiry(conn, package_id, now=now)
    else:
        s = get_session(conn, package_id, now=now)
    if not s:
        return None
    return _public_session(conn, s)


# ================================================================ 离线预检
def precheck(conn, manifest: dict, chunks_b64=None, local: bool = True) -> dict:
    """接收方预检：清单签章 → 分块 → 载荷 → 包内闭包 →（可选）本地只读冲突。"""
    package_id = manifest.get("package_id")
    report = {
        "package_id": package_id,
        "manifest_signature_valid": verify_manifest_signature(manifest),
        "chunks": {"provided": 0, "expected": manifest.get("chunk_count"),
                   "missing": [], "errors": []},
        "payload_ok": False,
        "internal_conflicts": [],
        "local_conflicts": [] if local else None,
        "ready": False,
    }
    if not report["manifest_signature_valid"]:
        report["internal_conflicts"].append({
            "code": "MANIFEST_SIGNATURE_INVALID", "entity": "manifest",
            "id": package_id, "message": "清单签章无效（可能被篡改或非本签发机构）"})
        return report

    payload = None
    if chunks_b64:
        report["chunks"]["provided"] = len([c for c in chunks_b64 if c])
        raw, errors, missing = assemble(manifest, list(chunks_b64))
        report["chunks"]["missing"] = missing
        report["chunks"]["errors"] = errors
        if raw is not None:
            payload, perrs = parse_payload(manifest, raw)
            report["internal_conflicts"] += perrs
    else:
        # 无分块时仅能做清单层面的结构核验（条目内部需要载荷）
        report["chunks"] = None

    if payload is not None:
        report["payload_ok"] = True
        report["internal_conflicts"] += internal_checks(manifest, payload)
        if local:
            report["local_conflicts"] = local_conflicts(conn, payload)

    report["ready"] = report["manifest_signature_valid"] and \
        not report["internal_conflicts"] and \
        (not local or not report["local_conflicts"]) and \
        (report["chunks"] is None or (not report["chunks"]["missing"]
                                      and not report["chunks"]["errors"]))
    return report


# ================================================================ 终检 + 一次性导入
def finalize(conn, package_id: str, *, actor=None, as_of=None) -> dict:
    """全块齐备且全部匹配 → 单事务一次性导入；否则返回可定位冲突，数据库原样。

    终检与分块上传一样只允许**当前负责人**；会话到期/冻结后直接拒绝。
    已导入会话的重放无需负责人校验（结果不可变）。
    """
    ts = ids.as_of(as_of)
    existing = get_session(conn, package_id, now=ts)
    if not existing:
        raise KeyError(package_id)
    if existing["status"] == IMPORTED and existing["result"]:
        return {"status": IMPORTED, "package_id": package_id,
                "replayed": True, "session": _public_session(conn, existing),
                **existing["result"]}

    # 窗口/冻结/负责人守卫（在幂等结果兜底之前：未导入会话到期同样拒绝写入）
    s = _check_writable(conn, package_id, actor, now=ts)
    manifest = s["manifest"]

    # 幂等结果（理论上 IMPORTED 已返回，这里兜底）
    if s["result"]:
        return {"status": IMPORTED, "package_id": package_id, "replayed": True,
                "session": _public_session(conn, s), **s["result"]}

    # 1) 分块层面：缺块 / 同序号异内容
    if s["chunk_conflicts"]:
        return _balk(conn, s, "CHUNK_CONFLICT", ts,
                     chunk_conflicts=s["chunk_conflicts"], actor=actor)
    rows = conn.execute(
        "SELECT seq,content FROM snapshot_chunk WHERE package_id=? ORDER BY seq",
        (package_id,)).fetchall()
    by_seq = {r["seq"]: r["content"] for r in rows}
    missing = [i for i in range(s["chunk_count"]) if i not in by_seq]
    if missing:
        return _balk(conn, s, "MISSING_CHUNKS", ts, missing=missing, actor=actor)

    # 2) 组装 + 整体哈希
    raw = b"".join(by_seq[i] for i in range(s["chunk_count"]))
    payload, perrs = parse_payload(manifest, raw)
    if perrs:
        return _balk(conn, s, "CONFLICT", ts, internal_conflicts=perrs, actor=actor)

    # 3) 包内闭包（链断/证明引用缺失/共享边/条目哈希）
    internal = internal_checks(manifest, payload)
    local = local_conflicts(conn, payload)
    if internal or local:
        return _balk(conn, s, "CONFLICT", ts,
                     internal_conflicts=internal, local_conflicts=local, actor=actor)

    # 4) 全部匹配 → 单事务一次性导入
    result = _materialize(conn, payload, ts=ts)
    out = {"status": IMPORTED, "package_id": package_id, **result}
    conn.execute(
        "UPDATE snapshot_session SET status='IMPORTED',chunk_conflicts_json=NULL,"
        "verify_conflicts_json=NULL,updated_at=?,result_json=? WHERE package_id=?",
        (ts, json.dumps(out, ensure_ascii=False), package_id))
    log_event(conn, package_id, "FINALIZE_IMPORT", actor=actor, ts=ts,
              detail={"inserted": result.get("inserted")})
    s2 = get_session(conn, package_id, now=ts)
    return {**out, "session": _public_session(conn, s2)}


def _balk(conn, s, status, ts, *, missing=None, chunk_conflicts=None,
          internal_conflicts=None, local_conflicts=None, actor=None):
    """终检失败：标记会话 CONFLICT（缺块保持 UPLOADING 以便续传），数据库原样。"""
    report = {"missing": missing or [],
              "chunk_conflicts": chunk_conflicts or s["chunk_conflicts"],
              "internal_conflicts": internal_conflicts or [],
              "local_conflicts": local_conflicts or []}
    log_event(conn, s["package_id"], "FINALIZE_REJECTED", actor=actor, ts=ts,
              detail={"reason": status,
                      "n_internal": len(report["internal_conflicts"]),
                      "n_local": len(report["local_conflicts"]),
                      "n_missing": len(report["missing"]),
                      "n_chunk_conflicts": len(report["chunk_conflicts"])})
    if status == "MISSING_CHUNKS":
        conn.execute("UPDATE snapshot_session SET status='UPLOADING',updated_at=? "
                     "WHERE package_id=?", (ts, s["package_id"]))
        return {"status": "MISSING_CHUNKS", "package_id": s["package_id"],
                "missing_seqs": missing,
                "session": session_detail(conn, s["package_id"], now=ts)}
    # chunk_conflicts_json 只放同序号异内容明细；内部/本地终检冲突单独存放
    conn.execute(
        "UPDATE snapshot_session SET status='CONFLICT',chunk_conflicts_json=?,"
        "verify_conflicts_json=?,updated_at=? WHERE package_id=?",
        (json.dumps(report["chunk_conflicts"], ensure_ascii=False),
         json.dumps({"internal_conflicts": report["internal_conflicts"],
                     "local_conflicts": report["local_conflicts"]},
                    ensure_ascii=False),
         ts, s["package_id"]))
    return {"status": "CONFLICT", "package_id": s["package_id"], **report,
            "session": session_detail(conn, s["package_id"], now=ts)}


# ================================================================ 接收窗口：移交 / 续期 / 冻结 / 重开
def handover(conn, package_id: str, payload: dict) -> dict:
    """负责人移交。

    冻结（到期/人工）的会话也允许由当前负责人移交，但**不解除冻结**
    （续传须先重开重验）；已导入会话不得移交。
    必须携带 request_key（幂等）与 version（会话版本号乐观锁）。
    """
    ts = ids.as_of(payload.get("as_of"))
    begin = _idempotent_begin(conn, package_id, "HANDOVER", payload, now=ts)
    if begin["mode"] == "replay":
        return begin["response"]
    s = begin["session"]
    new_owner = (payload.get("new_owner") or "").strip()
    if not new_owner:
        raise SessionError("new_owner 必填（新负责人标识）", code="OWNER_REQUIRED")
    old_owner = s["owner"]
    conn.execute(
        "UPDATE snapshot_session SET owner=?,version_no=version_no+1,updated_at=? "
        "WHERE package_id=?", (new_owner, ts, package_id))
    log_event(conn, package_id, "HANDOVER", actor=payload.get("actor"), ts=ts,
              detail={"from_owner": old_owner, "to_owner": new_owner,
                      "frozen": bool(s["frozen"])})
    s2 = get_session(conn, package_id, now=ts)
    out = {"action": "HANDOVER", "package_id": package_id, "replayed": False,
           "version": s2["version_no"], "owner": new_owner,
           "previous_owner": old_owner, "status": s2["status"],
           "session": _public_session(conn, s2)}
    _idempotent_commit(conn, package_id, "HANDOVER", payload,
                       expect_version=s["version_no"],
                       fingerprint=begin["fingerprint"], response=out, ts=ts)
    return out


def renew(conn, package_id: str, payload: dict) -> dict:
    """续期（延长接收窗口）。只允许在窗口开启且未冻结期间由当前负责人操作。"""
    ts = ids.as_of(payload.get("as_of"))
    begin = _idempotent_begin(conn, package_id, "RENEW", payload, now=ts)
    if begin["mode"] == "replay":
        return begin["response"]
    s = begin["session"]
    if s["frozen"] or s["status"] == FROZEN:
        log_event(conn, package_id, "MANAGE_DENIED", actor=payload.get("actor"),
                  ts=ts, detail={"action": "RENEW",
                                  "reason": "FROZEN",
                                  "frozen_reason": s["frozen_reason"]})
        pub = _public_session(conn, s)
        _commit_before_raise(conn)
        raise SessionFrozen(
            f"会话已冻结（{s['frozen_reason']}），不能续期；请先重新开启（重验）",
            reason=s["frozen_reason"], session=pub)
    if payload.get("valid_until") is None and payload.get("ttl_minutes") is None:
        raise SessionError("续期必须给出 valid_until 或 ttl_minutes",
                           code="WINDOW_REQUIRED")
    new_until = _resolve_window(payload.get("valid_until"),
                                payload.get("ttl_minutes"), ts)
    old_until = s["valid_until"]
    conn.execute(
        "UPDATE snapshot_session SET valid_until=?,version_no=version_no+1,"
        "updated_at=? WHERE package_id=?", (new_until, ts, package_id))
    log_event(conn, package_id, "RENEW", actor=payload.get("actor"), ts=ts,
              detail={"from_valid_until": old_until, "to_valid_until": new_until})
    s2 = get_session(conn, package_id, now=ts)
    out = {"action": "RENEW", "package_id": package_id, "replayed": False,
           "version": s2["version_no"], "valid_until": new_until,
           "previous_valid_until": old_until,
           "remaining_seconds": s2["remaining_seconds"], "status": s2["status"],
           "session": _public_session(conn, s2)}
    _idempotent_commit(conn, package_id, "RENEW", payload,
                       expect_version=s["version_no"],
                       fingerprint=begin["fingerprint"], response=out, ts=ts)
    return out


def manual_freeze(conn, package_id: str, payload: dict) -> dict:
    """人工冻结：保留已验真分块、缺块状态与冲突记录，拒绝继续写入。"""
    ts = ids.as_of(payload.get("as_of"))
    begin = _idempotent_begin(conn, package_id, "FREEZE", payload, now=ts)
    if begin["mode"] == "replay":
        return begin["response"]
    s = begin["session"]
    reason = (payload.get("reason") or FR_MANUAL).strip()
    if reason != FR_MANUAL:
        raise SessionError("人工冻结原因必须是 MANUAL", code="REASON_INVALID")
    s2 = _freeze_session(
        conn, s, FR_MANUAL, "人工冻结：已验真分块、缺块与冲突已保留，拒绝继续写入",
        {"by": payload.get("actor")}, now=ts, actor=payload.get("actor"),
        bump_version=True)
    out = {"action": "FREEZE", "package_id": package_id, "replayed": False,
           "version": s2["version_no"], "status": FROZEN,
           "frozen_reason": FR_MANUAL, "frozen_at": s2["frozen_at"],
           "session": _public_session(conn, s2)}
    _idempotent_commit(conn, package_id, "FREEZE", payload,
                       expect_version=s["version_no"],
                       fingerprint=begin["fingerprint"], response=out, ts=ts)
    return out


def reopen_verification(conn, s: dict) -> list[dict]:
    """重开前重新核验清单签章与**现存分块**（不要求全块齐备；缺块可续传）。

    返回可定位的失配明细（空列表 = 通过）：
      * 清单签章失效；
      * 现存分块内容与清单哈希不一致（理论上被写入守卫挡住，这里兜底）；
      * 全块齐备时进一步做载荷/闭包/链/证明/共享边/本地只读核验，
        任何失配都给出 entity/id 级原因（与终检同一套可定位口径）。
    """
    manifest = s["manifest"]
    errs: list[dict] = []
    if not verify_manifest_signature(manifest):
        errs.append(_err("MANIFEST_SIGNATURE_INVALID", "manifest",
                         manifest.get("package_id"), "重开重验：清单签章无效"))
    rows = conn.execute(
        "SELECT seq,content,sha256 FROM snapshot_chunk WHERE package_id=? ORDER BY seq",
        (s["package_id"],)).fetchall()
    expected = manifest["chunks_sha256"]
    stored = {r["seq"]: r for r in rows}
    for seq, r in stored.items():
        if sha256_hex(r["content"]) != expected[seq] or r["sha256"] != expected[seq]:
            errs.append(_err("CHUNK_HASH_MISMATCH", "CHUNK", seq,
                             f"重开重验：现存分块 {seq} 与清单哈希不一致",
                             {"expected": expected[seq],
                              "actual": sha256_hex(r["content"])}))
    # 同序号异内容记录（重传正确块后本应清除；存在即视为失配）
    errs += s["chunk_conflicts"]
    # 全块齐备：把完整终检口径前置到重开（清单/载荷/闭包/链/本地）
    if not errs and len(stored) == s["chunk_count"]:
        raw = b"".join(stored[i]["content"] for i in range(s["chunk_count"]))
        payload, perrs = parse_payload(manifest, raw)
        if perrs:
            errs += perrs
        else:
            errs += internal_checks(manifest, payload)
            errs += local_conflicts(conn, payload)
    return errs


def reopen(conn, package_id: str, payload: dict) -> dict:
    """重新开启冻结会话。

    先重新核验清单与现存分块（全块齐备时含完整终检口径）：
    失配 → **保持冻结**（REOPEN_MISMATCH），返回可定位原因，版本号不递增；
    但该 request_key **被消费为终局判定**：拒绝响应持久化到幂等记录，之后同键
    重放（连续点击、网络重试）永远原样回放这次拒绝——即使后台文件随后被修正，
    原操作标识也不再重新校验、不产生任何状态变更；操作者须提交**新 request_key
    与最新会话版本号**才能再次校验。通过 → 解冻并按分块状态回到 UPLOADING/READY，
    会话版本号递增；可携带新的接收窗口（原窗口已过期时必填）。
    """
    ts = ids.as_of(payload.get("as_of"))
    begin = _idempotent_begin(conn, package_id, "REOPEN", payload, now=ts)
    if begin["mode"] == "replay":
        return begin["response"]
    s = begin["session"]
    if not (s["frozen"] or s["status"] == FROZEN):
        raise SessionError(
            f"会话当前为 {s['status']}，仅冻结会话可以重新开启",
            code="NOT_FROZEN")

    mismatches = reopen_verification(conn, s)
    if mismatches:
        # 保持冻结：记录可定位原因（版本号不递增），并把本次拒绝**终局化**到
        # request_key：同键重放永远回放本次拒绝（见 ReplayedDecision）
        message = "重开重验未通过：保持冻结（清单/现存分块/本地核验失配）"
        s2 = _freeze_session(
            conn, s, FR_REOPEN, message,
            {"mismatches": mismatches[:200], "mismatch_count": len(mismatches)},
            now=ts, actor=payload.get("actor"), bump_version=False)
        pub = _public_session(conn, s2)
        rejected_body = {
            "message": f"重开重验失败：{len(mismatches)} 项失配，会话保持冻结",
            "code": "REOPEN_MISMATCH", "reason": FR_REOPEN,
            "conflicts": mismatches, "session": pub}
        log_event(conn, package_id, "REOPEN_REJECTED", actor=payload.get("actor"),
                  ts=ts, detail={"mismatch_count": len(mismatches),
                                 "request_key": payload["request_key"],
                                 "codes": sorted({c.get("code") for c in
                                                  mismatches if c.get("code")})[:20]})
        _idempotent_commit(conn, package_id, "REOPEN", payload,
                           expect_version=s["version_no"],
                           fingerprint=begin["fingerprint"],
                           response=rejected_body, ts=ts,
                           outcome="REJECTED", status_code=409)
        _commit_before_raise(conn)
        raise ReopenMismatch(rejected_body["message"], conflicts=mismatches,
                            session=pub)

    # 新窗口：显式 > ttl > 原窗口（仍在未来才有效）
    new_until = _resolve_window(payload.get("valid_until"),
                                payload.get("ttl_minutes"), ts)
    if new_until is None:
        if s["valid_until"] and s["valid_until"] > ts:
            new_until = s["valid_until"]
        else:
            raise SessionError(
                "原接收窗口已过期：重开必须携带新的 valid_until 或 ttl_minutes",
                code="WINDOW_REQUIRED")

    conn.execute(
        "UPDATE snapshot_session SET status='UPLOADING',frozen=0,frozen_reason=NULL,"
        "frozen_at=NULL,frozen_detail_json=NULL,reopened_at=?,valid_until=?,"
        "version_no=version_no+1,updated_at=? WHERE package_id=?",
        (ts, new_until, ts, package_id))
    log_event(conn, package_id, "REOPEN", actor=payload.get("actor"), ts=ts,
              detail={"previous_frozen_reason": s["frozen_reason"],
                      "valid_until": new_until})
    _refresh_status(conn, package_id, ts)  # 现存分块决定 UPLOADING / READY
    s2 = get_session(conn, package_id, now=ts)
    out = {"action": "REOPEN", "package_id": package_id, "replayed": False,
           "version": s2["version_no"], "status": s2["status"],
           "valid_until": new_until, "remaining_seconds": s2["remaining_seconds"],
           "session": _public_session(conn, s2)}
    _idempotent_commit(conn, package_id, "REOPEN", payload,
                       expect_version=s["version_no"],
                       fingerprint=begin["fingerprint"], response=out, ts=ts)
    return out


# ================================================================ 保留期清理
def cleanup_expired(conn, *, retention_days: float | None = None,
                    as_of: str | None = None) -> dict:
    """清理冻结超过保留期、且**从未导入**的会话及其分块/审计/幂等记录。

    已导入（IMPORTED/result_json 非空）会话一律保留——导入结果不得清理；
    仍在接收窗口内或未冻结的会话不在清理范围。
    """
    ts = ids.as_of(as_of)
    days = float(config.SNAPSHOT_RETENTION_DAYS if retention_days is None
                 else retention_days)
    if days < 0:
        raise ValueError("retention_days 不能为负")
    cutoff = _iso(_parse_dt(ts) - timedelta(days=days))
    rows = conn.execute(
        "SELECT package_id,frozen_reason,frozen_at,owner FROM snapshot_session "
        "WHERE COALESCE(frozen,0)=1 AND result_json IS NULL AND frozen_at IS NOT NULL "
        "AND frozen_at<=?", (cutoff,)).fetchall()
    removed = []
    for r in rows:
        pid = r["package_id"]
        conn.execute("DELETE FROM snapshot_chunk WHERE package_id=?", (pid,))
        conn.execute("DELETE FROM snapshot_session_event WHERE package_id=?", (pid,))
        conn.execute("DELETE FROM snapshot_request WHERE package_id=?", (pid,))
        conn.execute("DELETE FROM snapshot_session WHERE package_id=?", (pid,))
        removed.append({"package_id": pid, "frozen_reason": r["frozen_reason"],
                        "frozen_at": r["frozen_at"], "owner": r["owner"]})
    return {"cleaned_at": ts, "retention_days": days, "cutoff": cutoff,
            "removed_count": len(removed), "removed": removed,
            "protected_imported": conn.execute(
                "SELECT COUNT(*) c FROM snapshot_session "
                "WHERE result_json IS NOT NULL").fetchone()["c"]}


# ================================================================ 一次性落库
def _materialize(conn, payload: dict, *, ts: str) -> dict:
    """在调用方持有的写事务内按外键顺序补齐缺失行；同 id 同内容行只对齐生命周期。"""
    idx = _index(payload)
    inserted = {k: 0 for k in ("parcel", "point", "version", "version_point",
                               "job", "candidate", "dispute", "op",
                               "certificate", "draft", "plan", "occupancy")}
    identical = dict(inserted)
    new_version_ids: set[str] = set()

    def exists(table, i):
        return conn.execute(f"SELECT 1 FROM {table} WHERE id=?", (i,)).fetchone()

    # 1) 宗地（含占用存根）
    for p in sorted((x for x in idx.values() if x["_kind"] == "parcel"),
                    key=lambda x: x["id"]):
        if exists("parcel", p["id"]):
            identical["parcel"] += 1
            continue
        conn.execute("INSERT INTO parcel(id,label,created_at) VALUES(?,?,?)",
                     (p["id"], p["label"], p["created_at"]))
        inserted["parcel"] += 1

    # 2) 界址点
    for pt in sorted((x for x in idx.values() if x["_kind"] == "point"),
                     key=lambda x: x["id"]):
        if exists("point", pt["id"]):
            identical["point"] += 1
            continue
        conn.execute(
            "INSERT INTO point(id,x,y,kind,origin,created_at) VALUES(?,?,?,?,?,?)",
            (pt["id"], pt["x"], pt["y"], pt["kind"], pt.get("origin", "import"),
             pt["created_at"]))
        inserted["point"] += 1

    # 3) 版本（按 version_no 拓扑序，保证链/基先行；同内容行对齐效力区间）
    local_before = {p["id"]: vs.current_version(conn, p["id"])
                    for p in idx.values() if p["_kind"] == "parcel"}
    versions = sorted((x for x in idx.values() if x["_kind"] == "version"),
                      key=lambda v: (v["parcel_id"], v["version_no"]))
    for v in versions:
        r = conn.execute("SELECT id,status,valid_to FROM parcel_version WHERE id=?",
                         (v["id"],)).fetchone()
        if r:
            identical["version"] += 1
            if r["status"] != v["status"] or r["valid_to"] != v["valid_to"]:
                conn.execute(
                    "UPDATE parcel_version SET status=?,valid_to=? WHERE id=?",
                    (v["status"], v["valid_to"], v["id"]))
            continue
        conn.execute(
            """INSERT INTO parcel_version
               (id,parcel_id,version_no,status,ring_json,area,declared_area,
                base_version_id,chain_parent_id,valid_from,valid_to,created_at,
                version_hash) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (v["id"], v["parcel_id"], v["version_no"], v["status"],
             json.dumps(v["ring"], ensure_ascii=False), v["area"],
             v.get("declared_area"), v.get("base_version_id"),
             v.get("chain_parent_id"), v["valid_from"], v["valid_to"],
             v["created_at"], v["version_hash"]))
        inserted["version"] += 1
        new_version_ids.add(v["id"])

    # 4) 挂接
    for vp in (x for x in idx.values() if x["_kind"] == "version_point"):
        if conn.execute(
                "SELECT 1 FROM version_point WHERE version_id=? AND point_id=?",
                (vp["version_id"], vp["point_id"])).fetchone():
            identical["version_point"] += 1
            continue
        conn.execute(
            "INSERT INTO version_point(version_id,point_id,ord) VALUES(?,?,?)",
            (vp["version_id"], vp["point_id"], vp["ord"]))
        inserted["version_point"] += 1

    # 5) 作业单 / 候选 / 争议
    for j in (x for x in idx.values() if x["_kind"] == "job"):
        if exists("survey_job", j["id"]):
            identical["job"] += 1
            continue
        conn.execute(
            """INSERT INTO survey_job
               (id,device_id,surveyor,status,base_version_map,base_parcel_ids,
                payload,error_json,created_at,submitted_at,committed_at)
               VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
            (j["id"], j["device_id"], j.get("surveyor"), j["status"],
             json.dumps(j["base_version_map"], ensure_ascii=False),
             json.dumps(j.get("base_parcel_ids") or [], ensure_ascii=False),
             json.dumps(j.get("payload"), ensure_ascii=False) if j.get("payload") else None,
             json.dumps(j.get("error"), ensure_ascii=False) if j.get("error") else None,
             j["created_at"], j.get("submitted_at"), j.get("committed_at")))
        inserted["job"] += 1

    for c in (x for x in idx.values() if x["_kind"] == "candidate"):
        if exists("candidate", c["id"]):
            identical["candidate"] += 1
            continue
        conn.execute(
            """INSERT INTO candidate
               (id,job_id,parcel_id,label,ring_json,points_json,declared_area,
                status,created_at) VALUES(?,?,?,?,?,?,?,?,?)""",
            (c["id"], c["job_id"], c.get("parcel_id"), c.get("label"),
             json.dumps(c["ring"], ensure_ascii=False),
             json.dumps(c.get("points") or [], ensure_ascii=False),
             c.get("declared_area"), c["status"], c["created_at"]))
        inserted["candidate"] += 1

    for d in (x for x in idx.values() if x["_kind"] == "dispute"):
        if exists("dispute", d["id"]):
            identical["dispute"] += 1
            continue
        conn.execute(
            """INSERT INTO dispute
               (id,parcel_a,parcel_b,job_a,job_b,cand_a,cand_b,base_chain_json,
                geom_a_json,geom_b_json,anchor_start,anchor_end,status,decision,
                decided_chain_json,decided_by,decided_at,result_versions,created_at)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (d["id"], d["parcel_a"], d["parcel_b"], d["job_a"], d["job_b"],
             d["cand_a"], d["cand_b"],
             json.dumps(d["base_chain"], ensure_ascii=False),
             json.dumps(d["geom_a"], ensure_ascii=False),
             json.dumps(d["geom_b"], ensure_ascii=False),
             json.dumps(d["anchor_start"]), json.dumps(d["anchor_end"]),
             d["status"], d.get("decision"),
             json.dumps(d.get("decided_chain"), ensure_ascii=False)
             if d.get("decided_chain") else None,
             d.get("decided_by"), d.get("decided_at"),
             json.dumps(d.get("result_versions"), ensure_ascii=False)
             if d.get("result_versions") else None,
             d["created_at"]))
        inserted["dispute"] += 1

    # 6) 血缘操作
    for o in sorted((x for x in idx.values() if x["_kind"] == "op"),
                    key=lambda x: x["created_at"]):
        if exists("parcel_op", o["id"]):
            identical["op"] += 1
            continue
        conn.execute(
            """INSERT INTO parcel_op
               (id,type,parent_versions,child_versions,params_json,job_id,
                dispute_id,area_note,created_at) VALUES(?,?,?,?,?,?,?,?,?)""",
            (o["id"], o["type"],
             json.dumps(o["parent_versions"], ensure_ascii=False),
             json.dumps(o["child_versions"], ensure_ascii=False),
             json.dumps(o.get("params") or {}, ensure_ascii=False),
             o.get("job_id"), o.get("dispute_id"),
             json.dumps(o.get("area_note"), ensure_ascii=False)
             if o.get("area_note") is not None else None,
             o["created_at"]))
        inserted["op"] += 1

    # 7) 证明
    for c in (x for x in idx.values() if x["_kind"] == "certificate"):
        if exists("certificate", c["id"]):
            identical["certificate"] += 1
            continue
        conn.execute(
            """INSERT INTO certificate
               (id,version_id,parcel_id,area,issued_at,document_json,signature,revoked)
               VALUES(?,?,?,?,?,?,?,?)""",
            (c["id"], c["version_id"], c["parcel_id"], c["area"], c["issued_at"],
             json.dumps(c["document"], ensure_ascii=False), c["signature"],
             1 if c.get("revoked") else 0))
        inserted["certificate"] += 1

    # 8) 草案
    for d in (x for x in idx.values() if x["_kind"] == "draft"):
        if exists("correction_draft", d["id"]):
            identical["draft"] += 1
            continue
        conn.execute(
            """INSERT INTO correction_draft
               (id,target_version_id,corrected_ring_json,reason,status,created_by,
                created_at,previewed_at,preview_json,fingerprint_json,published_at,
                publish_idem,result_json,cancelled_at)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (d["id"], d["target_version_id"],
             json.dumps(d["corrected_ring"], ensure_ascii=False), d.get("reason", ""),
             d["status"], d.get("created_by"), d["created_at"],
             d.get("previewed_at"),
             json.dumps(d.get("preview"), ensure_ascii=False) if d.get("preview") else None,
             json.dumps(d.get("fingerprint"), ensure_ascii=False) if d.get("fingerprint") else None,
             d.get("published_at"), d.get("publish_idem"),
             json.dumps(d.get("result"), ensure_ascii=False) if d.get("result") else None,
             d.get("cancelled_at")))
        inserted["draft"] += 1

    # 9) 计划（导入时清除来源方在途租约——租约不可跨节点携带）
    for p in (x for x in idx.values() if x["_kind"] == "plan"):
        if exists("effect_plan", p["id"]):
            identical["plan"] += 1
            continue
        conn.execute(
            """INSERT INTO effect_plan
               (id,draft_id,request_key,status,execute_at,registered_at,created_by,
                parcels_json,fingerprint_json,lease_owner,lease_at,attempts,
                completion_token,completed_at,result_json,paused_at,pause_reason,
                pause_detail_json,cancelled_at)
               VALUES(?,?,?,?,?,?,?,?,?,NULL,NULL,?,?,?,?,?,?,?,?)""",
            (p["id"], p["draft_id"], p["request_key"], p["status"], p["execute_at"],
             p["registered_at"], p.get("created_by"),
             json.dumps(p["parcels"], ensure_ascii=False),
             json.dumps(p.get("fingerprint"), ensure_ascii=False) if p.get("fingerprint") else None,
             p.get("attempts", 0), p.get("completion_token"),
             p.get("completed_at"),
             json.dumps(p.get("result"), ensure_ascii=False) if p.get("result") else None,
             p.get("paused_at"), p.get("pause_reason"),
             json.dumps(p.get("pause_detail"), ensure_ascii=False) if p.get("pause_detail") else None,
             p.get("cancelled_at")))
        inserted["plan"] += 1

    # 10) 占用
    for o in (x for x in idx.values() if x["_kind"] == "occupancy"):
        if conn.execute("SELECT 1 FROM plan_occupancy WHERE plan_id=? AND parcel_id=?",
                        (o["plan_id"], o["parcel_id"])).fetchone():
            identical["occupancy"] += 1
            continue
        conn.execute("INSERT INTO plan_occupancy(plan_id,parcel_id) VALUES(?,?)",
                     (o["plan_id"], o["parcel_id"]))
        inserted["occupancy"] += 1

    # ---- 导入结果：新旧版本对应关系 / 来源时间点 / 在版变化
    version_rows = []
    for v in versions:
        local_before_cur = local_before.get(v["parcel_id"])
        version_rows.append({
            "version_id": v["id"], "parcel_id": v["parcel_id"],
            "version_no": v["version_no"], "status": v["status"],
            "state": "NEW" if v["id"] in new_version_ids else "IDENTICAL",
            "source_current": v["valid_to"] is None,
            "local_current_before": local_before_cur["id"] if local_before_cur else None,
        })
    current_changes = []
    for p in (x for x in idx.values() if x["_kind"] == "parcel"):
        before_cur = local_before.get(p["id"])
        after_cur = vs.current_version(conn, p["id"])
        if (before_cur or {}).get("id") != (after_cur or {}).get("id"):
            current_changes.append({
                "parcel_id": p["id"],
                "from_version_id": before_cur["id"] if before_cur else None,
                "to_version_id": after_cur["id"] if after_cur else None})

    return {
        "imported_at": ts,
        "source_at": payload.get("source_at"),
        "inserted": inserted,
        "identical_skipped": identical,
        "versions": version_rows,
        "current_changes": current_changes,
        "counts": {k: inserted[k] + identical[k] for k in inserted},
    }

