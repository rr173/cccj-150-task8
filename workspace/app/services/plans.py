"""生效计划（Effective Plan）：校正草案登记未来执行 + 地块互斥占用 + 崩溃补跑。

登记（register_plan）
    * 仅允许"已完成影响计算"（OPEN 且预演 releasable）的更正草案登记；
    * 为计划指定未来执行时刻 execute_at，并对预演闭包里的**全部目标地块**建立
      互斥占用（plan_occupancy）；
    * 相同 request_key 在计划生效期间（WAITING/PAUSED）全局只能存在一条
      （部分唯一索引兜底并发）；任何占用交集都返回 CONFLICT + 冲突清单；
    * 登记即持久化完成令牌（completion_token，同时是发布幂等键）。

执行器（PlanExecutor / run_due / execute_plan）
    * 后台轮询到期（execute_at <= now）且持租约的 WAITING 计划；
    * 租约（lease_owner/lease_at）与完成令牌都持久化：进程崩溃/服务重启后，
      失效租约会被回收并补跑；
    * 执行前重算指纹（地块版本快照、争议状态、证书集合）并实时重算预演：
      与登记基线不同 → PAUSED，**数据库（宗地版本/血缘/证明）保持原样**，
      占用继续保留；无漂移且仍 releasable 才原子落账（发布），状态转
      COMPLETED。completion_token 作发布幂等键，保证不可二次落账。

改期 / 取消 / 恢复
    * reschedule：改期 WAITING/PAUSED（不重检基线；PAUSED 仍是 PAUSED）；
    * cancel：WAITING/PAUSED → CANCELLED，删除占用，request_key 释放；
    * resume：PAUSED 后"刷新基线"（重新预演+换指纹），无冲突即回 WAITING，
      仍有漂移/冲突则保持 PAUSED 并给出原因。
"""
from __future__ import annotations

import json
import threading
from datetime import datetime, timedelta, timezone

from .. import config
from . import ids
from .ids import as_of, now_iso
from . import corrections as cr
from . import versions as vs

# 状态：等待 / 暂停 / 完成 / 取消
WAITING, PAUSED, COMPLETED, CANCELLED = "WAITING", "PAUSED", "COMPLETED", "CANCELLED"
ACTIVE = (WAITING, PAUSED)
TERMINAL = (COMPLETED, CANCELLED)


# ================================================================ 时间
def canon_iso(v: str) -> str:
    """把入参时间归一为 UTC 的 ...Z 串（词序可比较），非法则 ValueError。"""
    s = str(v).strip()
    try:
        if s.endswith("Z"):
            dt = datetime.fromisoformat(s[:-1])
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = datetime.fromisoformat(s)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
    except ValueError as e:
        raise ValueError(f"无效时间（需 ISO-8601）: {v}") from e
    dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _is_future(iso_ts: str) -> bool:
    return canon_iso(iso_ts) > now_iso()


# ================================================================ 存取
def _parse_plan(r) -> dict:
    d = dict(r)
    for src, dst in (("parcels_json", "parcels"), ("fingerprint_json", "fingerprint"),
                     ("result_json", "result"), ("pause_detail_json", "pause_detail")):
        d[dst] = json.loads(d[src]) if d[src] else None
        del d[src]
    return d


def get_plan(conn, plan_id: str) -> dict | None:
    r = conn.execute("SELECT * FROM effect_plan WHERE id=?", (plan_id,)).fetchone()
    return _parse_plan(r) if r else None


def get_plan_by_request_key(conn, key: str, active_only: bool = True) -> dict | None:
    sql = "SELECT * FROM effect_plan WHERE request_key=?"
    if active_only:
        sql += f" AND status IN ({','.join('?' * len(ACTIVE))}) ORDER BY registered_at DESC"
        r = conn.execute(sql, (key, *ACTIVE)).fetchone()
    else:
        sql += " ORDER BY registered_at DESC"
        r = conn.execute(sql, (key,)).fetchone()
    return _parse_plan(r) if r else None


def _active_plan_for_draft(conn, draft_id: str, exclude_plan: str | None = None):
    q = ("SELECT id FROM effect_plan WHERE draft_id=? "
         f"AND status IN ({','.join('?' * len(ACTIVE))})")
    args = [draft_id, *ACTIVE]
    if exclude_plan:
        q += " AND id<>?"
        args.append(exclude_plan)
    return conn.execute(q, args).fetchone()


def list_plans(conn, status: str | None = None) -> list[dict]:
    sql = "SELECT * FROM effect_plan"
    args = ()
    if status:
        sql += " WHERE status=?"
        args = (status,)
    sql += " ORDER BY execute_at"
    return [_parse_plan(r) for r in conn.execute(sql, args).fetchall()]


def _parcel_label(conn, pid) -> str | None:
    r = conn.execute("SELECT label FROM parcel WHERE id=?", (pid,)).fetchone()
    return r["label"] if r else None


def _occupants(conn, parcel_ids, exclude_plan: str | None):
    """返回持有这些地块占用的活动计划 {plan_id: [parcel_id...]}。"""
    if not parcel_ids:
        return {}
    ph = ",".join("?" * len(parcel_ids))
    sql = (f"SELECT o.plan_id, o.parcel_id FROM plan_occupancy o "
           f"JOIN effect_plan p ON p.id=o.plan_id "
           f"WHERE o.parcel_id IN ({ph}) AND p.status IN ({','.join('?' * len(ACTIVE))})")
    args = [*parcel_ids, *ACTIVE]
    if exclude_plan:
        sql += " AND o.plan_id<>?"
        args.append(exclude_plan)
    out: dict[str, list[str]] = {}
    for r in conn.execute(sql, args).fetchall():
        out.setdefault(r["plan_id"], []).append(r["parcel_id"])
    return out


def _conflict_list(conn, parcel_ids, exclude_plan: str | None) -> list[dict]:
    out = []
    for pid, pids in _occupants(conn, parcel_ids, exclude_plan).items():
        other = get_plan(conn, pid)
        if not other:
            continue
        out.append({
            "plan_id": other["id"],
            "request_key": other["request_key"],
            "status": other["status"],
            "execute_at": other["execute_at"],
            "draft_id": other["draft_id"],
            "overlap_parcels": sorted(set(pids) & set(parcel_ids)),
            "overlap_labels": [
                {"parcel_id": q, "label": _parcel_label(conn, q)}
                for q in sorted(set(pids) & set(parcel_ids))],
        })
    out.sort(key=lambda c: c["plan_id"])
    return out


# ================================================================ 登记
def register_plan(conn, payload: dict) -> dict:
    """把一条已完成影响计算的更正草案登记为未来生效计划。"""
    did = payload["draft_id"]
    draft = cr.get_draft(conn, did)
    if not draft:
        raise ValueError("更正草案不存在")
    if draft["status"] == "PUBLISHED":
        raise ValueError("草案已发布，不能再登记生效计划")
    if draft["status"] == "CANCELLED":
        raise ValueError("草案已撤销，不能登记生效计划")
    preview = draft.get("preview")
    if not preview:
        raise ValueError("草案尚未完成影响计算（预演），不能登记生效计划")
    if not preview.get("releasable"):
        raise ValueError("草案预演未通过（存在错误），不能登记生效计划")

    execute_at = canon_iso(payload.get("execute_at"))
    if execute_at <= now_iso():
        raise ValueError("执行时间必须是未来时刻")

    key = (payload.get("request_key") or "").strip()
    if not key:
        raise ValueError("request_key 必填（相同请求只生成一条计划）")

    parcels = sorted(preview["affected_parcels"])

    # 相同请求键：活动期唯一；内容一致则幂等返回首次计划
    existing = get_plan_by_request_key(conn, key, active_only=True)
    if existing:
        if existing["draft_id"] == did and existing["execute_at"] == execute_at:
            return {"status": existing["status"], "plan": _public(conn, existing),
                    "replayed": True}
        raise ValueError(
            f"request_key 已被另一条生效计划占用：{existing['id']}（{existing['status']}）")

    # 该草案是否已有活动计划
    owner = _active_plan_for_draft(conn, did)
    if owner:
        raise ValueError(f"该草案已有生效中的计划：{owner['id']}")

    # 任何占用交集 → 冲突清单
    conflicts = _conflict_list(conn, parcels, None)
    if conflicts:
        return {"status": "CONFLICT", "draft_id": did, "request_key": key,
                "execute_at": execute_at, "parcels": parcels,
                "conflicts": conflicts}

    ts = as_of(payload.get("as_of"))
    plan_id = ids.new_id("PLAN")
    token = ids.new_id("TOKEN")
    fp = draft.get("fingerprint")
    conn.execute(
        """INSERT INTO effect_plan
           (id,draft_id,request_key,status,execute_at,registered_at,created_by,
            parcels_json,fingerprint_json,completion_token,attempts)
           VALUES(?,?,?,?,?,?,?,?,?,?,0)""",
        (plan_id, did, key, WAITING, execute_at, ts, payload.get("created_by"),
         json.dumps(parcels, ensure_ascii=False),
         json.dumps(fp, ensure_ascii=False), token))
    conn.executemany(
        "INSERT INTO plan_occupancy(plan_id,parcel_id) VALUES(?,?)",
        [(plan_id, p) for p in parcels])
    plan = get_plan(conn, plan_id)
    return {"status": WAITING, "plan": _public(conn, plan), "replayed": False}


# ================================================================ 改期 / 取消 / 恢复
def reschedule(conn, plan_id: str, payload: dict) -> dict:
    plan = get_plan(conn, plan_id)
    if not plan:
        raise ValueError("生效计划不存在")
    if plan["status"] in TERMINAL:
        raise ValueError(f"计划已{plan['status']}，不能改期")
    new_at = canon_iso(payload.get("execute_at"))
    if new_at <= now_iso():
        raise ValueError("新执行时间必须是未来时刻")
    conn.execute("UPDATE effect_plan SET execute_at=? WHERE id=?", (new_at, plan_id))
    plan = get_plan(conn, plan_id)
    return {"status": plan["status"], "plan": _public(conn, plan)}


def cancel(conn, plan_id: str) -> dict:
    plan = get_plan(conn, plan_id)
    if not plan:
        raise ValueError("生效计划不存在")
    if plan["status"] in TERMINAL:
        return {"plan_id": plan_id, "status": plan["status"], "already": True}
    ts = now_iso()
    # 调用方持有写事务（routers 用 tx()）；占用与状态在同一事务内一起释放
    conn.execute(
        "UPDATE effect_plan SET status='CANCELLED',cancelled_at=?,"
        "lease_owner=NULL,lease_at=NULL WHERE id=?", (ts, plan_id))
    conn.execute("DELETE FROM plan_occupancy WHERE plan_id=?", (plan_id,))
    plan = get_plan(conn, plan_id)
    return {"status": CANCELLED, "plan": _public(conn, plan)}


def resume(conn, plan_id: str, payload: dict | None = None) -> dict:
    """刷新基线（重新预演 + 换指纹）后恢复暂停计划。"""
    payload = payload or {}
    plan = get_plan(conn, plan_id)
    if not plan:
        raise ValueError("生效计划不存在")
    if plan["status"] == WAITING:
        return {"status": WAITING, "plan": _public(conn, plan), "already": True}
    if plan["status"] in TERMINAL:
        raise ValueError(f"计划已{plan['status']}，不能恢复")

    # 1) 按当前世界重新预演（草案回 OPEN、preview/fingerprint 覆盖），
    #    并把新基线同步回计划。cr 侧的活动计划守卫跳过本计划。
    preview = cr.re_rehearse(conn, plan["draft_id"], _by_plan=plan_id)
    new_parcels = sorted(preview["affected_parcels"])
    fp = preview["fingerprint"]
    ts = now_iso()

    # 2) 与其他活动计划的占用冲突（刷新后影响闭包可能扩大）
    conflicts = _conflict_list(conn, new_parcels, plan_id)

    # 替换占用集合为本计划最新目标地块
    conn.execute("DELETE FROM plan_occupancy WHERE plan_id=?", (plan_id,))
    conn.executemany(
        "INSERT INTO plan_occupancy(plan_id,parcel_id) VALUES(?,?)",
        [(plan_id, p) for p in new_parcels])

    if conflicts or not preview.get("releasable"):
        reason = "OCCUPANCY_CONFLICT" if conflicts else "BASELINE_INVALID"
        detail = {"conflicts": conflicts,
                  "live_errors": preview.get("errors", [])}
        conn.execute(
            "UPDATE effect_plan SET status='PAUSED',paused_at=?,pause_reason=?,"
            "pause_detail_json=?,parcels_json=?,fingerprint_json=?,"
            "lease_owner=NULL,lease_at=NULL WHERE id=?",
            (ts, reason, json.dumps(detail, ensure_ascii=False),
             json.dumps(new_parcels, ensure_ascii=False),
             json.dumps(fp, ensure_ascii=False), plan_id))
        return {"status": PAUSED, "plan": _public(conn, get_plan(conn, plan_id)),
                "reason": reason, "conflicts": conflicts,
                "live_errors": preview.get("errors", [])}

    # 3) 无冲突、仍 releasable → 回等待；若已到期由执行器下一tick补跑
    conn.execute(
        "UPDATE effect_plan SET status='WAITING',paused_at=NULL,pause_reason=NULL,"
        "pause_detail_json=NULL,parcels_json=?,fingerprint_json=?,"
        "lease_owner=NULL,lease_at=NULL WHERE id=?",
        (json.dumps(new_parcels, ensure_ascii=False),
         json.dumps(fp, ensure_ascii=False), plan_id))
    return {"status": WAITING, "plan": _public(conn, get_plan(conn, plan_id))}


# ================================================================ 执行器
def _due_waiting(conn, now: str):
    return conn.execute(
        "SELECT id FROM effect_plan WHERE status=? AND execute_at<=? "
        "ORDER BY execute_at", (WAITING, now)).fetchall()


def run_due(conn, *, now: str | None = None, owner: str | None = None) -> list[dict]:
    """获取到期计划的持久租约并逐条执行（单节点串行）。

    返回每条计划的执行结果摘要。租约在同一写事务内先持久化，再执行；
    崩溃在执行前/执行中：租约持久存在但未落账，重启后等租约失效回收补跑。
    """
    now = now or now_iso()
    owner = owner or f"exec-{ids.new_id('')}"
    results = []
    due = [r["id"] for r in _due_waiting(conn, now)]
    for plan_id in due:
        # 原子抢租约：仅当未持租约时成功（其余执行器实例不会重复领取）；
        # 租约在执行前就持久化，崩溃后由回收逻辑在 TTL/重启时补跑。
        cur = conn.execute(
            "SELECT lease_owner FROM effect_plan WHERE id=?",
            (plan_id,)).fetchone()
        if cur is None or cur["lease_owner"]:
            continue  # 计划消失，或已被其他执行器实例持有
        conn.execute(
            "UPDATE effect_plan SET lease_owner=?,lease_at=?,attempts=attempts+1 "
            "WHERE id=? AND lease_owner IS NULL", (owner, now, plan_id))
        results.append(execute_plan(conn, plan_id, lease_owner=owner, execute_ts=now))
    return results


def execute_plan(conn, plan_id: str, *, lease_owner: str | None = None,
                 execute_ts: str | None = None) -> dict:
    """执行单条已持租约的计划。调用方需已取得租约并持有写事务。

    * 执行前指纹比对（版本快照/争议/证书）+ 实时重算预演：
      有漂移或不再 releasable → PAUSED，宗地数据保持原样；
    * 否则原子发布落账 → COMPLETED，completion_token 为幂等键，不可二次落账；
    * 草案在计划等待期已被（手动）发布 → 计划直接标记 COMPLETED（external），
      不再重复落账。
    """
    plan = get_plan(conn, plan_id)
    if not plan:
        raise ValueError("生效计划不存在")
    execute_ts = execute_ts or now_iso()

    # 幂等：已完成（任何路径）直接返回首次结果，绝不二次落账
    if plan["status"] == COMPLETED:
        return {"plan_id": plan_id, "status": COMPLETED,
                "already": True, "result": plan["result"]}
    if plan["status"] == CANCELLED:
        return {"plan_id": plan_id, "status": CANCELLED, "already": True}

    draft = cr.get_draft(conn, plan["draft_id"])

    # 草案已被手动发布：世界已按同一草案落账，计划收口为完成（不重复发布）
    if draft and draft["status"] == "PUBLISHED" and draft.get("result"):
        conn.execute(
            "UPDATE effect_plan SET status='COMPLETED',completed_at=?,"
            "result_json=?,lease_owner=NULL,lease_at=NULL WHERE id=?",
            (execute_ts, json.dumps(
                {**draft["result"], "external": True}, ensure_ascii=False), plan_id))
        conn.execute("DELETE FROM plan_occupancy WHERE plan_id=?", (plan_id,))
        return {"plan_id": plan_id, "status": COMPLETED, "external": True,
                "result": draft["result"]}
    if not draft or draft["status"] == "CANCELLED":
        return _pause(conn, plan, execute_ts, "SNAPSHOT_DRIFT",
                      {"message": "所依据的更正草案已撤销或不存在"})

    # 1) 实时漂移检测（地块版本快照 / 争议状态 / 证书集合）
    fp_now = cr.fingerprint(conn, draft["preview"])
    drift = cr.diff_fingerprint(conn, plan["fingerprint"], fp_now, {})
    # 2) 实时重算预演（不落账），检查世界变化后是否仍 releasable
    live = cr.rehearse(conn, draft["target_version_id"],
                       draft["corrected_ring"], draft["reason"])
    if drift or not live["releasable"]:
        return _pause(
            conn, plan, execute_ts, "SNAPSHOT_DRIFT",
            {"drift_nodes": drift, "live_errors": live["errors"]})

    # 3) 原子发布；completion_token 作发布幂等键 → 至多落账一次
    resp = cr.publish(
        conn, {"draft_id": plan["draft_id"], "idem_key": plan["completion_token"],
               "published_by": lease_owner or "plan-executor",
               "as_of": plan["execute_at"]},
        _by_plan=plan_id)

    if resp.get("status") == "DRIFTED":
        # publish 内已做实时漂移/预演，兜底转暂停
        return _pause(conn, plan, execute_ts, "SNAPSHOT_DRIFT",
                      {"drift_nodes": resp.get("drift_nodes", []),
                       "live_errors": resp.get("live_errors", [])})

    result = {k: v for k, v in resp.items() if k != "status"}
    conn.execute(
        "UPDATE effect_plan SET status='COMPLETED',completed_at=?,"
        "result_json=?,lease_owner=NULL,lease_at=NULL WHERE id=?",
        (execute_ts, json.dumps(result, ensure_ascii=False), plan_id))
    conn.execute("DELETE FROM plan_occupancy WHERE plan_id=?", (plan_id,))
    return {"plan_id": plan_id, "status": COMPLETED, "result": result}


def _pause(conn, plan: dict, ts: str, reason: str, detail: dict) -> dict:
    """计划转暂停：只动计划/草案状态，宗地版本/血缘/证明数据库保持原样。"""
    conn.execute(
        "UPDATE effect_plan SET status='PAUSED',paused_at=?,pause_reason=?,"
        "pause_detail_json=?,lease_owner=NULL,lease_at=NULL WHERE id=?",
        (ts, reason, json.dumps(detail, ensure_ascii=False), plan["id"]))
    # 草案同步为 DRIFTED（语义一致：基线已漂移），但不动任何版本
    conn.execute("UPDATE correction_draft SET status='DRIFTED' WHERE id=? "
                 "AND status='OPEN'", (plan["draft_id"],))
    return {"plan_id": plan["id"], "status": PAUSED, "reason": reason, **detail}


# ================================================================ 租约回收
def reclaim_stale_leases(conn, ttl_seconds: float | None = None, now: str | None = None):
    """崩溃/重启后回收失效租约：WAITING 计划的过期租约清空，等待下一 tick 补跑。"""
    ttl = config.PLAN_LEASE_TTL_SECONDS if ttl_seconds is None else ttl_seconds
    now_dt = _parse_dt(now or now_iso())
    cutoff = (now_dt - timedelta(seconds=ttl)).strftime(
        "%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    rows = conn.execute(
        "SELECT id FROM effect_plan WHERE status=? AND lease_owner IS NOT NULL "
        "AND lease_at IS NOT NULL AND lease_at<?", (WAITING, cutoff)).fetchall()
    for r in rows:
        conn.execute(
            "UPDATE effect_plan SET lease_owner=NULL,lease_at=NULL WHERE id=? "
            "AND status=?", (r["id"], WAITING))
    return [r["id"] for r in rows]


def clear_all_waiting_leases(conn):
    """服务（重新）启动时立即清空所有 WAITING 租约，让补跑无需等待 TTL。"""
    rows = conn.execute(
        "SELECT id FROM effect_plan WHERE status=? AND lease_owner IS NOT NULL",
        (WAITING,)).fetchall()
    conn.execute(
        "UPDATE effect_plan SET lease_owner=NULL,lease_at=NULL "
        "WHERE status=?", (WAITING,))
    return [r["id"] for r in rows]


def _parse_dt(s: str) -> datetime:
    s = s[:-1] + "+00:00" if s.endswith("Z") else s
    return datetime.fromisoformat(s)


# ================================================================ 对外视图
def _public(conn, plan: dict) -> dict:
    out = {k: plan[k] for k in (
        "id", "draft_id", "request_key", "status", "execute_at", "registered_at",
        "created_by", "parcels", "lease_owner", "lease_at", "attempts",
        "completion_token", "completed_at", "result", "paused_at",
        "pause_reason", "pause_detail", "cancelled_at")}
    # occupancy 只反映**当前仍持有**的占用行（完成/取消后已删除即为空）
    rows = conn.execute(
        "SELECT parcel_id FROM plan_occupancy WHERE plan_id=? ORDER BY parcel_id",
        (plan["id"],)).fetchall()
    out["occupancy"] = [
        {"parcel_id": r["parcel_id"], "label": _parcel_label(conn, r["parcel_id"])}
        for r in rows]
    return out


def public_detail(conn, plan: dict, *, live_drift: bool = False) -> dict:
    d = _public(conn, plan)
    d["draft"] = {"id": plan["draft_id"],
                  "status": cr.get_draft(conn, plan["draft_id"])["status"]}
    if live_drift and plan["status"] in ACTIVE:
        draft = cr.get_draft(conn, plan["draft_id"])
        if draft and draft.get("preview") and plan.get("fingerprint"):
            fp_now = cr.fingerprint(conn, draft["preview"])
            d["live_drift"] = cr.diff_fingerprint(
                conn, plan["fingerprint"], fp_now, {})
    return d


# ================================================================ 后台执行器
class PlanExecutor:
    """单节点后台轮询执行器：持久租约 + 完成令牌保证重启补跑、不可二次落账。"""

    def __init__(self):
        from ..db import tx
        self._tx = tx
        self._stop = threading.Event()
        self._thread = None
        self.interval = config.PLAN_POLL_SECONDS

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self.bootstrap()
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._loop, name="plan-executor", daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)

    def bootstrap(self):
        """服务启动：清掉所有 WAITING 租约（上一进程的在途租约）以便补跑。"""
        try:
            with self._tx() as conn:
                clear_all_waiting_leases(conn)
        except Exception:  # noqa: BLE001  （库未就绪等启动竞态，下一tick自愈）
            pass

    def _loop(self):
        while not self._stop.wait(self.interval):
            self.tick()

    def tick(self, now: str | None = None):
        """一轮：回收失效租约 → 领取并执行到期计划。"""
        try:
            with self._tx() as conn:
                reclaim_stale_leases(conn)
                return run_due(conn, now=now)
        except Exception as e:  # noqa: BLE001  执行器不能因单轮异常退出
            return [{"error": str(e)}]


_executor: PlanExecutor | None = None
_executor_lock = threading.Lock()


def get_executor() -> PlanExecutor:
    global _executor
    with _executor_lock:
        if _executor is None:
            _executor = PlanExecutor()
        return _executor
