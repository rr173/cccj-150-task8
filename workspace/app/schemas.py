"""API 数据模型（请求/响应）。"""
from __future__ import annotations

from typing import Optional, Any
from pydantic import BaseModel, Field


# ---------------- 外业采集 ----------------
class SurveyPointIn(BaseModel):
    local_id: str = Field(description="设备端本地点号（回传时关联照片）")
    x: float
    y: float
    kind: str = "corner"                      # corner / intermediate
    accuracy_m: Optional[float] = None       # GNSS/全站仪精度（米）
    marker_type: Optional[str] = None        # 界标类型：钢钉/石桩/刻字...
    photo_ids: list[str] = []                # 上传照片后返回的 media id
    confirmed_by: list[str] = []             # 相邻权利人（姓名/证件后四位）


class ParcelCandidateIn(BaseModel):
    parcel_id: Optional[str] = None           # 空 = 新宗地
    label: Optional[str] = None
    ring: list[list[float]]                   # 界址环（可带重复终点）
    points: list[SurveyPointIn] = []
    declared_area: Optional[float] = None     # 外业手簿声明面积
    owner: Optional[str] = None               # 本宗地权利人
    owner_id_no: Optional[str] = None


class OwnerConfirmationIn(BaseModel):
    parcel_id: Optional[str] = None
    owner_name: str
    owner_id_no: Optional[str] = None
    segment_desc: Optional[str] = None
    confirmed: bool = True


class SubmissionIn(BaseModel):
    job_id: Optional[str] = None
    idem_key: Optional[str] = None            # 幂等键（离线重放）
    device_id: str = "device-1"
    surveyor: Optional[str] = None
    base_version_map: dict[str, Optional[str]] = Field(
        default_factory=dict,
        description="{parcel_id: 作业所依据的版本id}；新宗地键使用 'NEW:label'",
    )
    candidates: list[ParcelCandidateIn]
    confirmations: list[OwnerConfirmationIn] = []
    as_of: Optional[str] = None               # 可注入提交时刻（测试时间轴）


class RingError(BaseModel):
    code: str
    message: str
    detail: Any = None


class SubmitResponse(BaseModel):
    job_id: str
    status: str                               # COMMITTED / DISPUTED / REJECTED
    accepted: list[dict]
    disputes: list[dict]
    errors: list[RingError]


# ---------------- 离线作业单 ----------------
class JobCreateIn(BaseModel):
    device_id: str = "device-1"
    surveyor: Optional[str] = None
    parcel_ids: list[Optional[str]] = []


class BundleIn(BaseModel):
    device_id: str = "device-1"
    parcel_ids: list[Optional[str]] = []
    surveyor: Optional[str] = None


# ---------------- 裁定 ----------------
class AdjudicationItemIn(BaseModel):
    dispute_id: str
    decision: str = Field(pattern="^(A|B|REVISED)$")
    # REVISED 时给出修订链；A/B 可省略
    chain_a: Optional[list[list[float]]] = None
    chain_b: Optional[list[list[float]]] = None
    decided_by: Optional[str] = None
    as_of: Optional[str] = None


# ---------------- 分割 / 合并 / 更正 ----------------
class SplitIn(BaseModel):
    parent_version_id: str
    children: list[ParcelCandidateIn] = Field(min_length=2)
    note: Optional[str] = None
    as_of: Optional[str] = None


class MergeIn(BaseModel):
    parent_version_ids: list[str] = Field(min_length=2)
    result: ParcelCandidateIn
    note: Optional[str] = None
    as_of: Optional[str] = None


class CorrectionIn(BaseModel):
    version_id: str
    corrected: ParcelCandidateIn
    reason: str
    as_of: Optional[str] = None


# ---------------- 二阶段历史更正（草案 / 预演 / 发布 / 撤销）----------------
class CorrectionDraftIn(BaseModel):
    version_id: str
    corrected: ParcelCandidateIn
    reason: str = ""
    created_by: Optional[str] = None
    as_of: Optional[str] = None


class CorrectionPublishIn(BaseModel):
    draft_id: Optional[str] = None
    idem_key: Optional[str] = None
    published_by: Optional[str] = None
    as_of: Optional[str] = None


# ---------------- 生效计划（未来执行 / 互斥占用 / 暂停恢复）----------------
class PlanRegisterIn(BaseModel):
    draft_id: str
    execute_at: str = Field(description="计划生效（落账）时刻，ISO-8601，需为未来")
    request_key: str = Field(description="相同请求键只能生成一条活动计划")
    created_by: Optional[str] = None
    as_of: Optional[str] = None


class PlanRescheduleIn(BaseModel):
    execute_at: str
    as_of: Optional[str] = None


# ---------------- 地籍快照交换包（导出 / 离线预检 / 分块导入）----------------
class SnapshotExportIn(BaseModel):
    parcel_ids: list[str] = Field(
        description="按时间点选取的一组宗地（以各宗在该时点有效版本为种子）")
    at: str = Field(description="来源时间点，ISO-8601；只导出该时刻已生效的内容")
    created_by: Optional[str] = None
    chunk_size: int = 16384               # 分块大小（字节），默认 16 KiB
    include_plans: bool = True
    as_of: Optional[str] = None           # 可注入打包时刻（测试）


class SnapshotImportIn(BaseModel):
    manifest: dict = Field(description="交换包清单（manifest.json 的内容）")
    created_by: Optional[str] = None
    owner: Optional[str] = Field(
        default=None,
        description="当前负责人；指定后上传分块/终检只允许该负责人（缺省不限制，向后兼容）")
    valid_until: Optional[str] = Field(
        default=None,
        description="接收窗口截止时刻 ISO-8601；与 ttl_minutes 二选一；均缺省为不限期")
    ttl_minutes: Optional[float] = Field(
        default=None, description="接收窗口时长（分钟），自创建时刻起算")
    as_of: Optional[str] = None           # 可注入创建时刻（测试）


class SnapshotHandoverIn(BaseModel):
    """负责人移交：必须携带幂等请求键与会话版本号。"""
    new_owner: str = Field(description="新负责人标识")
    request_key: str = Field(description="幂等请求键（重复请求返回首次结果）")
    version: int = Field(description="客户端持有的会话版本号（防并发覆盖）")
    actor: Optional[str] = Field(default=None, description="操作人（须为当前负责人）")
    as_of: Optional[str] = None


class SnapshotRenewIn(BaseModel):
    """续期：只在接收窗口开启期间允许；必须携带幂等请求键与版本号。"""
    valid_until: Optional[str] = None      # 新的窗口截止时刻（与 ttl_minutes 二选一）
    ttl_minutes: Optional[float] = None
    request_key: str
    version: int
    actor: Optional[str] = None
    as_of: Optional[str] = None


class SnapshotFreezeIn(BaseModel):
    """人工冻结：保留已验真分块/缺块/冲突，拒绝继续写入。"""
    request_key: str
    version: int
    actor: Optional[str] = None
    reason: str = "MANUAL"
    as_of: Optional[str] = None


class SnapshotReopenIn(BaseModel):
    """重新开启：重验清单与现存分块，失配保持冻结并返回可定位原因。"""
    request_key: str
    version: int
    actor: Optional[str] = None
    valid_until: Optional[str] = None      # 重开后的新窗口（原窗口已过期时必填之一）
    ttl_minutes: Optional[float] = None
    as_of: Optional[str] = None


class SnapshotFinalizeIn(BaseModel):
    """终检请求体（可选；负责人也可走 X-Cadastre-Actor 头）。"""
    actor: Optional[str] = None
    as_of: Optional[str] = None


class SnapshotCleanupIn(BaseModel):
    """保留期清理：只清理冻结超过保留期且从未导入的会话；已导入永不清理。"""
    retention_days: Optional[float] = None
    as_of: Optional[str] = None


class SnapshotPrecheckIn(BaseModel):
    manifest: dict
    chunks: list[str] = Field(
        default_factory=list,
        description="可选：与导出一致的 base64 分块；提供时做组装/内容级离线预检")
    local: bool = True                    # 是否只读检查与本地数据库的冲突


# ---------------- 证明 ----------------
class IssueCertIn(BaseModel):
    version_id: str
    as_of: Optional[str] = None


# ---------------- 通用响应 ----------------
class Ok(BaseModel):
    ok: bool = True
    data: Any = None
