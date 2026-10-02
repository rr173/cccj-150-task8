# 地籍界址测量与宗地版本管理平台

离线外业采集 → 回网提交候选边界 → 几何校验 → 并发共享边争议 → 仲裁裁定 →
分割/合并/历史更正 → 不可变版本与哈希链 → 历史证明持续可验 → 任意时间点查询。

## 快速开始

```bash
pip install -r requirements.txt
python3 seed.py                                   # 初始化并种入甲/乙两宗相邻地块
python3 -m uvicorn app.main:app --host 0.0.0.0 --port 8000
# 浏览器打开 http://localhost:8000
```

运行测试：

```bash
python3 -m pytest tests/ -q          # 233 项：业务规则 + HTTP 集成 + 回执中继（水位/隔离/回执/租约/并发/CLI/RFC8032/密钥轮换/撤销/离线信任包）
python3 demo_live.py                 # 完整 HTTP 端到端演示（需先启动服务并 seed）

# 交换包交付回执中继：命令行模拟器 / 独立核验器（可不启动 HTTP 直连库演示）
RELAY_DATA_DIR=data/relay python3 -m app.relay.cli --sender site-A demo
RELAY_DATA_DIR=data/relay python3 -m app.relay.cli --sender site-A recovery
RELAY_DATA_DIR=data/relay python3 -m app.relay.cli --institution DEMO-IN rotate-demo
python3 -m app.relay.verifier REQ-1.receipt.json          # 完全离线核验回执包
python3 -m app.relay.verifier TRUST-1.trust.json          # 离线核验机构信任包
python3 -m app.relay.verifier --trust TRUST-1.trust.json REQ-1.receipt.json  # 以信任根定位回执
# 网页界面：启动服务后打开 http://localhost:8000/relay
```

## 需求 → 实现 对照

| 需求 | 实现位置 |
| --- | --- |
| 离线采集界址点/精度/界标照片/相邻权利人确认 | `services/sync.py`（bundle/job/media）、`schemas.py`（SurveyPointIn/OwnerConfirmationIn） |
| 回网提交候选边界 | `POST /api/sync/submit`（幂等键 idem_key，断网重放安全） |
| 多边形闭合校验 | `validation.validate_ring` → `NOT_CLOSED`（回点与首点偏差 > 5cm） |
| 面积容差 | `AREA_TOL_RATIO=2%` → `AREA_MISMATCH`（声明面积 vs 鞋带公式实算） |
| 共享边一致 | `geo.shared_segments` + 逐重合段偏差 → `SHARED_INCONSISTENT` / `SHARED_NEIGHBOR_UNCONFIRMED` |
| 不能自交 | 线段对精确求交 → `SELF_INTERSECT`（另含零长边、面积非正、非法重叠） |
| 两组测量同改共享边不得后提交覆盖 | 提交时对比**库内当前版本**与作业基线，按「宗地对+折点锚点」检测分歧，双方方案几何不一致即生成 `dispute`（A/B 差异几何并存），整批挂起不落版本 |
| 相邻权利人确认 | 单方改边必须携带确认；确认后共享链以"只替换该片段"方式传播到邻宗候选并成对落库 |
| 裁定只能选/修订争议片段 | `POST /api/disputes/adjudicate`：decision=A/B/REVISED；修订链端点必须吸附锚点；服务端用当前环替换争议段重建 |
| 裁定不能重写未争议边界 | 服务端强制补链逐点不动（Hausdorff ≤ 5cm），越界即 400；并校验两宗共享边一致、面积变化等量反向 |
| 分割保持面积关系 | `POST /api/ops/split`：子宗并集与父宗**全等**且面积和守恒（0.5%） |
| 合并保持面积关系 | `POST /api/ops/merge`：结果与父宗并集全等、面积守恒 |
| 历史更正（即时） | `POST /api/ops/correction`：仅可更正当前版本；旧版标 `ANNULLED` 但**行不删**；`parcel_op` 记录 SPLIT/MERGE/CORRECTION/ADJUDICATION 的父子版本 |
| **历史更正（二阶段可预演）** | `POST /api/correction-drafts`（建草案+预演）→ `POST /api/correction-drafts/{id}/publish`（原子发布分叉链）；`rehearse` 重新预演、`cancel` 撤销；草案不改在版宗地，基线漂移（后代/争议/证明变化）禁止套用旧预演；旧链与旧证明保留 |
| **生效计划（未来执行/互斥占用/崩溃补跑）** | `POST /api/effect-plans` 把 releasable 草案登记到未来时刻，对全部目标地块建互斥占用；相同 `request_key` 活动期唯一，占用交集返回冲突清单；后台执行器靠**持久租约 + 完成令牌**重启补跑且不可二次落账；执行前快照/争议/证书变化 → `PAUSED`（数据库原样），可 `resume`（刷新基线）/ `reschedule` / `cancel`（释放占用与请求键）|
| 已签发历史证明继续可验证 | `certificate` HMAC-SHA256 绑定版本哈希；`GET /api/certificates/{id}/verify` 重算签名+几何+哈希链；宗地后续变化不影响旧证明 |
| 地图编辑界面 | `static/index.html` + Canvas（平移缩放、加点/拖点、精度/界标/照片、A/B 差异叠加、锚点间修订、时间轴、血缘图），零外部依赖 |
| 离线同步接口 | `/api/sync/bundle`（底图+基线版本+容差+邻宗）、`/jobs/{id}/media`、`/validate`、`/submit`、`/jobs/{id}` |
| 按时间点查询 | `GET /api/parcels/{id}?at=ISO` 与 `GET /api/at/{ts}`，半开区间 `[valid_from, valid_to)` |
| **地籍快照交换包** | `POST /api/snapshots/export`（时间点+最小闭包导出）、`/precheck`（无网络离线预检）、`/imports`（分块乱序/重复/断点续传，全匹配才一次性导入；见下节） |
| **接收窗口与移交** | 建会话指定负责人/有效期；分块与终检仅当前负责人；到期/人工冻结保留分块缺块冲突但拒绝写入；移交/续期/冻结/重开携带 `request_key` 幂等键 + `version` 会话版本号防并发覆盖；重开重验清单与现存分块（失配保持冻结、可定位）；已导入不可重开/清理；保留期清理；操作审计（见下节） |

## 版本模型

* `parcel_version` 不可变：几何、面积、生效时间、上一版本哈希、跨操作父哈希共同进入 SHA-256；
  新版本另起一行，旧版本置 `SUPERSEDED/ANNULLED`（状态流转不计入哈希）。
* 争议期不落新版本，后提交方不会覆盖先落库方；`candidate` 与 `dispute` 保留双方原始几何。
* 分割子版本与合并结果版本的哈希包含全部父版本哈希，构成跨宗地 DAG 血缘。

## 二阶段历史更正（草案 / 预演 / 原子发布）

历史更正扩展为"先建可预演草案、再原子发布"，避免预演即生效、也避免在过期基线上套用旧结论。

**阶段一 DRAFT（只预演，不改世界）**

`POST /api/correction-drafts` 校验更正环后生成一条 `correction_draft`（`status=OPEN`），
**不产生任何 `parcel_version`、不改变在版宗地**。服务端沿 `parcel_op` 血缘从目标版本
向**下游**闭包遍历所有受影响后代（SPLIT 子宗、MERGE 结果、CORRECTION/ADJUDICATION 链），
用弧长参数传导（`geo.transfer_fragments`）逐节点推演，预览里给出：

* `new_ring`：每个后代传导后的新几何（非整环替换；内部分割线顶点保留，落在被更正
  片段上的切口随片段移动；切口落在片段中间也正确——支持任意方向/跨环接缝的更正）；
* `old_area / new_area / area_delta`：旧面积、新面积与面积差；
* `lineage`：血缘变化（由哪个 SPLIT/MERGE/… 操作产生、父版本是谁、发布后的新 id 映射）；
* 跨节点守恒校验（分割子宗面积和=更正后父宗、合并结果=父宗并集）、自交/重叠校验；
  任一不过则 `releasable=false`（草案保留、错误可见、不可发布）。
* 同时保存一份世界状态**指纹**（受影响宗地全部版本哈希/状态/效力区间、相关争议、相关证明）。

**阶段二 PUBLISH（原子 + 分叉 + 幂等）**

`POST /api/correction-drafts/{id}/publish` 在单事务内：

1. **实时漂移检测**：重算指纹与建案时比对。受影响后代出现新增/修改/消失、当前版本
   变化、相关争议被裁定/新增、相关证明新签发/吊销 → 返回 `status=DRIFTED`，
   **不套用旧预演、不写任何版本**，在 `drift_nodes` 标出漂移节点，草案置 `DRIFTED` 保留；
2. 同时**实时重算预演**，世界变化导致传导结果不再 releasable 同样拒绝；
3. 无漂移才原子生成整条更正链：每个受影响版本一个新版本行，`chain_parent_id` 指向
   同宗地新链锚点，旧行/旧哈希原样保留（**旧链与新链平行分叉、各自哈希可验**）；
   血缘写 `CORRECTION_REPLAY`（逐原操作）+ `CORRECTION_PUBLISH`（总结）。
   只有血缘**叶子**新版本在版（已分割父宗不与其子宗同时在版，面积不重复）；
4. 已签发证明绑定旧版本哈希，新链不影响其验真；历史时间点查询仍返回旧几何。
5. 相同发布请求（同一草案/同一 `idem_key`）重放返回首次结果。

`rehearse` 在漂移后按当前世界重新预演（草案回 `OPEN`）；`cancel` 撤销 OPEN/DRIFTED
草案——草案从未产生版本，所以撤销没有任何半成品残留。草案状态机：
`OPEN → PUBLISHED` / `OPEN|DRIFTED → CANCELLED` / `OPEN ⇄ DRIFTED`。

前端「分割/合并/更正」页建草案，「更正草案」页查看逐节点影响/漂移、重新预演、
批准、撤销；地图上以**琥珀虚线**叠加草案目标环与后代预演几何，明确区别于在版版本（蓝/绿实线）。

## 生效计划（登记未来执行 / 互斥占用 / 崩溃补跑）

完成影响计算（`releasable`）的更正草案可登记一条**生效计划**，在未来时刻自动原子落账。

**登记（`POST /api/effect-plans`）**

* 请求含 `draft_id / execute_at（必须未来）/ request_key`；
* 对预演闭包里的**全部目标地块**建立互斥占用（`plan_occupancy`）；
* **相同 `request_key`** 在 `WAITING/PAUSED` 期间全局唯一（DB 部分唯一索引兜底）：
  完全相同的重复请求幂等返回首次计划，同键不同内容 400；
* 与任何活动计划存在**占用交集**时不建立任何占用，返回 `status=CONFLICT` 与
  冲突清单（对方计划 id/状态/执行时间/交集地块）。

**执行器（后台轮询，`PLAN_POLL_SECONDS` 可调）**

* 每轮先回收失效租约（`PLAN_LEASE_TTL_SECONDS`），再为到期（`execute_at<=now`）
  的 WAITING 计划**在同一写事务内先持久化租约**（`lease_owner/lease_at`）后执行；
* 执行前重算基线指纹（**地块版本快照 / 纠纷状态 / 证书集合**）并实时重算预演：
  任一不同或不再 releasable → `PAUSED`，**宗地版本/血缘/证明数据库保持原样**，
  占用继续保留、草案同步标 `DRIFTED`；
* 无漂移才原子发布落账 → `COMPLETED`。**完成令牌**（登记时生成并持久化的
  `completion_token`）同时作为发布幂等键，重复补跑只返回首次结果，**不可二次落账**；
* 服务重启（startup bootstrap）立即清空上个进程遗留在 WAITING 计划上的租约，
  到期计划由新进程补跑；硬崩溃在落账前后都安全（租约持久、令牌幂等）。

**暂停后处置 / 状态机**

`WAITING → COMPLETED / PAUSED`；`PAUSED → WAITING（resume）/ CANCELLED`；
`WAITING|PAUSED → CANCELLED`。

* `POST /{id}/reschedule`：改期（PAUSED 改期后仍暂停，需先恢复）；
* `POST /{id}/resume`：按当前世界**重新预演、刷新指纹基线**（闭包扩大则同步占用，
  仍冲突/不可发布则保持 PAUSED 并给原因），干净则回 WAITING；
* `POST /{id}/cancel`：取消并删除全部占用、释放 `request_key`，**之后可用同键重新登记**。

前端「生效计划」页：左侧栏按 **等待 / 暂停 / 完成 / 取消** 过滤列计划与占用对象，
右侧为横向时间轴（含"现在"刻度）与详情/操作面板（改期、恢复基线、取消释放）；
地图上以**紫色虚线**描出被占用地块，选中计划高亮。

## 地籍快照交换包（离线导出 / 分块导入 / 一次性核验）

跨节点（如外业站 → 县中心）按**时间点**交付一宗地籍快照的离线交换模块。

**导出（`POST /api/snapshots/export`）**

* 入参 `parcel_ids + at + chunk_size`：种子取各宗在 `at` 时点的有效版本；
* 服务端计算**最小闭包**（不动点扩张）：
  * **版本链**——同宗 `chain_parent_id`/`base_version_id` 前驱 + 跨宗地
    `parcel_op`（SPLIT/MERGE/CORRECTION/ADJUDICATION）的全部父版本，含界址点/挂接；
  * **共享边**——闭包各宗在该时点版本两两之间的重合界址边；
  * **争议**——涉及闭包宗地的 dispute（连同双方作业单/候选/裁定结果版本）；
  * **证明**——闭包宗地在该时点前签发的 certificate（HMAC 签章随包）；
  * **生效计划**——占用与闭包宗地相交的 effect_plan（连同 correction_draft、
    占用对象宗地存根）；
* 载荷规范化后整体 SHA-256 并切块；**清单**逐项登记内容哈希、计数、分块哈希，
  再用 HMAC-SHA256 签发。接收方仅凭包内信息即可独立验真（无需联网/无需库）。

**接收（预检 → 分块 → 终检一次性导入）**

* `POST /api/snapshots/precheck`：可在**完全无网络**环境核验——清单签章 →
  分块哈希/缺块 → 载荷整体哈希 → 条目内容哈希与计数 → **引用关系最小闭包**
  （证明/候选/占用等引用缺失）→ **重算版本哈希链**（链断裂）→ 证明签章/绑定 →
  共享边重算；带 `local=true` 时再**只读**比对本地库（同 id 不同版本、
  在版分叉、计划 request_key/占用互斥），不做任何写入；
* `POST /api/snapshots/imports` 凭清单建会话：**相同包标识 + 相同清单**恢复原会话，
  同标识不同内容直接 `409 PACKAGE_ID_CONFLICT`；
* `PUT /imports/{id}/chunks/{seq}`：分块可**乱序、重复**上传（multipart 文件或
  base64 表单字段）；同序号相同内容幂等；**同序号不同内容**记为
  `CHUNK_CONTENT_MISMATCH` 且不覆盖已收正确块，重传正确内容即清除；
  上传进程中断后凭 package_id **续传**（分块实体持久化）；
* `POST /imports/{id}/finalize`：只有全块齐备且**清单/链/引用/本地**全部匹配时，
  才在**单事务**内一次性导入；缺块返回 `MISSING_CHUNKS`，任何内容/本地冲突返回
  可定位的冲突明细（`entity/id/seq/detail`）并**保持数据库原样**；
* **相同包标识再次导入返回首次结果**（结果持久化在会话上，不可二次落账）；
* 前端「快照交换」页三栏：导出（含 `.pkg.json` 下载）/ 接收（预检、建会话、
  单块或乱序自动上传、终检）/ 会话结果——分块点阵（绿已收/灰缺失/红异内容）、
  可定位冲突、**来源时间点**、**新旧版本对应关系**（NEW/IDENTICAL、导入前后在版 id）。

```
POST /api/snapshots/export                  按时间点导出最小闭包（清单 + base64 分块）
POST /api/snapshots/precheck                无网络离线预检（可带分块做内容级核验）
POST /api/snapshots/imports                 凭清单建/恢复上传会话（同 id 异内容 409；可带 owner/valid_until/ttl_minutes）
GET  /api/snapshots/imports                 会话清单（负责人/剩余时间/冻结原因，惰性到期）
GET  /api/snapshots/imports/{id}            会话详情（缺块/冲突/窗口/冻结/结果）
PUT  /api/snapshots/imports/{id}/chunks/{seq}  分块上传（乱序/重复/续传；文件或 base64；仅当前负责人）
POST /api/snapshots/imports/{id}/finalize   终检并一次性导入（全匹配才落库；重放幂等；仅当前负责人）
POST /api/snapshots/imports/{id}/handover   负责人移交（request_key 幂等 + version 乐观锁）
POST /api/snapshots/imports/{id}/renew      续期（窗口开启期间；request_key + version）
POST /api/snapshots/imports/{id}/freeze     人工冻结（保留分块/缺块/冲突，拒绝写入）
POST /api/snapshots/imports/{id}/reopen     重新开启（重验清单与现存分块；失配保持冻结并给可定位原因）
GET  /api/snapshots/imports/{id}/events     会话操作审计（创建/移交/续期/冻结/重开/分块/终检/拒绝）
POST /api/snapshots/imports-cleanup         保留期清理（仅冻结超期且从未导入；已导入永不清理）
```

## 交换包交付回执中继（独立模块 / 连续水位 / 会话隔离 / 离线回执）

`app/relay/` 是**独立子系统**（独立 SQLite 库 `data/relay/relay.db`、独立
机构密钥目录），把"快照接收服务"的审计事件按**会话修订号**中继成可离线
核验的交付回执。它不与主平台库共享任何表，崩溃/重启/多实例都保持一致。

**事件接收与连续水位（乱序、重复、批量重放都安全）**

* 发送方（快照接收站点）持有 Ed25519 私钥，对每个事件的 `event_hash`
  签章；事件字段（sender/session/revision/type/session_version/state/
  prev_event_hash/occurred_at/detail）规范化后 SHA-256，
  `prev_event_hash` 把事件串成**哈希链**。
* 原始事件**只追加落盘**（`relay_raw_event`，`UNIQUE(sender,session,rev,hash)`）：
  乱序的高修订号先到也不丢，进程在落盘前后崩溃、重放、批量补发都不漏记、
  不重复确认。
* 每个 (sender, session) 维护**连续水位**：只有「前序齐全（1..n 无缺口）+
  prev 哈希链接得上链顶 + 发送方签章有效 + 会话版本/状态跃迁合法」才把
  事件确认进链（`relay_event`，修订号唯一）并推进水位；缺口只停在当前
  水位（`WAITING`，**不隔离**），补传后自动把后续乱序事件一起确认。
* 事件类型：`CREATE / CHUNK_ACCEPTED / CHUNK_REJECTED / HANDOVER /
  FINALIZE_ACCEPTED / FINALIZE_REJECTED`；合法状态跃迁与版本跃迁规则在
  `relay/config.py`（如 `HANDOVER` 必须 session_version +1、只有
  `FINALIZE_ACCEPTED` 可进入 `IMPORTED` 终态闭合）。

**会话隔离（可定位差异，不阻塞其他会话）**

发现下列任一情况即把**该会话**隔离（`relay_quarantine`），后续事件只入库
留证、永不推进水位；其他会话、其他发送方完全不受影响（写操作按
(sender,session) 在独立事务内完成）：

| 原因码 | 触发 | 可定位差异 |
| --- | --- | --- |
| `SAME_REV_DIFFERENT_CONTENT` | 同修订号出现不同 event_hash（含跨批次累积） | `at_revision` + 全部 `distinct_hashes` |
| `FORKED_CHAIN` | prev_event_hash 接不上链顶 / 首事件 prev 非空 | `at_revision` + `expected_prev` vs `actual_prev` |
| `BAD_SIGNATURE` | 事件哈希与内容不符 / 发送方签章验证失败 | `at_revision` + `event_hash` |
| `INVALID_TRANSITION` | 非法状态、版本未 +1、回退、CREATE 不在 rev1 | 修订号 + 允许集合 + 请求值 |

恢复：运维比对差异后 `release-quarantine`，可**撤回导致隔离的错误版本
原始事件**（仅限水位之后未确认的留证；已确认链上事件不可撤回，
`CONFIRMED_EVENT_IMMUTABLE`），解除后立即按现存事件重跑校验与推进。

**签名回执包（按接收机构，完全离线可核验）**

* 每个接收机构一把 Ed25519（**纯 Python RFC 8032 实现** `relay/ed25519.py`，
  基点预计算表 + Straus 多标量乘，~2ms/验签，零外部依赖）；
  `POST /api/relay/institutions` 生成，公钥随回执包分发。
* 回执包正文：格式版本、请求键、机构、发送方、签发/过期时间、每会话
  **已确认水位、逐事件（含全部哈希字段，可独立重算 event_hash 与 prev
  链接）、链摘要 chain_digest、链顶 head_event_hash、拒绝明细**；
  机构对规范化正文做 Ed25519 签章。
* **相同导出请求键 `request_key` 重放永远返回同一原包**（持久化在
  `relay_receipt`）；同键绑定不同机构/发送方 → `REQUEST_KEY_CONFLICT`。
* 独立核验器**不访问中继/数据库**：重算签章 → 有效期 → 逐事件 event_hash
  → prev 链连续 → 修订号 1..N 连续且长度 == 水位 → chain_digest/head
  → 拒绝明细与链一致。`python -m app.relay.verifier 包.json [--at ISO]`。

**清理授权（发送方清本地事件前的闸门）**

发送方凭回执包 + 本地事件清单调 `/cleanup-authorization`，只有同时满足
才授权：回执签章有效、**未过期**、修订号 ≤ 已确认水位、本地 event_hash
与回执摘要**逐一仍一致**。过期回执（`RECEIPT_EXPIRED`）、本地事件后来
变化（`LOCAL_EVENT_CHANGED`，附回执中期望哈希）、超出水位、会话不在
回执中、伪造签章一律拒绝，只授权最小安全集合并逐项给出拒绝原因。

**崩溃 / 重启 / 两个工作实例并发**

* 原始事件只追加 + 唯一约束 + `BEGIN IMMEDIATE` 串行写事务，
  `synchronous=FULL`：应答丢失整批重放只得到 `DUPLICATE`，不漏记、
  不重复确认；不同会话绝不串写（复合主键 (sender,session)）。
* 会话处理权用**持久租约**（`lease_owner/lease_at`）：两实例并发
  `POST /claim` 只有一个成功，另一个 409 `LEASE_HELD`（租约粒度是单会话，
  不影响其领取别的会话）；同实例续租幂等；实例崩溃后超过
  `RELAY_LEASE_TTL_SECONDS` 可被安全接管。

```
POST /api/relay/institutions                 生成接收机构 Ed25519 密钥
POST /api/relay/senders                      注册发送方公钥
POST /api/relay/events/{sender_id}           批量推送事件（乱序/重复/重放；逐项 ACCEPTED/WAITING/DUPLICATE/QUARANTINED）
GET  /api/relay/sessions[?sender_id=]        水位/隔离/租约总览
GET  /api/relay/sessions/{sender}/{session}  会话详情（已确认链/缺口/待补修订/隔离差异/拒绝明细）
POST /api/relay/sessions/{sender}/{session}/release-quarantine  撤回误版（未确认原始事件）并解除隔离、重跑推进
POST /api/relay/claim | /release-lease       工作实例领取/释放单会话处理租约（TTL 接管）
POST /api/relay/receipts                     导出/同键重放签名回执包（水位+摘要+拒绝明细+有效期）
GET  /api/relay/receipts                     已签发回执清单
POST /api/relay/receipts/verify              上传回执包核验（签章/哈希链/有效期/水位）
POST /api/relay/cleanup-authorization        凭回执申请本地事件清理授权（过期/摘要变化拒绝）
POST /api/relay/demo/*                       网页演示端点（演示私钥本地签名后走同一推送管线）
```

网页界面 `/relay`：左栏会话水位点阵（绿已确认/黄等待前序/灰缺口/隔离红），
中栏确认哈希链、**隔离原因与可定位差异**、撤回误版恢复，右栏四页签：
回执签发与 `.receipt.json` 下载（同键重放校验字节一致）、**上传回执包
核验**、清理授权（一键把本地事件哈希篡改为 `ff…` 演示拒绝）、两实例并发
领取租约；顶部按钮一键演示乱序缺口→补传→批量重放完成→制造同序号异内容
隔离（旁边 `PKG-HEALTHY` 保持健康）→撤回误版恢复。命令行模拟器
`python -m app.relay.cli demo|recovery|push|receipt|rotation|revocation|trust|rotate-demo`
走完全相同的服务管线。

## 机构签发密钥轮换 / 回执撤销 / 离线信任包

在连续水位回执中继之上，机构侧增加**离线可验证**的签发密钥轮换与
回执撤销机制。全部状态在中继独立 SQLite 库中，写操作走
`BEGIN IMMEDIATE` 串行事务 + 部分唯一索引，两名管理员并发登记或批准时
**只有一个结果生效**；服务重启后状态不回退、不重复切换。

### 签发密钥轮换（连续签名链 / 生效水位 / 双人控制）

* 机构签发钥按**纪元（epoch）**组织：epoch 0 为创世钥（既有
  `{code}.pub` 引导，首次使用时幂等归档为 `{code}.e0.seed`）。
* 管理员 A 用**幂等登记请求键** `POST .../rotations/propose`
  登记「下一把公钥 + 生效水位 `activate_serial`」：
  * 新钥必须对登记挑战签名（PoP，证明持有对应私钥）；也可由服务端
    直接生成并把种子固化为 0600 的 `{code}.eN.seed`（首次登记响应
    回传一次）；
  * 水位不得落在当前机构单调回执序号之后（`ACTIVATE_SERIAL_IN_PAST`，
    轮换不可追溯，防止回退重签）；
  * 同一机构至多一条未生效轮换，并发登记靠部分唯一索引只允许一条胜出
    （`PENDING_ROTATION_EXISTS`）；同请求键重放返回首次结果。
* 管理员 B（**必须不同于登记人**，`APPROVER_MUST_DIFFER`）用独立的
  批准请求键 `POST .../rotations/approve`：**旧钥对整条轮换记录签名**
  （批准签章背书新钥）；两名管理员用不同批准键并发批准时只有一个生效，
  另一个得到 409 `APPROVAL_RACE` 并标明胜出者；同键重放返回首次批准。
* 状态机 `PROPOSED → APPROVED → ACTIVE`。达到生效水位（机构内单调
  **回执序号** `serial_no` ≥ `activate_serial`）后：下一张回执签发时
  在同一事务内**幂等自动生效**新钥（重启/重入不重复切换），
  `POST .../rotations/activate` 可手动触发；水位之前的回执永远继续
  按旧钥验证，水位之后不可能再用旧钥签发。
* 每条轮换记录有不可变 `record_hash`（固定字段规范化 SHA256）与
  `prev_record_hash`，与创世记录一起构成**连续签名链**；新钥 PoP、
  旧钥批准签章、纪元连续性、水位单调性全部可离线重算。
* `GET .../rotations/preview` 为只读**预演**：给当前纪元/下一序号/
  建议水位/「还有几张回执会由旧钥签发」/ 生效预测（IMMEDIATE/
  DEFERRED），不落任何状态。

### 版本化撤销清单（按回执标识 / 时间区间）

* `POST .../revocations` 发布新版：可按**回执请求键**（整包撤销）、
  **签发时间区间** `time_range.issued_from/issued_to`（查已签发回执）、
  或显式细粒度条目（`sender_id/session_id/revision`）选择，取并集。
* 版本号机构内单调（v1 为引导时的空集锚点），每版都是**完整撤销条目
  集合**且必须是上一版超集；逐版带 `prev_digest` 摘要链、发布时间与
  当时**生效纪元密钥**的签名。发布请求键幂等（同键永远返回首版）。

### 离线信任包（导出 / 导入 / 可定位拒绝）

`POST /api/relay/trust-bundles` 导出 `relay-trust-bundle/v1`：

```
body: format/bundle_serial(单调)/institution/root_epoch/
      key_chain(全部 ACTIVE/APPROVED 纪元记录, 含 PoP/旧钥批准签章/prev 哈希)/
      revocation_versions(全量撤销版本链)/issued_at/expires_at
signer_epoch + signature   # 当前生效钥对规范化正文签名
```

* 导出请求键幂等（同键返回原包）；包序号机构内单调。
* 核验器（`verifier.verify_trust_bundle`，纯离线）逐纪元重算
  record_hash / prev 链接 / PoP / **旧钥批准签名** / 水位单调，
  逐版重算撤销摘要 / 签名 / **超集单调（REVOCATION_ROLLBACK）**，
  并校验包签名与有效期；每个问题都带 `where/epoch/version` 等定位字段。
* `POST /api/relay/trust-bundles/import` 核验后落库：同机构同包序号
  + 同内容幂等重导，同序号异内容 409 `TRUST_SERIAL_CONFLICT`；
  核验不过的包不导入（返回全部可定位 problems）。
* `check_receipt_against_trust(receipt, bundle)`（CLI:
  `verifier --trust 信任包 回执包`，以及 `POST /receipts/status`）
  以信任包为根定位回执：

| 结论 | 触发 |
| --- | --- |
| `VALID` | 回执自签章合法；内嵌公钥在轮换链上；序号落在该纪元水位区间；未撤销；包未过期 |
| `REVOKED` | 命中当前撤销集合（包级键或会话/修订级，返回具体条目） |
| `TRUST_EXPIRED` | 信任包已过期（独立可验但不能放行） |
| `EXPIRED` | 回执自身过期 |
| `DENIED` | `SIGNING_KEY_NOT_IN_CHAIN` / `RECEIPT_EPOCH_KEY_MISMATCH` / `SIGNED_AFTER_WATERMARK_WITH_OLD_KEY`（水位后旧钥/伪造钥）|
| `TRUST_DENIED` | 信任包断链（`ROTATION_CHAIN_BROKEN`）/ 批准签名非法 / 撤销回滚等 |

**未撤销的历史回执**（无论用哪把旧钥）在轮换、多次撤销之后仍验证通过。

### 崩溃 / 重启 / 并发一致性

* 轮换状态、批准签章、回执序号、撤销版本全部在同一串行写库；
  回执序号分配与「到水位自动切换」在签发事务内一次完成
  （`relay_institution.next_serial` 只增），崩溃在切换前后都安全：
  已 ACTIVE 的重启后仍是 ACTIVE 且 `activated_at` 不被重写，
  APPROVED 未到水位的保持 APPROVED，到水位由下一张回执幂等切换。
* 并发登记 / 并发批准由部分唯一索引（单条 pending、登记键、批准键）
  + 条件 UPDATE（`... WHERE status='PROPOSED'`）保证只一个结果生效。

```
GET  /api/relay/institutions/{code}/rotations/preview   轮换预演（只读）
POST /api/relay/institutions/{code}/rotations/propose   登记下一把公钥+生效水位（幂等）
POST /api/relay/institutions/{code}/rotations/approve   第二管理员批准（双人控制/并发裁决）
POST /api/relay/institutions/{code}/rotations/activate  手动生效检查
GET  /api/relay/institutions/{code}/rotations           轮换签名链视图
POST /api/relay/institutions/{code}/revocations         发布撤销版本（标识/区间/条目；幂等）
GET  /api/relay/institutions/{code}/revocations         撤销版本链
POST /api/relay/trust-bundles                           导出离线信任包（公钥链+撤销+单调序号）
POST /api/relay/trust-bundles/import                    导入（核验；同序号幂等/异内容 409）
POST /api/relay/trust-bundles/verify                    信任包离线核验
GET  /api/relay/trust-bundles/imports                   已导入信任包
POST /api/relay/receipts/status                         以当前信任根定位回执状态
```

CLI：`rotation preview|propose|approve|activate|list`、
`revocation publish|list`、`trust export|verify|import|check`、
`rotate-demo`（轮换预演→登记→并发批准裁决→水位切换→旧回执持续可验→
撤销→信任包导出/导入→离线定位已撤销/断链/撤销回滚/过期包，13 步全断言）。
网页 `/relay` 右侧新增「密钥轮换 / 撤销清单 / 信任包」三个页签。

| 环境变量 | 默认 | 含义 |
| --- | --- | --- |
| `RELAY_TRUST_BUNDLE_TTL_SECONDS` | 2592000（30 天） | 离线信任包默认有效期（过期必须重新导入）|

### 回执中继坐标与目录（`app/relay/config.py`）

| 环境变量 | 默认 | 含义 |
| --- | --- | --- |
| `RELAY_DATA_DIR` / `RELAY_DB` | `data/relay/` / `data/relay/relay.db` | 中继独立数据目录与库 |
| `RELAY_KEY_DIR` | `data/relay/keys` | 接收机构 seed(0600)/公钥 |
| `RELAY_RECEIPT_DIR` | `data/relay/receipts` | 回执包导出目录 |
| `RELAY_RECEIPT_TTL_SECONDS` | 604800（7 天） | 回执默认有效期 |
| `RELAY_LEASE_TTL_SECONDS` | 30 | 工作实例领取租约 TTL（崩溃接管） |

### 接收窗口与移交（负责人 / 有效期 / 冻结 / 重开 / 保留期）

* **创建窗口**：`POST /imports` 可带 `owner`（负责人）与 `valid_until`（绝对截止）
  或 `ttl_minutes`（时长；均缺省为不限期）。此后**上传分块与终检只允许当前负责人**
  （`actor` 表单/JSON 字段或 `X-Cadastre-Actor` 头；未指定负责人的会话不限制，向后兼容）。
* **到期冻结**：窗口截止后写入被**惰性冻结**（`FROZEN / EXPIRED`）——
  已经验真的分块、缺块点阵、同序号异内容与终检冲突**全部保留**，但拒绝任何继续写入
  （分块 PUT / 终检 → 409 `SESSION_FROZEN`，响应附完整可定位会话视图与审计事件 `WRITE_DENIED`）。
* **人工冻结**：负责人可随时 `freeze`（`FROZEN / MANUAL`），语义同到期冻结。
* **移交 / 续期 / 冻结 / 重开必须携带 `request_key`（幂等请求键）与 `version`（会话版本号）**：
  版本号不匹配 → 409 `VERSION_CONFLICT`（并发覆盖被乐观锁挡下，客户端须刷新后重试；
  版本冲突失败**不消费**请求键）；成功动作的同键同内容重放 → 返回首次结果
  （`replayed=true`，不二次变更、不重复记审计）；同键不同内容 → 400。每次成功
  动作 `version_no += 1`。
* **重开校验拒绝是终局判定（请求去重）**：一次 `reopen` 若因**磁盘分块损坏**等
  失配被拒（409 `REOPEN_MISMATCH`，保持冻结），该操作标识（`request_key`）即被
  **永久绑定到这次拒绝响应**——之后同键重放（连续点击、断网重试、甚至携带新的
  版本号）一律 409 原样回放首次拒绝（响应带 `replayed=true` 与首次失配明细），
  即使后台文件后来已修正、会话已被其他操作标识推进（解冻甚至已完成导入），原标识
  也**不再重新校验、不产生任何新状态变更**（不重复冻结、不重复记审计；`FREEZE` 与
  `REOPEN_REJECTED` 审计各只记一次）。操作者必须提交**新的 `request_key` 与最新
  `version`** 才能再次校验并恢复接收；前端在重开失败时给出终局提示并提供
  「新操作标识重验（文件已修复）」按钮（自动取最新版本号），操作进行中连续点击
  与网络重试复用同一待决标识，不会绕过首次判定。
* **移交**在冻结状态下也允许（不解除冻结）：负责人交接后由新负责人发起重开；
  **续期**只在窗口开启、未冻结期间允许（过期后须先重开）。
* **重新开启（reopen）前重新核验清单与现存分块**：清单签章 → 现存分块哈希与缺块；
  全块齐备时按**完整终检口径**（载荷/闭包/链/证明/共享边/本地只读）复验。
  失配 → **保持冻结**（`REOPEN_MISMATCH`），返回 `entity/id/seq` 级可定位原因，
  会话版本号不递增，但请求键被**终局消费**（同键永远回放这次拒绝，见上条）；
  通过 → 解冻、现存分块决定 UPLOADING/READY、版本号递增，并须给出新窗口
  （原窗口已过期时必填）。
* **已导入保护**：`IMPORTED` 会话拒绝移交/续期/冻结/重开（409 `SESSION_IMPORTED`），
  终检仅返回首次结果；保留期清理**永不删除**已导入会话及其导入结果。
* **保留期清理**：`POST /imports-cleanup` 只删除冻结超过 `retention_days`
  （默认 `CADASTRE_SNAPSHOT_RETENTION_DAYS=7`）且从未导入的会话，连同其分块、
  审计与幂等请求记录；响应返回清单与受保护的已导入会话计数。
* 前端「快照交换」页会话清单/详情展示**负责人、剩余时间（倒计时/过期）、冻结原因**、
  会话版本与**操作审计时间线**，并支持**续期、移交、冻结、重开**与保留期清理。

## 坐标与容差（`app/config.py`，单位：米/m²）

| 参数 | 值 | 含义 |
| --- | --- | --- |
| CLOSURE_TOL_M | 0.05 | 环闭合容差 |
| POINT_SNAP_TOL_M | 0.15 | 界址点归并/锚点吸附 |
| SHARED_CONSIST_TOL_M | 0.05 | 共享边一致性 |
| SHARED_SEARCH_TOL_M | 0.50 | 共边/基线片段寻找 |
| UNCHANGED_EDGE_TOL_M | 0.05 | 裁定时未争议边界保持容差 |
| AREA_TOL_RATIO | 2% | 外业面积容差 |
| SPLIT_MERGE_AREA_RATIO | 0.5% | 分割/合并面积守恒 |

> 内部使用平面投影坐标（米）。真实部署时设备端把地方 CRS（如 CGCS2000 高斯带）投影后提交。

## 主要接口

```
POST /api/sync/bundle            下载离线包（基线版本/邻宗/容差）
POST /api/sync/jobs/{id}/media   界标照片上传（multipart）
POST /api/sync/validate          只校验不入库（弱网预检）
POST /api/sync/submit            幂等提交候选边界 → COMMITTED/DISPUTED/REJECTED
GET  /api/disputes               未决争议（含 base/A/B 差异几何）
POST /api/disputes/adjudicate    裁定：A / B / REVISED（端点固定）
POST /api/ops/split | merge | correction
POST /api/correction-drafts            建更正草案并预演（不产生版本）
GET  /api/correction-drafts[?status=]  草案列表
GET  /api/correction-drafts/{id}       草案详情（预演影响 + 实时漂移）
POST /api/correction-drafts/{id}/rehearse  漂移后重新预演
POST /api/correction-drafts/{id}/publish  原子发布（漂移→DRIFTED，不写版本；重放幂等）
POST /api/correction-drafts/{id}/cancel   撤销草案（无半成品残留）
POST /api/effect-plans                    登记生效计划（未来执行+互斥占用；冲突清单/幂等）
GET  /api/effect-plans[?status=]          计划列表（等待/暂停/完成/取消）
GET  /api/effect-plans/{id}               计划详情（占用对象/租约/令牌/暂停原因/实时漂移）
POST /api/effect-plans/{id}/reschedule    改期
POST /api/effect-plans/{id}/resume        暂停后刷新基线并恢复
POST /api/effect-plans/{id}/cancel        取消并释放占用（request_key 可重新登记）
POST /api/snapshots/export                按时间点导出最小闭包离线交换包（清单+分块）
POST /api/snapshots/precheck              接收方离线预检（签章/分块/引用/链/证明/共享边/本地）
POST /api/snapshots/imports               建/恢复分块上传会话（同包标识异内容 409；可带 owner/valid_until/ttl_minutes）
GET  /api/snapshots/imports[/{id}]        会话清单/详情（负责人/剩余时间/冻结原因/缺块/冲突/导入结果）
PUT  /api/snapshots/imports/{id}/chunks/{seq}   分块上传（乱序/重复/断点续传；仅当前负责人）
POST /api/snapshots/imports/{id}/finalize 终检：全匹配一次性导入；冲突可定位且库原样；重放幂等；仅当前负责人
POST /api/snapshots/imports/{id}/handover|renew|freeze|reopen  接收窗口管理（request_key 幂等 + version 乐观锁）
GET  /api/snapshots/imports/{id}/events   会话操作审计
POST /api/snapshots/imports-cleanup       保留期清理（已导入永不清理）

# —— 交换包交付回执中继（独立模块，前缀 /api/relay；详见上文专节）——
POST /api/relay/events/{sender_id}             审计事件推送（乱序/重复/批量重放）
GET  /api/relay/sessions[/{sender}/{session}]  连续水位 / 隔离原因与可定位差异
POST /api/relay/sessions/.../release-quarantine 撤回误版并解除隔离、重跑推进
POST /api/relay/claim | release-lease          工作实例单会话处理租约（并发/TTL 接管）
POST /api/relay/receipts                       按机构签发/同键重放离线回执包
POST /api/relay/receipts/verify                上传回执包离线核验
POST /api/relay/cleanup-authorization          清理授权（过期/本地变化拒绝）
POST /api/relay/trust-bundles                  导出离线信任包（机构公钥链/撤销版本/单调序号）
POST /api/relay/trust-bundles/import|verify    导入（同序号幂等/异内容409）/离线核验
GET  /api/relay/trust-bundles/imports          已导入信任包
GET  /api/relay/institutions/{c}/rotations[/preview]  轮换链视图 / 预演
POST /api/relay/institutions/{c}/rotations/propose|approve|activate  登记/批准/生效
GET|POST /api/relay/institutions/{c}/revocations      版本化撤销清单
POST /api/relay/receipts/status                以当前信任根定位回执（VALID/REVOKED/过期/断链）
POST /api/certificates           签发证明
GET  /api/certificates/{id}/verify
GET  /api/parcels/{id}?at=ISO    单宗时点状态（含血缘操作）
GET  /api/at/{ts}                全区时点快照
GET  /api/map                    编辑器一次拉取（宗地/界址点/争议/证明）
GET  /api/ops                    生命周期操作血缘
```

## 目录

```
app/
  config.py          容差与路径
  db.py              SQLite schema（版本/候选/争议/操作/证明/幂等）
  geo.py             几何内核：自交求交、片段差异、定向选路、片段替换、面积
  schemas.py         API 模型
  services/
    sync.py          离线包、提交、并发分歧检测、确认传播
    adjudication.py  裁定（锚点约束/补链不动/面积守恒）
    lifecycle.py     分割/合并/更正
    plans.py         生效计划：登记/互斥占用/租约执行器/暂停恢复/取消
    snapshots.py     快照交换包：时间点最小闭包导出/清单签章/离线预检/分块会话/一次性导入
    versions.py      不可变版本、时间点查询、哈希链审计
    certificates.py  证明签发/验真
    crypto.py        哈希链与 HMAC
  routers/           HTTP 层（含 effect-plans 生效计划、snapshots 快照交换包、relay 回执中继）
  relay/             **交付回执中继**（独立库）：
                       ed25519.py 纯 Python RFC8032（基点预计算 + 多标量乘，~2ms 验签）
                       crypto.py 事件哈希链/发送方签章/机构回执签章/轮换批准/撤销/信任包签章
                       store.py  原始事件只追加/连续水位/隔离/租约/机构纪元/轮换链/撤销版本/信任包
                       service.py 推送/水位推进/隔离恢复/回执导出（单调序号+纪元钥）/清理授权/领取租约
                       trust.py  密钥轮换（登记/批准/生效）/版本化撤销/信任包导出导入/回执定位
                       verifier.py 完全离线核验器（回执包 + 信任包/轮换链/撤销回滚；`python -m app.relay.verifier`）
                       cli.py 命令行（demo/recovery/push/receipt/rotation/revocation/trust/rotate-demo）
                       demo.py 网页演示用本地签名发送方
static/              Canvas 编辑器 + `relay/index.html` 回执中继网页界面（零依赖）
tests/               业务规则 + HTTP 集成测试
                     （test_relay_*.py 覆盖中继核心/回执清理/租约/并发/RFC8032 向量/CLI/
                       密钥轮换/撤销/离线信任包，共 103 项中继测试）
seed.py              演示种子（甲/乙两宗，共享 x=100 边）
demo_live.py         实时端到端断言脚本
```

## 安全与生产化说明（演示边界）

* 证明使用对称 HMAC（`CADASTRE_CERT_KEY`），生产应替换为非对称 CA/KMS 密钥与吊销列表；
* 未做鉴权/RBAC、操作人电子签章与设备证书绑定；
* 照片为本地文件存储，生产应转对象存储并做病毒扫描；
* SQLite + 进程内写锁适合单节点演示，多节点应换 PostGIS/PostgreSQL 并加行级乐观锁；
* 生效计划执行器是单节点后台线程（持久租约 + 完成令牌已保证崩溃补跑/不二次落账），
  多节点部署应改为带行锁/选主的分布式调度（如 `SELECT ... FOR UPDATE SKIP LOCKED`），
  租约回收间隔由 `CADASTRE_PLAN_POLL_SECONDS` / `CADASTRE_PLAN_LEASE_TTL_SECONDS` 控制。
