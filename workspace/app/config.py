"""全局配置：坐标系与测量容差。

平台内部使用**平面投影坐标（单位：米）**，便于面积/距离计算。
真实工程中前端可把地方 CRS（如 CGCS2000 高斯-克吕格带）投影到该平面。
"""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
MEDIA_DIR = DATA_DIR / "media"


def _db_path() -> str:
    return os.environ.get("CADASTRE_DB", str(DATA_DIR / "cadastre.db"))

# 签字密钥（演示用对称密钥；生产环境应使用非对称 CA / KMS）
CERT_KEY = os.environ.get("CADASTRE_CERT_KEY", "cadastre-demo-sealing-key-v1")
CERT_ISSUER = "地籍管理平台（演示）"

# ---- 测量容差（米 / 平方米 / 比值）----
CLOSURE_TOL_M = 0.05           # 多边形首尾闭合容差
SELF_INTERSECT_GRID = 0.001    # 近重复点归算网格（米）
POINT_SNAP_TOL_M = 0.15        # 采集点与已有点自动归并阈值
SHARED_SEARCH_TOL_M = 0.50     # 共享边"寻找对应边"容差（A/B 差于此内视为同一条边）
SHARED_CONSIST_TOL_M = 0.05    # 共享边一致性容差（偏差超限即不一致）
UNCHANGED_EDGE_TOL_M = 0.05    # 裁定时"未争议边界必须保持不动"的容差
AREA_TOL_RATIO = 0.02          # 外业面积容差：声明面积与计算面积差 ≤ 2%
SPLIT_MERGE_AREA_RATIO = 0.005 # 分割/合并面积守恒容差 0.5%
TURNING_ANGLE_DEG = 1.0        # 折片段端点判定：内角偏离 180° 超过此值才算折点
MIN_SEG_LEN_M = 0.10           # 最小界址边长

# ---- 生效计划执行器（后台轮询；单节点演示）----
PLAN_POLL_SECONDS = float(os.environ.get("CADASTRE_PLAN_POLL_SECONDS", "1.0"))
PLAN_LEASE_TTL_SECONDS = float(os.environ.get("CADASTRE_PLAN_LEASE_TTL_SECONDS", "30"))

# ---- 快照交换接收会话：接收窗口 / 保留期清理 ----
# 冻结（到期/人工/重开失败）后保留多少天才允许清理；已导入会话永不清理
SNAPSHOT_RETENTION_DAYS = float(os.environ.get("CADASTRE_SNAPSHOT_RETENTION_DAYS", "7"))

os.makedirs(MEDIA_DIR, exist_ok=True)
