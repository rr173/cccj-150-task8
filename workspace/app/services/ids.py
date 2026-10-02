"""ID 生成与统一时间。"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone


def new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def as_of(v: str | None) -> str:
    """接受注入时间（测试/回放），否则取当前 UTC。"""
    return v or now_iso()
