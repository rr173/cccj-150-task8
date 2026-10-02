"""FastAPI 入口。"""
from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from .db import init_db
from .routers import parcels, sync as sync_router, disputes, lifecycle, certificates, corrections, plans as plans_router, snapshots as snapshots_router, relay as relay_router
from .services import plans as plans_svc
from .relay.store import init_relay_db

BASE_DIR = Path(__file__).resolve().parent.parent
STATIC_DIR = BASE_DIR / "static"

app = FastAPI(title="地籍界址测量与宗地版本管理平台", version="1.4.0")


@app.on_event("startup")
def _startup():
    init_db()
    # 生效计划执行器：启动即回收上一进程的在途租约并补跑（持久租约/完成令牌）
    plans_svc.get_executor().start()
    # 交换包交付回执中继：独立库初始化（与主平台库隔离）
    init_relay_db()


@app.on_event("shutdown")
def _shutdown():
    plans_svc.get_executor().stop()


app.include_router(parcels.router)
app.include_router(sync_router.router)
app.include_router(disputes.router)
app.include_router(lifecycle.router)
app.include_router(certificates.router)
app.include_router(corrections.router)
app.include_router(plans_router.router)
app.include_router(snapshots_router.router)
app.include_router(relay_router.router)


@app.get("/api/health")
def health():
    return {"ok": True, "service": "cadastre"}


@app.get("/relay")
def relay_page():
    return FileResponse(str(STATIC_DIR / "relay" / "index.html"))


app.mount("/relay-static", StaticFiles(directory=str(STATIC_DIR / "relay")),
          name="relay-static")

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/")
def index():
    return FileResponse(str(STATIC_DIR / "index.html"))
