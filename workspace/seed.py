"""演示种子：两宗相邻地块 A / B，共享一条南北向界址边。

坐标（米）
  A: (0,0)-(100,0)-(100,100)-(0,100)
  B: (100,0)-(200,0)-(200,100)-(100,100)   ← 与 A 共享 x=100 的边
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.db import init_db, tx
from app.services import versions as vs
from app.services import sync as sync_svc
from app.services.ids import as_of

RING_A = [[0, 0], [100, 0], [100, 100], [0, 100]]
RING_B = [[100, 0], [200, 0], [200, 100], [100, 100]]


def _candidate(ring, label):
    return {"parcel_id": None, "label": label, "ring": ring,
            "area": None, "declared_area": None, "points": {},
            "owner": None, "owner_id_no": None}


def seed():
    init_db()
    with tx() as conn:
        existing = vs.list_parcels(conn)
        if existing:
            print("seed skipped (db not empty)")
            return
        ts = as_of("2026-01-10T08:00:00.000Z")
        for ring, label in ((RING_A, "甲宗地"), (RING_B, "乙宗地")):
            n = sync_svc.val.normalize_candidate(
                {"parcel_id": None, "label": label, "ring": ring,
                 "points": [], "declared_area": None})
            v = sync_svc._commit_one(conn, n, None, ts, "初始登记", None,
                                     op_type="SURVEY")
            conn.execute("UPDATE parcel SET label=? WHERE id=?",
                         (label, v["parcel_id"]))
            print(f"created {label}: parcel={v['parcel_id']} version={v['id']} area={v['area']}")
        print("seed done")


if __name__ == "__main__":
    seed()
