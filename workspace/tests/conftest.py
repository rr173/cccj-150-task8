"""回执中继测试公共夹具：每个用例使用独立临时库与独立机构/发送方密钥。"""
from __future__ import annotations

import os
import tempfile

import pytest

# 在任何 app.* 导入前，把中继默认路径指到临时目录，避免非中继测试
# （TestClient 触发主应用 startup 中的 init_relay_db）在工作区落 data/relay。
_SESSION_RELAY = tempfile.mkdtemp(prefix="relay-tests-")
os.environ.setdefault("RELAY_DATA_DIR", _SESSION_RELAY)
os.environ.setdefault("RELAY_KEY_DIR", os.path.join(_SESSION_RELAY, "keys"))
os.environ.setdefault("RELAY_RECEIPT_DIR", os.path.join(_SESSION_RELAY, "receipts"))
os.environ.setdefault("RELAY_DB", os.path.join(_SESSION_RELAY, "relay.db"))

from app.relay import ed25519, service, crypto  # noqa: E402
from app.relay import store as relay_store      # noqa: E402


@pytest.fixture()
def relay_env(tmp_path, monkeypatch):
    data = tmp_path / "relay"
    monkeypatch.setenv("RELAY_DATA_DIR", str(data))
    monkeypatch.setenv("RELAY_KEY_DIR", str(data / "keys"))
    monkeypatch.setenv("RELAY_RECEIPT_DIR", str(data / "receipts"))
    monkeypatch.setenv("RELAY_DB", str(data / "relay.db"))
    relay_store.init_relay_db()
    crypto.create_institution_keys("TEST-IN", overwrite=True)
    seed, pub = ed25519.keypair()
    service.register_sender("site-A", pub.hex(), "测试站A")
    other_seed, other_pub = ed25519.keypair()
    service.register_sender("site-B", other_pub.hex(), "测试站B")

    def make(seed_bytes, *, sender="site-A", session="PKG-1", revision=1,
             etype="CREATE", version=1, state="UPLOADING", prev=None,
             ts="2026-10-02T10:00:00Z", detail=None):
        e = {"sender_id": sender, "session_id": session, "revision": revision,
             "event_type": etype, "session_version": version, "state": state,
             "prev_event_hash": prev, "occurred_at": ts, "detail": detail}
        e["event_hash"] = crypto.compute_event_hash(e)
        e["sender_signature"] = crypto.sign_event_hash(e["event_hash"], seed_bytes)
        return e

    def chain(seed_bytes, spec, *, sender="site-A", session="PKG-1"):
        """spec: [(etype, version, state, detail), ...]"""
        out, prev = [], None
        for i, (et, ver, st, det) in enumerate(spec, 1):
            ts = f"2026-10-02T10:{i:02d}:00Z"
            out.append(make(seed_bytes, sender=sender, session=session,
                            revision=i, etype=et, version=ver, state=st,
                            prev=prev, ts=ts, detail=det))
            prev = out[-1]["event_hash"]
        return out

    return {"service": service, "crypto": crypto, "store": relay_store,
            "seed": seed, "pub": pub.hex(),
            "seed_b": other_seed, "pub_b": other_pub.hex(),
            "make": make, "chain": chain, "institution": "TEST-IN"}
