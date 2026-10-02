"""命令行发送端模拟器与独立核验器的子进程冒烟测试。"""
from __future__ import annotations

import json
import subprocess
import sys

import pytest

pytestmark = pytest.mark.relay_cli


def _env(tmp_path):
    d = str(tmp_path)
    return {
        "PYTHONPATH": "/workspace",
        "RELAY_DATA_DIR": d,
        "RELAY_KEY_DIR": f"{d}/keys",
        "RELAY_RECEIPT_DIR": f"{d}/receipts",
        "RELAY_DB": f"{d}/relay.db",
        "PATH": "/usr/bin:/bin:/usr/local/bin",
    }


def test_cli_demo_receipt_and_standalone_verifier(tmp_path):
    env = _env(tmp_path)
    receipt = tmp_path / "r.json"
    p = subprocess.run(
        [sys.executable, "-m", "app.relay.cli", "--sender", "site-A",
         "--institution", "TEST-IN", "demo", "--request-key", "K1",
         "--ttl", "3600", "--out", str(receipt)],
        capture_output=True, text=True, env=env, cwd="/workspace", timeout=120)
    assert p.returncode == 0, p.stderr
    assert "原包一致: True" in p.stdout
    pkg = json.loads(receipt.read_text(encoding="utf-8"))

    # 独立核验器命令行（完全离线）
    p2 = subprocess.run(
        [sys.executable, "-m", "app.relay.verifier", str(receipt)],
        capture_output=True, text=True, env=env, cwd="/workspace", timeout=60)
    assert p2.returncode == 0, p2.stderr
    report = json.loads(p2.stdout)
    assert report["valid"] is True
    assert report["sessions"][0]["confirmed_watermark"] == 6

    # 过期时刻核验应失败（退出码 1）
    p3 = subprocess.run(
        [sys.executable, "-m", "app.relay.verifier", str(receipt),
         "--at", "2030-01-01T00:00:00Z"],
        capture_output=True, text=True, env=env, cwd="/workspace")
    assert p3.returncode == 1
    assert "RECEIPT_EXPIRED" in p3.stdout


def test_cli_recovery(tmp_path):
    env = _env(tmp_path)
    p = subprocess.run(
        [sys.executable, "-m", "app.relay.cli", "--sender", "site-R",
         "--institution", "TEST-IN", "recovery"],
        capture_output=True, text=True, env=env, cwd="/workspace", timeout=120)
    assert p.returncode == 0, p.stderr
    assert '"watermark": 2' in p.stdout
    assert '"quarantined": false' in p.stdout
