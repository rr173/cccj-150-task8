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


def test_cli_rotate_demo_and_offline_trust_verifier(tmp_path):
    env = _env(tmp_path)
    prefix = tmp_path / "rot"
    p = subprocess.run(
        [sys.executable, "-m", "app.relay.cli", "--sender", "site-T",
         "--institution", "TEST-IN", "rotate-demo",
         "--out-prefix", str(prefix)],
        capture_output=True, text=True, env=env, cwd="/workspace", timeout=180)
    assert p.returncode == 0, p.stderr
    # 离线核验信任包
    pv = subprocess.run(
        [sys.executable, "-m", "app.relay.verifier", f"{prefix}.trust.json"],
        capture_output=True, text=True, env=env, cwd="/workspace", timeout=60)
    assert pv.returncode == 0, pv.stderr
    report = json.loads(pv.stdout)
    assert report["active_epoch"] == 1 and report["revocation_version"] == 2
    # 已撤销旧回执：--trust 对照核验退出码 1 且可定位 REVOKED
    pr = subprocess.run(
        [sys.executable, "-m", "app.relay.verifier",
         "--trust", f"{prefix}.trust.json", f"{prefix}.old.json"],
        capture_output=True, text=True, env=env, cwd="/workspace", timeout=60)
    assert pr.returncode == 1
    assert '"status": "REVOKED"' in pr.stdout
    assert "RECEIPT_REVOKED" in pr.stdout
    # 未撤销的新钥回执 VALID（退出码 0）
    pn = subprocess.run(
        [sys.executable, "-m", "app.relay.verifier",
         "--trust", f"{prefix}.trust.json", f"{prefix}.new.json"],
        capture_output=True, text=True, env=env, cwd="/workspace", timeout=60)
    assert pn.returncode == 0, pn.stderr
    assert '"status": "VALID"' in pn.stdout


def test_cli_rotation_and_trust_subcommands(tmp_path):
    env = _env(tmp_path)
    receipt = tmp_path / "base.json"

    def run(*a):
        return subprocess.run(
            [sys.executable, "-m", "app.relay.cli", "--institution", "TEST-IN",
             "--sender", "site-X", *a],
            capture_output=True, text=True, env=env, cwd="/workspace", timeout=120)

    # 先用 demo 引导机构/发送方与一张回执
    p = run("demo", "--request-key", "BASE", "--ttl", "3600",
            "--out", str(receipt))
    assert p.returncode == 0, p.stderr

    # 预演 -> 登记 -> 批准 -> 列表（新钥水位=5，demo 已用 serial1）
    p = run("rotation", "preview")
    assert p.returncode == 0 and '"active_epoch": 0' in p.stdout
    p = run("rotation", "propose", "--request-key", "P1",
            "--proposed-by", "alice", "--activate-serial", "5")
    assert p.returncode == 0, p.stderr
    p = run("rotation", "approve", "--request-key", "A1",
            "--approved-by", "bob")
    assert p.returncode == 0, p.stderr
    p = run("rotation", "list")
    assert '"PROPOSED"' not in p.stdout and "APPROVED" in p.stdout

    # 撤销发布 + 列表
    p = run("revocation", "publish", "--request-key", "RV1",
            "--receipts", "BASE")
    assert p.returncode == 0 and '"version": 2' in p.stdout
    p = run("revocation", "list")
    assert p.returncode == 0 and '"latest_version": 2' in p.stdout

    # 信任包导出 -> 离线核验 -> 导入
    tb = tmp_path / "tb.json"
    p = run("trust", "export", "--request-key", "TB1", "--out", str(tb))
    assert p.returncode == 0, p.stderr
    p = run("trust", "verify", str(tb))
    assert p.returncode == 0 and '"revocation_version": 2' in p.stdout
    p = run("trust", "import", str(tb))
    assert p.returncode == 0 and '"imported": true' in p.stdout
    # 重导幂等
    p = run("trust", "import", str(tb))
    assert '"replayed": true' in p.stdout
    # BASE 已撤销：trust check 退出码 1
    p = run("trust", "check", "--trust", str(tb), str(receipt))
    assert p.returncode == 1
    assert '"status": "REVOKED"' in p.stdout
