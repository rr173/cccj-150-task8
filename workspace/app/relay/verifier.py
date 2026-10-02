"""回执包 / 离线信任包独立核验器。

仅凭**包本身**（回执包内含机构公钥；信任包内含机构公钥链）即可完成
全部核验，不访问中继、不访问任何数据库：

回执包：

1. 包结构 / 版本格式；
2. 机构 Ed25519 签章（对规范化正文重算）；
3. 有效期（可注入核验时刻）；
4. 每个会话的**事件哈希链**：逐事件重算 event_hash、校验
   prev_event_hash 连续、链顶摘要与 sessions[].chain_digest 一致；
5. 水位一致性（链长 == confirmed_watermark，修订号 1..N 连续）；
6. 拒绝明细中的 event_hash 与链上对应事件一致。

离线信任包（``relay-trust-bundle/v1``）：机构公钥**轮换签名链**
（旧钥签新钥、连续纪元、生效水位单调）、版本化**撤销清单**
（摘要链、签名、超集单调防回滚）、单调包序号、有效期。配合
``check_receipt_against_trust`` 可定位拒绝：断链轮换、撤销回滚、
信任包过期、已撤销回执、签发纪元与水位不符。

命令行::

    python -m app.relay.verifier <receipt|trust-bundle>.json [--at ISO]
    python -m app.relay.verifier --trust trust.json receipt.json [--at ISO]
"""
from __future__ import annotations

import hashlib
import json
import sys
from datetime import datetime, timezone

from . import crypto


class ReceiptError(Exception):
    def __init__(self, message: str, code: str, problems=None):
        super().__init__(message)
        self.code = code
        self.problems = problems or []


def _iso(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def verify_receipt_package(package: dict, *, now: str | None = None,
                           min_watermark: dict | None = None) -> dict:
    """完整离线核验；通过返回核验报告 dict，任一不过抛 :class:`ReceiptError`。"""
    problems = []
    if not isinstance(package, dict):
        raise ReceiptError("回执包不是 JSON 对象", "MALFORMED_PACKAGE")
    body = package.get("body")
    sig = package.get("signature")
    pub = package.get("institution_public_key")
    if not isinstance(body, dict) or not sig or not pub:
        raise ReceiptError("回执包缺少 body/signature/institution_public_key",
                           "MALFORMED_PACKAGE")

    # 1. 格式
    if body.get("format") != crypto.RECEIPT_FORMAT:
        problems.append({"code": "UNSUPPORTED_FORMAT",
                         "actual": body.get("format")})

    # 2. 签章（完全离线）
    if not crypto.verify_receipt_signature(body, sig, pub):
        problems.append({"code": "BAD_SIGNATURE"})

    # 3. 有效期
    now_dt = _iso(now) if now else datetime.now(timezone.utc)
    expires_at = None
    expired = False
    try:
        expires_at = _iso(body["expires_at"])
        issued_at = _iso(body["issued_at"])
        if expires_at <= issued_at:
            problems.append({"code": "BAD_VALIDITY_WINDOW",
                             "issued_at": body.get("issued_at"),
                             "expires_at": body.get("expires_at")})
        if now_dt >= expires_at:
            expired = True
            problems.append({"code": "RECEIPT_EXPIRED",
                             "expires_at": body["expires_at"],
                             "checked_at": now_dt.strftime("%Y-%m-%dT%H:%M:%SZ")})
    except (KeyError, ValueError):
        problems.append({"code": "BAD_VALIDITY_WINDOW"})

    # 4/5. 逐会话链核验
    sessions_report = []
    for snap in body.get("sessions", []):
        r = _verify_session(snap)
        sessions_report.append(r)
        problems.extend({"session_id": snap.get("session_id"), **p}
                        for p in r["problems"])

    # 6. 调用方可选最低水位要求（发送方/审计场景）
    if min_watermark:
        by = {s["session_id"]: s["confirmed_watermark"]
              for s in body.get("sessions", [])}
        for sid, need in min_watermark.items():
            if by.get(sid, 0) < need:
                problems.append({"code": "WATERMARK_BELOW_REQUIRED",
                                 "session_id": sid, "required": need,
                                 "actual": by.get(sid, 0)})

    if problems:
        raise ReceiptError(f"回执核验发现 {len(problems)} 个问题",
                           "VERIFY_FAILED", problems)

    return {
        "valid": True,
        "institution_code": body.get("institution_code"),
        "institution_public_key": pub,
        "sender_id": body.get("sender_id"),
        "request_key": body.get("request_key"),
        "issued_at": body.get("issued_at"),
        "expires_at": body.get("expires_at"),
        "expired": expired,
        "sessions": sessions_report,
    }


def _verify_session(snap: dict) -> dict:
    problems = []
    sid = snap.get("session_id")
    events = snap.get("events", [])
    wm = snap.get("confirmed_watermark")

    if wm != len(events):
        problems.append({"code": "WATERMARK_LENGTH_MISMATCH",
                         "watermark": wm, "chain_length": len(events)})

    prev_hash = None
    digest_parts = []
    rejection_index = {r.get("revision"): r for r in snap.get("rejections", [])}
    for i, e in enumerate(events, start=1):
        rev = e.get("revision")
        if rev != i:
            problems.append({"code": "NON_CONTIGUOUS_REVISION",
                             "at_index": i, "revision": rev})
        # 离线重算 event_hash：回执链条目含全部哈希字段
        reconstructed = {
            "sender_id": snap.get("sender_id"),
            "session_id": sid,
            "revision": rev,
            "event_type": e.get("event_type"),
            "session_version": e.get("session_version"),
            "state": e.get("state"),
            "prev_event_hash": e.get("prev_event_hash"),
            "occurred_at": e.get("occurred_at"),
            "detail": e.get("detail"),
        }
        # prev 链接连续（首事件 prev 必须为 null）
        if e.get("prev_event_hash") != prev_hash:
            problems.append({"code": "BROKEN_PREV_LINK", "revision": rev,
                             "expected_prev": prev_hash,
                             "actual_prev": e.get("prev_event_hash")})
        if "event_hash" not in e:
            problems.append({"code": "MISSING_EVENT_HASH", "revision": rev})
        else:
            recomputed = crypto.sha256_hex(
                crypto.canonical({k: reconstructed.get(k)
                                  for k in crypto.EVENT_HASH_FIELDS}))
            if recomputed != e["event_hash"]:
                problems.append({"code": "EVENT_HASH_MISMATCH", "revision": rev,
                                 "expected": recomputed,
                                 "actual": e["event_hash"]})
            digest_parts.append(e["event_hash"])
            prev_hash = e["event_hash"]
        # 拒绝明细一致性
        if rev in rejection_index:
            rj = rejection_index[rev]
            if rj.get("event_hash") != e.get("event_hash"):
                problems.append({"code": "REJECTION_HASH_MISMATCH",
                                 "revision": rev})
            if rj.get("event_type") != e.get("event_type"):
                problems.append({"code": "REJECTION_TYPE_MISMATCH",
                                 "revision": rev})

    digest = hashlib.sha256("\n".join(digest_parts).encode()).hexdigest()
    if digest_parts and snap.get("chain_digest") != digest:
        problems.append({"code": "CHAIN_DIGEST_MISMATCH",
                         "expected": snap.get("chain_digest"),
                         "actual": digest})
    head = events[-1]["event_hash"] if events else None
    if snap.get("head_event_hash") != head:
        problems.append({"code": "HEAD_HASH_MISMATCH",
                         "expected": snap.get("head_event_hash"),
                         "actual": head})
    return {"session_id": sid, "sender_id": snap.get("sender_id"),
            "confirmed_watermark": wm, "state": snap.get("state"),
            "head_event_hash": head, "chain_digest": digest,
            "event_count": len(events),
            "quarantined": snap.get("quarantined", False),
            "problems": problems}


def main(argv=None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    if not argv:
        print("用法:\n"
              "  python -m app.relay.verifier <receipt|trust-bundle>.json [--at ISO]\n"
              "  python -m app.relay.verifier --trust <trust.json> <receipt.json> [--at ISO]",
              file=sys.stderr)
        return 2

    trust_path = None
    if "--trust" in argv:
        i = argv.index("--trust")
        trust_path = argv[i + 1]
        del argv[i:i + 2]

    path = argv[0]
    at = None
    if "--at" in argv:
        at = argv[argv.index("--at") + 1]
    with open(path, "r", encoding="utf-8") as f:
        package = json.load(f)

    # 信任包核验
    if isinstance(package, dict) and isinstance(package.get("body"), dict) \
            and package["body"].get("format") == crypto.TRUST_BUNDLE_FORMAT \
            and trust_path is None:
        try:
            report = verify_trust_bundle(package, now=at)
        except TrustBundleError as exc:
            print(json.dumps({"valid": False, "code": exc.code,
                              "message": str(exc), "problems": exc.problems},
                             ensure_ascii=False, indent=2))
            return 1
        print(json.dumps(_short_trust_report(report), ensure_ascii=False,
                         indent=2))
        return 0

    try:
        if trust_path:
            with open(trust_path, "r", encoding="utf-8") as f:
                bundle = json.load(f)
            try:
                report = verify_trust_bundle(bundle, now=at)
            except TrustBundleError as exc:
                print(json.dumps({"valid": False, "stage": "TRUST_BUNDLE",
                                  "code": exc.code, "message": str(exc),
                                  "problems": exc.problems},
                                 ensure_ascii=False, indent=2))
                return 1
            decision = check_receipt_against_trust(package, bundle, now=at)
            print(json.dumps({"trust_bundle": _short_trust_report(report),
                              "receipt": decision}, ensure_ascii=False,
                             indent=2))
            return 0 if decision["status"] == "VALID" else 1
        report = verify_receipt_package(package, now=at)
    except ReceiptError as exc:
        print(json.dumps({"valid": False, "code": exc.code,
                          "message": str(exc), "problems": exc.problems},
                         ensure_ascii=False, indent=2))
        return 1
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


def _short_trust_report(report: dict) -> dict:
    return {
        "valid": report["valid"],
        "institution_code": report["institution_code"],
        "active_epoch": report["active_epoch"],
        "revocation_version": report["revocation_version"],
        "bundle_serial": report["bundle_serial"],
        "expired": report["expired"],
    }


# ---------------------------------------------------------------------------
# 离线信任包：机构公钥轮换签名链 / 版本化撤销清单 / 包序号 / 有效期
# ---------------------------------------------------------------------------

class TrustBundleError(Exception):
    def __init__(self, message: str, code: str, problems=None):
        super().__init__(message)
        self.code = code
        self.problems = problems or []


def verify_trust_bundle(package: dict, *, now: str | None = None,
                        allow_expired: bool = False) -> dict:
    """完整离线核验信任包；问题以**可定位** problem 列表返回。"""
    problems = []
    if not isinstance(package, dict):
        raise TrustBundleError("信任包不是 JSON 对象", "MALFORMED_BUNDLE")
    body = package.get("body")
    sig = package.get("signature")
    signer_epoch = package.get("signer_epoch")
    if not isinstance(body, dict) or not sig:
        raise TrustBundleError(
            "信任包缺少 body/signature", "MALFORMED_BUNDLE")
    if body.get("format") != crypto.TRUST_BUNDLE_FORMAT:
        problems.append({"code": "UNSUPPORTED_FORMAT",
                         "where": "body.format",
                         "actual": body.get("format")})

    chain = body.get("key_chain", [])
    chain_report = _verify_key_chain(body, chain, problems)

    # 包本身必须由链上当前生效纪元密钥签发
    signer_pub = None
    if signer_epoch is not None:
        signer_pub = chain_report["epoch_pubs"].get(signer_epoch)
        if signer_pub is None:
            problems.append({"code": "SIGNER_EPOCH_NOT_IN_CHAIN",
                             "where": "signer_epoch",
                             "signer_epoch": signer_epoch})
    else:
        problems.append({"code": "MALFORMED_BUNDLE",
                         "where": "signer_epoch", "actual": None})
    if signer_pub and not crypto.verify_trust_bundle_signature(
            body, sig, signer_pub):
        problems.append({"code": "BAD_TRUST_SIGNATURE",
                         "where": "signature", "signer_epoch": signer_epoch})

    # 有效期
    now_dt = _iso(now) if now else datetime.now(timezone.utc)
    expired = False
    try:
        expires_at = _iso(body["expires_at"])
        issued_at = _iso(body["issued_at"])
        if expires_at <= issued_at:
            problems.append({"code": "BAD_VALIDITY_WINDOW", "where": "body",
                             "issued_at": body.get("issued_at"),
                             "expires_at": body.get("expires_at")})
        if now_dt >= expires_at:
            expired = True
            problems.append({"code": "TRUST_BUNDLE_EXPIRED",
                             "where": "body.expires_at",
                             "expires_at": body["expires_at"],
                             "checked_at": now_dt.strftime(
                                 "%Y-%m-%dT%H:%M:%SZ")})
    except (KeyError, ValueError):
        problems.append({"code": "BAD_VALIDITY_WINDOW", "where": "body"})

    # 撤销版本链
    rev_report = _verify_revocation_versions(body, chain_report, problems)

    if problems and not (allow_expired
                         and {p["code"] for p in problems} <=
                         {"TRUST_BUNDLE_EXPIRED"}):
        raise TrustBundleError(
            f"信任包核验发现 {len(problems)} 个问题",
            "TRUST_VERIFY_FAILED", problems)

    return {
        "valid": True,
        "institution_code": body.get("institution_code"),
        "bundle_serial": body.get("bundle_serial"),
        "active_epoch": chain_report["active_epoch"],
        "epoch_public_keys": chain_report["epoch_pubs"],
        "activation": chain_report["activation"],
        "revocation_version": rev_report["latest_version"],
        "revocation_digests": rev_report["digests"],
        "revoked_entries": rev_report["latest_entries"],
        "issued_at": body.get("issued_at"),
        "expires_at": body.get("expires_at"),
        "expired": expired,
        "problems": problems,
    }


def _verify_key_chain(body: dict, chain: list, problems: list) -> dict:
    """逐纪元验证：record_hash 重算、prev 连续、旧钥批准签名、水位单调。"""
    code = body.get("institution_code")
    epoch_pubs: dict = {}
    activation: dict = {}
    prev_serial = 0
    prev_hash = None
    prev_pub = None
    last_epoch = None
    for i, rec in enumerate(chain):
        where = f"body.key_chain[{i}]"
        epoch = rec.get("epoch")
        pub = rec.get("public_key")
        try:
            bytes.fromhex(pub or "")
        except ValueError:
            problems.append({"code": "BAD_PUBLIC_KEY", "where": where,
                             "epoch": epoch})
        # 纪元连续
        if epoch != i:
            problems.append({"code": "NON_CONTIGUOUS_EPOCH", "where": where,
                             "expected_epoch": i, "actual_epoch": epoch})
        # prev_record_hash 连续（断链定位）
        if rec.get("prev_record_hash") != prev_hash:
            problems.append({"code": "ROTATION_CHAIN_BROKEN", "where": where,
                             "epoch": epoch,
                             "expected_prev": prev_hash,
                             "actual_prev": rec.get("prev_record_hash")})
        # record_hash 重算（固定字段不可变）
        recomputed = crypto.rotation_record_hash({
            "institution_code": code, "epoch": epoch, "public_key": pub,
            "activate_serial": rec.get("activate_serial"),
            "proposed_by": rec.get("proposed_by"),
            "proposed_at": rec.get("proposed_at"),
            "pop_signature": rec.get("pop_signature"),
            "prev_record_hash": rec.get("prev_record_hash")})
        if recomputed != rec.get("record_hash"):
            problems.append({"code": "ROTATION_RECORD_HASH_MISMATCH",
                             "where": where, "epoch": epoch,
                             "expected": recomputed,
                             "actual": rec.get("record_hash")})
        # PoP：新钥持有证明
        if not (pub and crypto.verify_pop(
                code, epoch, pub, rec.get("activate_serial"),
                rec.get("pop_signature"))):
            problems.append({"code": "POP_SIGNATURE_INVALID", "where": where,
                             "epoch": epoch})
        # 生效水位单调
        serial = rec.get("activate_serial")
        if not isinstance(serial, int) or serial < prev_serial:
            problems.append({"code": "ACTIVATE_SERIAL_NOT_MONOTONIC",
                             "where": where + ".activate_serial", "epoch": epoch,
                             "previous": prev_serial, "actual": serial})
        prev_serial = serial if isinstance(serial, int) else prev_serial

        # 批准签名：epoch 0 自举（自签）；之后必须由**上一纪元旧钥**签 record_hash
        approval = rec.get("approval_signature")
        if i == 0:
            signer_pub = pub
            if epoch != 0:
                problems.append({"code": "FIRST_EPOCH_NOT_ZERO",
                                 "where": where, "epoch": epoch})
            ok = bool(pub and crypto.verify_rotation_approval(
                rec.get("record_hash"), approval, pub))
            if not ok:
                problems.append({"code": "GENESIS_SELF_SIGNATURE_INVALID",
                                 "where": where, "epoch": epoch})
        else:
            signer_pub = prev_pub
            ok = bool(prev_pub and crypto.verify_rotation_approval(
                rec.get("record_hash"), approval, prev_pub))
            if not ok:
                problems.append({"code": "ROTATION_APPROVAL_SIGNATURE_INVALID",
                                 "where": where, "epoch": epoch,
                                 "signer_epoch": i - 1})
        if rec.get("status") not in ("APPROVED", "ACTIVE"):
            problems.append({"code": "ROTATION_NOT_EFFECTIVE",
                             "where": where + ".status", "epoch": epoch,
                             "actual": rec.get("status")})
        if pub:
            if pub in set(epoch_pubs.values()):
                problems.append({"code": "DUPLICATE_PUBLIC_KEY_IN_CHAIN",
                                 "where": where, "epoch": epoch})
            epoch_pubs[epoch] = pub
        activation[epoch] = serial
        prev_hash = rec.get("record_hash")
        prev_pub = pub
        last_epoch = epoch
    if not chain:
        problems.append({"code": "EMPTY_KEY_CHAIN", "where": "body.key_chain"})
    active = max((e for e in activation if isinstance(e, int)),
                 default=None)
    return {"epoch_pubs": epoch_pubs, "activation": activation,
            "active_epoch": active}


def _verify_revocation_versions(body: dict, chain_report: dict,
                                problems: list) -> dict:
    code = body.get("institution_code")
    versions = body.get("revocation_versions", [])
    prev_digest = None
    prev_set: set | None = None
    digests = {}
    latest_version = 0
    latest_entries = []
    for i, v in enumerate(versions):
        where = f"body.revocation_versions[{i}]"
        ver = v.get("version")
        if ver != i + 1:
            problems.append({"code": "NON_MONOTONIC_REVOCATION_VERSION",
                             "where": where, "expected": i + 1,
                             "actual": ver})
        if v.get("prev_digest") != prev_digest:
            problems.append({"code": "REVOCATION_CHAIN_BROKEN",
                             "where": where, "version": ver,
                             "expected_prev": prev_digest,
                             "actual_prev": v.get("prev_digest")})
        entries = v.get("entries", [])
        recomputed = crypto.revocation_digest({
            "institution_code": code, "version": ver,
            "prev_digest": v.get("prev_digest"), "entries": entries,
            "published_at": v.get("published_at")})
        digest = v.get("digest")
        if recomputed != digest:
            problems.append({"code": "REVOCATION_DIGEST_MISMATCH",
                             "where": where, "version": ver,
                             "expected": recomputed, "actual": digest})
        signer_epoch = v.get("signer_epoch")
        pub = chain_report["epoch_pubs"].get(signer_epoch)
        if pub is None:
            problems.append({"code": "REVOCATION_SIGNER_EPOCH_UNKNOWN",
                             "where": where + ".signer_epoch",
                             "version": ver, "signer_epoch": signer_epoch})
        elif not crypto.verify_revocation_signature(
                digest, v.get("signature"), pub):
            problems.append({"code": "REVOCATION_SIGNATURE_INVALID",
                             "where": where, "version": ver,
                             "signer_epoch": signer_epoch})
        # 超集单调（防回滚）：每版条目必须是上一版的超集
        cur_set = {crypto.canonical(_norm_entry(e)).hex() for e in entries}
        if prev_set is not None and not prev_set.issubset(cur_set):
            removed = [json.loads(bytes.fromhex(h).decode())
                       for h in sorted(prev_set - cur_set)]
            problems.append({"code": "REVOCATION_ROLLBACK",
                             "where": where, "version": ver,
                             "removed_entries": removed})
        # 条目内部基本结构
        for j, e in enumerate(entries):
            if not isinstance(e, dict) or not (
                    e.get("receipt_request_key") or
                    (e.get("session_id") and e.get("revision"))):
                problems.append({"code": "BAD_REVOCATION_ENTRY",
                                 "where": f"{where}.entries[{j}]",
                                 "version": ver, "entry": e})
        prev_digest = digest
        prev_set = cur_set
        digests[ver] = digest
        latest_version = ver if isinstance(ver, int) else latest_version
        latest_entries = entries
    if not versions:
        problems.append({"code": "EMPTY_REVOCATION_VERSIONS",
                         "where": "body.revocation_versions"})
    return {"digests": digests, "latest_version": latest_version,
            "latest_entries": latest_entries}


def _norm_entry(e: dict) -> dict:
    return {k: v for k, v in sorted(e.items()) if v is not None}


# ---------------------------------------------------------------------------
# 回执 × 信任根：轮换纪元 / 生效水位 / 撤销定位
# ---------------------------------------------------------------------------

def check_receipt_against_trust(receipt_package: dict, bundle: dict, *,
                                now: str | None = None) -> dict:
    """以离线信任包为信任根定位单张回执。

    检查：回执自签章（用包内嵌公钥）→ 信任包有效（含过期定位）→
    内嵌公钥必须是轮换链上某纪元公钥 → 回执序号必须落在该纪元
    生效水位区间（旧钥旧回执按旧钥验证、水位后不得用旧钥）→
    是否命中当前撤销集合。
    """
    body = receipt_package.get("body", {})
    problems = []

    # 1. 回执自身（内嵌公钥）签章 + 事件链；过期仍继续做撤销判定
    expired = False
    try:
        verify_receipt_package(receipt_package, now=now)
    except ReceiptError as exc:
        for p in exc.problems:
            if p.get("code") == "RECEIPT_EXPIRED":
                expired = True
            else:
                problems.append({**p, "stage": "RECEIPT"})

    # 2. 信任包核验（过期单独标记，结构/链/签名问题是硬拒绝）
    now_dt = _iso(now) if now else datetime.now(timezone.utc)
    try:
        trust = verify_trust_bundle(bundle, now=now)
    except TrustBundleError as exc:
        hard = [p for p in exc.problems
                if p.get("code") != "TRUST_BUNDLE_EXPIRED"]
        if hard:
            return {"status": "TRUST_DENIED",
                    "code": "TRUST_BUNDLE_INVALID",
                    "problems": hard,
                    "institution_code": body.get("institution_code")}
        trust = None
        trust_expired = True
    else:
        trust_expired = trust.get("expired", False)

    code = body.get("institution_code")
    serial = body.get("serial_no")
    epoch = body.get("signer_epoch")
    embedded_pub = receipt_package.get("institution_public_key")

    if trust is None:
        # 过期信任包：按其内容尽力定位但结论不可用于放行
        trust = _best_effort_trust(bundle)

    # 机构一致
    if code and code != trust["institution_code"]:
        problems.append({"code": "INSTITUTION_MISMATCH", "stage": "TRUST",
                         "receipt_institution": code,
                         "trust_institution": trust["institution_code"]})

    # 3. 内嵌公钥必须在轮换链上
    epoch_pubs = trust["epoch_public_keys"]
    pub_epoch = next((e for e, p in epoch_pubs.items()
                      if p == embedded_pub), None)
    if embedded_pub and pub_epoch is None:
        problems.append({"code": "SIGNING_KEY_NOT_IN_CHAIN",
                         "stage": "TRUST",
                         "where": "institution_public_key"})

    # 4. 纪元与生效水位
    activation = trust["activation"]
    if epoch is not None and pub_epoch is not None and epoch != pub_epoch:
        problems.append({"code": "RECEIPT_EPOCH_KEY_MISMATCH",
                         "stage": "TRUST", "signer_epoch": epoch,
                         "key_epoch": pub_epoch,
                         "where": "body.signer_epoch"})
    if serial is not None and pub_epoch is not None and not problems:
        lo = activation.get(pub_epoch, 1)          # 本纪元首张序号
        hi = activation.get(pub_epoch + 1)         # 下一纪元首张序号（即水位）
        if serial < lo:
            problems.append({
                "code": "RECEIPT_SERIAL_BEFORE_EPOCH_START",
                "stage": "TRUST", "serial_no": serial,
                "epoch_start": lo, "signer_epoch": pub_epoch})
        if hi is not None and serial >= hi:
            problems.append({"code": "SIGNED_AFTER_WATERMARK_WITH_OLD_KEY",
                             "stage": "TRUST", "serial_no": serial,
                             "watermark": hi, "signer_epoch": pub_epoch,
                             "required_epoch": pub_epoch + 1})

    # 5. 撤销定位（包级 + 会话/修订级）
    revocations = []
    if not problems:
        revocations = _match_revocations(body, trust["revoked_entries"])
        if revocations:
            problems.append({"code": "RECEIPT_REVOKED", "stage": "REVOCATION",
                             "revocation_version": trust["revocation_version"],
                             "matches": revocations})

    base = {
        "institution_code": code,
        "request_key": body.get("request_key"),
        "serial_no": serial, "signer_epoch": epoch,
        "trust_bundle_serial": bundle["body"].get("bundle_serial"),
        "revocation_version": trust["revocation_version"],
        "active_epoch": trust["active_epoch"],
        "receipt_expired": expired,
        "trust_bundle_expired": trust_expired,
        "revocations": revocations,
        "problems": problems,
    }
    if problems:
        codes = {p["code"] for p in problems}
        if "RECEIPT_REVOKED" in codes:
            base["status"] = "REVOKED"
        elif trust_expired:
            base["status"] = "TRUST_EXPIRED"
        else:
            base["status"] = "DENIED"
        base["code"] = next(p["code"] for p in problems)
        return base
    if trust_expired:
        return {**base, "status": "TRUST_EXPIRED",
                "code": "TRUST_BUNDLE_EXPIRED"}
    if expired:
        return {**base, "status": "EXPIRED", "code": "RECEIPT_EXPIRED"}
    return {**base, "status": "VALID", "code": "OK"}


def _best_effort_trust(bundle: dict) -> dict:
    """过期信任包的尽力解析（仅用于继续定位撤销/纪元，不用于放行）。"""
    body = bundle["body"]
    epoch_pubs, activation = {}, {}
    prev_digest = None
    latest_entries, latest_version = [], 0
    for i, rec in enumerate(body.get("key_chain", [])):
        epoch_pubs[rec.get("epoch", i)] = rec.get("public_key")
        activation[rec.get("epoch", i)] = rec.get("activate_serial")
    for v in body.get("revocation_versions", []):
        if v.get("prev_digest") == prev_digest:
            latest_entries = v.get("entries", [])
            latest_version = v.get("version", latest_version)
            prev_digest = v.get("digest")
    return {"institution_code": body.get("institution_code"),
            "epoch_public_keys": epoch_pubs, "activation": activation,
            "active_epoch": max(epoch_pubs, default=None),
            "revoked_entries": latest_entries,
            "revocation_version": latest_version}


def _match_revocations(receipt_body: dict, entries: list) -> list:
    """返回命中回执的撤销条目（包级或会话/修订级，可定位到具体条目）。"""
    rk = receipt_body.get("request_key")
    sessions = {s.get("session_id"): s for s in receipt_body.get("sessions", [])}
    matches = []
    for e in entries:
        e = _norm_entry(e)
        why = None
        if e.get("receipt_request_key") and e["receipt_request_key"] == rk:
            why = "RECEIPT_KEY"
        elif e.get("session_id") and e["session_id"] in sessions:
            rev = e.get("revision")
            wm = sessions[e["session_id"]].get("confirmed_watermark")
            if rev is None or (isinstance(wm, int) and rev <= wm):
                why = "SESSION_REVISION"
        if why:
            matches.append({"entry": e, "match": why,
                            "request_key": rk,
                            "session_id": e.get("session_id"),
                            "revision": e.get("revision")})
    return matches


if __name__ == "__main__":
    raise SystemExit(main())
