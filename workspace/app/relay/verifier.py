"""回执包 / 离线信任包独立核验器。

回执包可单独核验（向后兼容 relay-receipt/v1）；新回执建议携带信任包路径，
由核验器重算机构公钥轮换链、版本化撤销清单、单调 trust_version 与有效期。
整个过程不访问中继、不访问任何数据库。
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


def _problem(code: str, **extra):
    d = {"code": code}
    d.update(extra)
    return d


def verify_receipt_package(package: dict, *, now: str | None = None,
                           min_watermark: dict | None = None,
                           trust_package: dict | None = None,
                           trust_report: dict | None = None) -> dict:
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

    trust = trust_report
    if trust_package is not None:
        trust = verify_trust_package(trust_package, now=now)

    if body.get("format") != crypto.RECEIPT_FORMAT:
        problems.append(_problem("UNSUPPORTED_FORMAT",
                                 actual=body.get("format")))

    # 新格式用实际签发钥验签；旧包使用包内机构公钥。若提供信任包，公钥必须在
    # 机构公钥链中；旧包只允许由根钥在首次轮换登记之前签发。
    serial = body.get("receipt_serial")
    signing_pub = body.get("signing_public_key") or pub
    issued_at = None
    try:
        issued_at = _iso(body["issued_at"])
    except (KeyError, ValueError, TypeError):
        problems.append(_problem("BAD_VALIDITY_WINDOW", field="issued_at"))

    if trust:
        if body.get("institution_code") != trust["institution_code"]:
            problems.append(_problem(
                "INSTITUTION_MISMATCH",
                receipt_institution=body.get("institution_code"),
                trust_institution=trust["institution_code"]))
        key_info = _signing_key_for_receipt(body, trust, problems)
        if key_info and key_info["public_key"] != signing_pub:
            problems.append(_problem(
                "RECEIPT_SIGNING_KEY_NOT_EXPECTED",
                receipt_serial=serial,
                declared_key=signing_pub, expected_key=key_info["public_key"],
                expected_key_seq=key_info["key_seq"]))
        expected_pub = key_info["public_key"] if key_info else signing_pub
    else:
        expected_pub = signing_pub

    if not crypto.verify_receipt_signature(body, sig, expected_pub):
        problems.append(_problem("BAD_SIGNATURE",
                                 signing_public_key=expected_pub))

    now_dt = _iso(now) if now else datetime.now(timezone.utc)
    expires_at = None
    expired = False
    try:
        expires_at = _iso(body["expires_at"])
        if expires_at <= issued_at:
            problems.append(_problem("BAD_VALIDITY_WINDOW",
                                     issued_at=body.get("issued_at"),
                                     expires_at=body.get("expires_at")))
        if now_dt >= expires_at:
            expired = True
            problems.append(_problem(
                "RECEIPT_EXPIRED", expires_at=body["expires_at"],
                checked_at=now_dt.strftime("%Y-%m-%dT%H:%M:%SZ")))
    except (KeyError, ValueError, TypeError):
        problems.append(_problem("BAD_VALIDITY_WINDOW"))

    if trust and now_dt > _iso(trust["expires_at"]):
        # verify_trust_package 已追加详细问题；这里给出回执级定位。
        problems.append(_problem("TRUST_PACKAGE_EXPIRED",
                                 trust_version=trust["trust_version"],
                                 expires_at=trust["expires_at"]))

    sessions_report = []
    for snap in body.get("sessions", []):
        r = _verify_session(snap)
        sessions_report.append(r)
        problems.extend({"session_id": snap.get("session_id"), **p}
                        for p in r["problems"])

    if min_watermark:
        by = {s["session_id"]: s["confirmed_watermark"]
              for s in body.get("sessions", [])}
        for sid, need in min_watermark.items():
            if by.get(sid, 0) < need:
                problems.append(_problem("WATERMARK_BELOW_REQUIRED",
                                         session_id=sid, required=need,
                                         actual=by.get(sid, 0)))

    if trust:
        revocation = _check_receipt_revocation(body, trust)
        if revocation:
            problems.append(revocation)

    if problems:
        raise ReceiptError(f"回执核验发现 {len(problems)} 个问题",
                           "VERIFY_FAILED", problems)

    return {
        "valid": True,
        "institution_code": body.get("institution_code"),
        "institution_public_key": pub,
        "signing_public_key": signing_pub,
        "sender_id": body.get("sender_id"),
        "request_key": body.get("request_key"),
        "receipt_id": body.get("receipt_id", body.get("request_key")),
        "receipt_serial": serial,
        "issued_at": body.get("issued_at"),
        "expires_at": body.get("expires_at"),
        "expired": expired,
        "sessions": sessions_report,
        "trust_version": trust["trust_version"] if trust else None,
        "revocation_version": trust["latest_revocation_version"] if trust else 0,
    }


def _signing_key_for_receipt(body: dict, trust: dict, problems: list[dict]):
    records = trust.get("rotation_records", [])
    by_seq = {r.get("key_seq"): r for r in records}
    serial = body.get("receipt_serial")
    declared_seq = body.get("signing_key_seq")
    if serial is None:
        # 兼容轮换前历史回执：必须由根钥签发，且签发时间早于下一把钥登记时间。
        first_rotation = next((r for r in records if r.get("key_seq", 0) > 0),
                              None)
        try:
            issued = _iso(body["issued_at"])
        except (KeyError, ValueError, TypeError):
            return by_seq.get(0)
        if first_rotation and issued >= _iso(first_rotation["registered_at"]):
            problems.append(_problem(
                "LEGACY_RECEIPT_AFTER_ROTATION_REGISTERED",
                issued_at=body.get("issued_at"),
                registered_at=first_rotation.get("registered_at")))
        return by_seq.get(0)

    try:
        serial_i = int(serial)
    except (TypeError, ValueError):
        problems.append(_problem("BAD_RECEIPT_SERIAL", serial=serial))
        return None
    expected = records[0] if records else None
    for rec in records[1:]:
        wm = rec.get("effective_watermark")
        if wm is None:
            problems.append(_problem("ROTATION_WATERMARK_MISSING",
                                     key_seq=rec.get("key_seq")))
            continue
        if serial_i >= wm:
            expected = rec
        else:
            break
    if declared_seq is not None and expected and \
            int(declared_seq) != expected["key_seq"]:
        problems.append(_problem(
            "RECEIPT_KEY_SEQ_MISMATCH", receipt_serial=serial_i,
            declared_key_seq=declared_seq,
            expected_key_seq=expected["key_seq"]))
    return expected


def _check_receipt_revocation(body: dict, trust: dict) -> dict | None:
    rid = body.get("receipt_id", body.get("request_key"))
    serial = body.get("receipt_serial")
    issued = body.get("issued_at")
    for e in trust.get("revocation_entries", []):
        if e.get("receipt_id") == rid and \
                (e.get("receipt_serial") in (None, serial)):
            return _problem("RECEIPT_REVOKED", receipt_id=rid,
                            receipt_serial=serial, revocation=e)
        if e.get("issued_from") or e.get("issued_to"):
            try:
                start = _iso(e["issued_from"]) if e.get("issued_from") else \
                    datetime.min.replace(tzinfo=timezone.utc)
                end = _iso(e["issued_to"]) if e.get("issued_to") else \
                    datetime.max.replace(tzinfo=timezone.utc)
                if start <= _iso(issued) <= end:
                    return _problem("RECEIPT_REVOKED_BY_TIME_RANGE",
                                    receipt_id=rid, receipt_serial=serial,
                                    revocation=e)
            except (KeyError, ValueError, TypeError):
                continue
    return None


def _verify_session(snap: dict) -> dict:
    problems = []
    sid = snap.get("session_id")
    events = snap.get("events", [])
    wm = snap.get("confirmed_watermark")

    if wm != len(events):
        problems.append(_problem("WATERMARK_LENGTH_MISMATCH",
                                 watermark=wm, chain_length=len(events)))

    prev_hash = None
    digest_parts = []
    rejection_index = {r.get("revision"): r for r in snap.get("rejections", [])}
    for i, e in enumerate(events, start=1):
        rev = e.get("revision")
        if rev != i:
            problems.append(_problem("NON_CONTIGUOUS_REVISION",
                                     at_index=i, revision=rev))
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
        if e.get("prev_event_hash") != prev_hash:
            problems.append(_problem("BROKEN_PREV_LINK", revision=rev,
                                     expected_prev=prev_hash,
                                     actual_prev=e.get("prev_event_hash")))
        if "event_hash" not in e:
            problems.append(_problem("MISSING_EVENT_HASH", revision=rev))
        else:
            recomputed = crypto.sha256_hex(
                crypto.canonical({k: reconstructed.get(k)
                                  for k in crypto.EVENT_HASH_FIELDS}))
            if recomputed != e["event_hash"]:
                problems.append(_problem("EVENT_HASH_MISMATCH", revision=rev,
                                         expected=recomputed,
                                         actual=e["event_hash"]))
            digest_parts.append(e["event_hash"])
            prev_hash = e["event_hash"]
        if rev in rejection_index:
            rj = rejection_index[rev]
            if rj.get("event_hash") != e.get("event_hash"):
                problems.append(_problem("REJECTION_HASH_MISMATCH", revision=rev))
            if rj.get("event_type") != e.get("event_type"):
                problems.append(_problem("REJECTION_TYPE_MISMATCH", revision=rev))

    digest = hashlib.sha256("\n".join(digest_parts).encode()).hexdigest()
    if digest_parts and snap.get("chain_digest") != digest:
        problems.append(_problem("CHAIN_DIGEST_MISMATCH",
                                 expected=snap.get("chain_digest"),
                                 actual=digest))
    head = events[-1]["event_hash"] if events else None
    if snap.get("head_event_hash") != head:
        problems.append(_problem("HEAD_HASH_MISMATCH",
                                 expected=snap.get("head_event_hash"),
                                 actual=head))
    return {"session_id": sid, "sender_id": snap.get("sender_id"),
            "confirmed_watermark": wm, "state": snap.get("state"),
            "head_event_hash": head, "chain_digest": digest,
            "event_count": len(events),
            "quarantined": snap.get("quarantined", False),
            "problems": problems}


# ---------------------------------------------------------------------------
# 离线信任包
# ---------------------------------------------------------------------------

def verify_trust_package(package: dict, *, now: str | None = None,
                         min_trust_version: int | None = None) -> dict:
    problems = []
    if not isinstance(package, dict):
        raise ReceiptError("信任包不是 JSON 对象", "MALFORMED_TRUST_PACKAGE")
    body = package.get("body")
    sig = package.get("signature")
    sign_pub = package.get("signing_public_key")
    if not isinstance(body, dict) or not sig or not sign_pub:
        raise ReceiptError(
            "信任包缺少 body/signature/signing_public_key",
            "MALFORMED_TRUST_PACKAGE")
    code = body.get("institution_code")
    if body.get("format") != crypto.TRUST_FORMAT:
        problems.append(_problem("UNSUPPORTED_TRUST_FORMAT",
                                 actual=body.get("format")))
    version = body.get("trust_version")
    if not isinstance(version, int) or version < 1:
        problems.append(_problem("BAD_TRUST_VERSION", actual=version))
    if min_trust_version is not None and isinstance(version, int) and \
            version < min_trust_version:
        problems.append(_problem("TRUST_VERSION_ROLLED_BACK",
                                 actual=version,
                                 expected_at_least=min_trust_version))

    now_dt = _iso(now) if now else datetime.now(timezone.utc)
    try:
        if now_dt >= _iso(body["expires_at"]):
            problems.append(_problem("TRUST_PACKAGE_EXPIRED",
                                     expires_at=body.get("expires_at"),
                                     trust_version=version,
                                     checked_at=now_dt.isoformat()))
        if _iso(body["expires_at"]) <= _iso(body["issued_at"]):
            problems.append(_problem("BAD_TRUST_VALIDITY_WINDOW",
                                     issued_at=body.get("issued_at"),
                                     expires_at=body.get("expires_at")))
    except (KeyError, ValueError, TypeError):
        problems.append(_problem("BAD_TRUST_VALIDITY_WINDOW"))

    records = body.get("rotation_records", [])
    key_by_seq = _verify_rotation_chain(
        code, records, problems, body.get("current_key_seq"))
    if sign_pub not in {r.get("public_key") for r in records}:
        problems.append(_problem("TRUST_SIGNING_KEY_NOT_IN_CHAIN",
                                 signing_public_key=sign_pub))
    if not crypto.verify_trust_signature(body, sig, sign_pub):
        problems.append(_problem("BAD_TRUST_SIGNATURE",
                                 signing_public_key=sign_pub))
    expected_digest = crypto.sha256_hex(crypto.canonical(body))
    if package.get("trust_digest") != expected_digest:
        problems.append(_problem("TRUST_DIGEST_MISMATCH",
                                 expected=expected_digest,
                                 actual=package.get("trust_digest")))

    latest_rev_version = _verify_revocation_lists(
        code, body.get("revocation_lists", []), records, key_by_seq, problems)
    entries = body.get("revocation_entries", [])
    entries_digest = crypto.revocation_entries_digest(entries)
    latest_list = body.get("revocation_lists", [])[-1] if body.get(
        "revocation_lists") else None
    if latest_list:
        if entries_digest != latest_list.get("entries_digest"):
            problems.append(_problem(
                "REVOCATION_ENTRIES_DIGEST_MISMATCH",
                expected=latest_list.get("entries_digest"),
                actual=entries_digest))
        if body.get("revocation_digest") != latest_list.get("list_hash"):
            problems.append(_problem(
                "REVOCATION_DIGEST_ROLLED_BACK",
                expected=latest_list.get("list_hash"),
                actual=body.get("revocation_digest")))
    elif body.get("revocation_digest") is not None:
        problems.append(_problem("REVOCATION_DIGEST_WITHOUT_LIST",
                                 actual=body.get("revocation_digest")))

    if problems:
        raise ReceiptError(f"信任包核验发现 {len(problems)} 个问题",
                           "TRUST_VERIFY_FAILED", problems)
    return {"valid": True, "format": crypto.TRUST_FORMAT,
            "institution_code": code, "trust_version": version,
            "issued_at": body.get("issued_at"),
            "expires_at": body.get("expires_at"),
            "trust_digest": package.get("trust_digest"),
            "rotation_records": records,
            "revocation_lists": body.get("revocation_lists", []),
            "revocation_entries": entries,
            "revocation_digest": body.get("revocation_digest"),
            "latest_revocation_version": latest_rev_version}


def _verify_rotation_chain(code, records, problems, current_key_seq=None) -> dict:
    key_by_seq = {}
    if not isinstance(records, list) or not records:
        problems.append(_problem("ROTATION_CHAIN_EMPTY"))
        return key_by_seq
    if current_key_seq is not None and \
            current_key_seq != records[-1].get("key_seq"):
        problems.append(_problem(
            "CURRENT_KEY_SEQ_MISMATCH",
            actual=current_key_seq,
            expected=records[-1].get("key_seq")))
    prev_hash = None
    prev_pub = None
    prev_wm = 0
    for i, rec in enumerate(records):
        seq = rec.get("key_seq")
        loc = {"key_seq": seq, "at_index": i}
        if seq != i:
            problems.append(_problem("ROTATION_SEQ_GAP", **loc,
                                     expected_seq=i, actual_seq=seq))
        if rec.get("institution_code") != code:
            problems.append(_problem("ROTATION_INSTITUTION_MISMATCH", **loc,
                                     expected=code,
                                     actual=rec.get("institution_code")))
        if rec.get("status") != "ACTIVE":
            problems.append(_problem("ROTATION_STATUS_INVALID", **loc,
                                     actual=rec.get("status"),
                                     expected="ACTIVE"))
        pub = rec.get("public_key")
        if seq == 0:
            if rec.get("effective_watermark") not in (None, 0):
                problems.append(_problem("GENESIS_WATERMARK_INVALID", **loc,
                                         actual=rec.get("effective_watermark")))
            if not crypto.verify_rotation_record(rec, pub):
                problems.append(_problem("ROTATION_GENESIS_SIGNATURE_INVALID",
                                         **loc))
        else:
            proof_msg = crypto.canonical({
                "institution_code": code, "key_seq": seq,
                "register_request_key": rec.get("register_request_key"),
                "public_key": pub})
            try:
                proof_ok = crypto.ed25519.verify(
                    proof_msg, bytes.fromhex(rec.get(
                        "new_key_self_signature", "")), bytes.fromhex(pub))
            except (ValueError, TypeError, crypto.ed25519.SignatureError,
                    crypto.ed25519.PublicKeyError):
                proof_ok = False
            if not proof_ok:
                problems.append(_problem("NEW_KEY_PROOF_INVALID", **loc))
            wm = rec.get("effective_watermark")
            if not isinstance(wm, int) or wm <= prev_wm:
                problems.append(_problem("ROTATION_WATERMARK_NOT_MONOTONIC",
                                         **loc, previous_watermark=prev_wm,
                                         actual_watermark=wm))
            prev_wm = wm if isinstance(wm, int) else prev_wm
            if rec.get("previous_record_hash") != prev_hash:
                problems.append(_problem("ROTATION_CHAIN_BROKEN", **loc,
                                         expected_prev=prev_hash,
                                         actual_prev=rec.get(
                                             "previous_record_hash")))
            if not crypto.verify_rotation_record(rec, prev_pub):
                problems.append(_problem("ROTATION_SIGNATURE_INVALID", **loc,
                                         signer_key_seq=i - 1))
        key_by_seq[seq] = rec
        prev_hash = rec.get("record_hash")
        prev_pub = pub
    return key_by_seq


def _verify_revocation_lists(code, lists, records, key_by_seq, problems) -> int:
    prev_hash = None
    prev_entries = set()
    for i, item in enumerate(lists, start=1):
        loc = {"revocation_version": item.get("version"), "at_index": i}
        if item.get("version") != i:
            problems.append(_problem("REVOCATION_VERSION_NOT_CONTIGUOUS", **loc,
                                     expected=i, actual=item.get("version")))
        if item.get("institution_code") != code:
            problems.append(_problem("REVOCATION_INSTITUTION_MISMATCH", **loc))
        entries = item.get("entries", [])
        digest = crypto.revocation_entries_digest(entries)
        if digest != item.get("entries_digest"):
            problems.append(_problem("REVOCATION_ENTRIES_DIGEST_MISMATCH",
                                     **loc, expected=digest,
                                     actual=item.get("entries_digest")))
        signed = {"institution_code": item.get("institution_code"),
                  "version": item.get("version"), "entries": entries,
                  "previous_list_hash": item.get("previous_list_hash"),
                  "published_at": item.get("published_at")}
        if item.get("previous_list_hash") != prev_hash:
            problems.append(_problem("REVOCATION_LIST_ROLLBACK", **loc,
                                     expected_prev=prev_hash,
                                     actual_prev=item.get("previous_list_hash")))
        current_entries = {crypto.canonical(e).hex() for e in entries}
        missing = sorted(prev_entries - current_entries)
        if missing:
            problems.append(_problem("REVOCATION_ENTRIES_ROLLED_BACK", **loc,
                                     removed_entries=missing[:20],
                                     removed_count=len(missing)))
        if crypto.revocation_list_hash(signed, digest) != item.get("list_hash"):
            problems.append(_problem("REVOCATION_LIST_HASH_MISMATCH", **loc))
        signer = key_by_seq.get(item.get("signing_key_seq"))
        if signer is None:
            problems.append(_problem("REVOCATION_SIGNER_NOT_IN_CHAIN", **loc,
                                     signing_key_seq=item.get("signing_key_seq")))
        elif not crypto.verify_revocation_list(
                signed, item.get("signature", ""), signer.get("public_key")):
            problems.append(_problem("REVOCATION_SIGNATURE_INVALID", **loc,
                                     signing_key_seq=item.get("signing_key_seq")))
        prev_entries = current_entries
        prev_hash = item.get("list_hash")
    return lists[-1]["version"] if lists else 0


def detect_package(obj: dict) -> str:
    body = obj.get("body", {}) if isinstance(obj, dict) else {}
    if body.get("format") == crypto.TRUST_FORMAT:
        return "trust"
    return "receipt"


def main(argv=None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    if not argv:
        print("用法: python -m app.relay.verifier <package.json> "
              "[--at ISO] [--trust trust.json]", file=sys.stderr)
        return 2
    path = argv[0]
    at = argv[argv.index("--at") + 1] if "--at" in argv else None
    trust_path = argv[argv.index("--trust") + 1] if "--trust" in argv else None
    with open(path, "r", encoding="utf-8") as f:
        package = json.load(f)
    try:
        if detect_package(package) == "trust":
            report = verify_trust_package(package, now=at)
        else:
            trust = None
            if trust_path:
                with open(trust_path, "r", encoding="utf-8") as f:
                    trust = json.load(f)
            report = verify_receipt_package(package, now=at, trust_package=trust)
    except ReceiptError as exc:
        print(json.dumps({"valid": False, "code": exc.code,
                          "message": str(exc), "problems": exc.problems},
                         ensure_ascii=False, indent=2))
        return 1
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
