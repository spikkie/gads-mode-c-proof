"""SEC-02.4C - HMAC challenge/replay reference contract, NO GitHub issuer.

Test-only signing uses an explicitly supplied synthetic secret. Never put
real keys into a model, source tree, public CI, or local J-01 process.
A matching HMAC/nonce does NOT establish genuine independent AI review,
trusted GitHub App identity, or permission to publish a status check.
"""
import hashlib
import hmac
import json
import secrets
import sqlite3
from gads import j01_runtime as runtime

SCHEMA = "gads.sec024.challenge.v1"
RECEIPT_SCHEMA = "gads.sec024.prototype-receipt.v1"
MAX_TTL_SECONDS = 300


class ChallengeBlocked(ValueError):
    pass


def _hex40(value):
    return isinstance(value, str) and bool(runtime.SHA.fullmatch(value))


def _hex64(value):
    return isinstance(value, str) and len(value) == 64 and all(
        ch in "0123456789abcdef" for ch in value)


def new_challenge(*, pr, head, base, diff_sha256, packet_sha256,
                  trusted_source_sha, issued_at, ttl_seconds=120, nonce=None):
    if type(pr) is not int or pr < 1 or pr > 100000:
        raise ChallengeBlocked("INVALID_PR")
    if not all(_hex40(v) for v in (head, base, trusted_source_sha)):
        raise ChallengeBlocked("INVALID_COMMIT_BINDING")
    if not all(_hex64(v) for v in (diff_sha256, packet_sha256)):
        raise ChallengeBlocked("INVALID_DIFF_BINDING")
    if type(issued_at) is not int or issued_at < 0:
        raise ChallengeBlocked("INVALID_ISSUED_AT")
    if type(ttl_seconds) is not int or not 1 <= ttl_seconds <= MAX_TTL_SECONDS:
        raise ChallengeBlocked("INVALID_TTL")
    nonce = secrets.token_hex(32) if nonce is None else nonce
    if not _hex64(nonce):
        raise ChallengeBlocked("INVALID_NONCE")
    return {
        "schema": SCHEMA, "audience": "GADS_SYNTHETIC_J01_ONLY",
        "repo": runtime.REPO, "pr": pr,
        "head": head, "base": base, "diff_sha256": diff_sha256,
        "packet_sha256": packet_sha256,
        "trusted_source_sha": trusted_source_sha,
        "nonce": nonce, "issued_at": issued_at,
        "expires_at": issued_at + ttl_seconds,
        "purpose": "NON_AUTHORITATIVE_PROTOTYPE",
    }


def sign_prototype(challenge, *, secret, decision, model_evidence_sha256):
    """Synthetic test helper only: NOT a deployed independent issuer."""
    if not isinstance(secret, bytes) or len(secret) < 32:
        raise ChallengeBlocked("INVALID_TEST_KEY")
    if decision not in ("APPROVE", "REQUEST_CHANGES"):
        raise ChallengeBlocked("INVALID_DECISION")
    if not _hex64(model_evidence_sha256):
        raise ChallengeBlocked("INVALID_EVIDENCE_DIGEST")
    body = {"schema": RECEIPT_SCHEMA, "challenge": challenge,
            "decision": decision, "model_evidence_sha256": model_evidence_sha256,
            "issuer": "TEST_FIXTURE_ONLY",
            "writer_authorized": False, "github_status_issued": False,
            "owner_approval": False}
    signature = hmac.new(secret, runtime.canonical(body), hashlib.sha256).hexdigest()
    return {**body, "prototype_hmac_sha256": signature}


def verify_and_consume_prototype(receipt, *, secret, expected, now, ledger):
    """Bounded local anti-replay prototype; never authorizes GitHub actions.

    ledger is a caller-owned SQLite connection, not an authoritative shared
    distributed ledger. The caller must not put this sqlite file in Git.
    """
    if not isinstance(receipt, dict) or not isinstance(expected, dict):
        raise ChallengeBlocked("MISSING_RECEIPT")
    if not isinstance(secret, bytes) or len(secret) < 32:
        raise ChallengeBlocked("UNVERIFIED_ISSUER_KEY")
    if type(now) is not int or now < 0:
        raise ChallengeBlocked("INVALID_CLOCK")
    if receipt.get("schema") != RECEIPT_SCHEMA or receipt.get("issuer") != "TEST_FIXTURE_ONLY":
        raise ChallengeBlocked("UNTRUSTED_ISSUER")
    if set(receipt) != {"schema", "challenge", "decision", "model_evidence_sha256",
                        "issuer", "writer_authorized", "github_status_issued",
                        "owner_approval", "prototype_hmac_sha256"}:
        raise ChallengeBlocked("UNEXPECTED_RECEIPT_FIELDS")
    if any(receipt.get(k) is not False for k in
           ("writer_authorized", "github_status_issued", "owner_approval")):
        raise ChallengeBlocked("UNAUTHORIZED_PRIVILEGE_CLAIM")
    if receipt.get("decision") not in ("APPROVE", "REQUEST_CHANGES") or not _hex64(
            receipt.get("model_evidence_sha256")):
        raise ChallengeBlocked("BAD_REVIEW_CONTENT")
    signature = receipt["prototype_hmac_sha256"]
    if not _hex64(signature):
        raise ChallengeBlocked("INVALID_SIGNATURE_SHAPE")
    body = {k: v for k, v in receipt.items() if k != "prototype_hmac_sha256"}
    expected_signature = hmac.new(secret, runtime.canonical(body), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected_signature):
        raise ChallengeBlocked("SIGNATURE_MISMATCH")
    challenge = receipt.get("challenge")
    if not isinstance(challenge, dict) or challenge.get("schema") != SCHEMA:
        raise ChallengeBlocked("INVALID_CHALLENGE")
    if (challenge.get("purpose") != "NON_AUTHORITATIVE_PROTOTYPE" or
            challenge.get("audience") != "GADS_SYNTHETIC_J01_ONLY" or
            challenge.get("repo") != runtime.REPO):
        raise ChallengeBlocked("WRONG_AUDIENCE_OR_REPOSITORY")
    fields = ("pr", "head", "base", "diff_sha256",
              "packet_sha256", "trusted_source_sha")
    if any(challenge.get(name) != expected.get(name) for name in fields):
        raise ChallengeBlocked("SHA_OR_PR_BINDING_CHANGED")
    if not _hex64(challenge.get("nonce")):
        raise ChallengeBlocked("INVALID_NONCE")
    issued, expiry = challenge.get("issued_at"), challenge.get("expires_at")
    if (type(issued) is not int or type(expiry) is not int or
            not issued <= now <= expiry or
            not 1 <= expiry - issued <= MAX_TTL_SECONDS):
        raise ChallengeBlocked("CHALLENGE_EXPIRED_OR_NOT_YET_VALID")
    if not isinstance(ledger, sqlite3.Connection):
        raise ChallengeBlocked("REPLAY_LEDGER_ABSENT")
    try:
        ledger.execute("BEGIN IMMEDIATE")
        ledger.execute("CREATE TABLE IF NOT EXISTS consumed_j01_challenges "
                       "(nonce TEXT PRIMARY KEY NOT NULL)")
        ledger.execute("INSERT INTO consumed_j01_challenges(nonce) VALUES (?)",
                       (challenge["nonce"],))
        ledger.commit()
    except (sqlite3.IntegrityError, sqlite3.OperationalError) as exc:
        ledger.rollback()
        raise ChallengeBlocked("REPLAY_OR_LEDGER_FAILURE") from exc
    return {
        "decision": "PROTOTYPE_RECEIPT_CONSISTENT_NOT_TRUSTED",
        "source_head": challenge["head"], "model_decision": receipt["decision"],
        "nonce_consumed": True,
        "independent_j01_verified": False, "github_status_issued": False,
        "writer_authorized": False, "merge_authorized": False,
    }
