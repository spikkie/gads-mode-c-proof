"""SEC-02.4B - reproducible clean-context review handoff, not a reviewer.

A review packet contains only immutable synthetic GitHub diff data and a
declared context contract. It NEVER proves independent model execution.
This code cannot approve a PR or publish a GitHub check.
"""
import hashlib
from gads import j01_runtime as runtime
from gads import j01_batches as batches

SCHEMA = "gads.sec024.review-packet.v1"
DECISIONS = {"APPROVE", "REQUEST_CHANGES"}


def prepare(snapshot, *, worker_identity="W-01", reviewer_identity="J-01"):
    if worker_identity == reviewer_identity or not all(
            isinstance(x, str) and x for x in (worker_identity, reviewer_identity)):
        raise runtime.ReviewBlocked("REVIEW_IDENTITY_NOT_INDEPENDENT")
    if not isinstance(snapshot, dict) or snapshot.get("schema") != "gads.j01-diff.v1":
        raise runtime.ReviewBlocked("UNVERIFIED_SOURCE_SNAPSHOT")
    head, base = snapshot.get("reviewed_head"), snapshot.get("base_head")
    if not all(isinstance(x, str) and runtime.SHA.fullmatch(x) for x in (head, base)):
        raise runtime.ReviewBlocked("UNVERIFIED_SOURCE_SHA")
    partitions = batches.partition(snapshot)
    raw_hash = hashlib.sha256(runtime.canonical(snapshot)).hexdigest()
    packet = {
        "schema": SCHEMA, "repo": runtime.REPO,
        "pr_number": snapshot.get("pr_number"), "head_sha": head,
        "base_sha": base, "diff_sha256": raw_hash,
        "worker_identity": worker_identity,
        "reviewer_identity": reviewer_identity,
        "context_policy": {
            "fresh_process": "REQUIRED_NOT_ATTESTED",
            "inherited_w01_context": "FORBIDDEN",
            "model_tools": "FORBIDDEN",
            "source_checkout_execution": "FORBIDDEN",
        },
        "batches": [{"index": b["batch_index"],
                     "digest": batches.batch_digest(b),
                     "files": [f["path"] for f in b["files"]]}
                    for b in partitions],
        "whole_review_covered": False,
        "independent_review_proven": False,
        "owner_approval": False,
        "writer_authorized": False,
    }
    packet["packet_sha256"] = hashlib.sha256(runtime.canonical(packet)).hexdigest()
    return packet


def check_return(packet, result):
    """Only validates shape/binding; never authenticates reviewer provenance."""
    if not isinstance(packet, dict) or not isinstance(result, dict):
        raise runtime.ReviewBlocked("INDEPENDENT_REVIEW_MISSING")
    if packet.get("schema") != SCHEMA:
        raise runtime.ReviewBlocked("INVALID_PACKET")
    checksum = packet.get("packet_sha256")
    source = {k: v for k, v in packet.items() if k != "packet_sha256"}
    if checksum != hashlib.sha256(runtime.canonical(source)).hexdigest():
        raise runtime.ReviewBlocked("HANDOFF_PACKET_TAMPERED")
    if result.get("packet_sha256") != checksum:
        raise runtime.ReviewBlocked("REVIEW_SOURCE_MISMATCH")
    if result.get("reviewer_identity") != packet.get("reviewer_identity"):
        raise runtime.ReviewBlocked("REVIEWER_IDENTITY_MISMATCH")
    if not isinstance(result.get("decision"), str) or result["decision"] not in DECISIONS:
        raise runtime.ReviewBlocked("INVALID_REVIEW_DECISION")
    reported = result.get("batch_digests")
    expected = [b["digest"] for b in packet.get("batches", [])]
    if not isinstance(reported, list) or reported != expected or not expected:
        raise runtime.ReviewBlocked("INCOMPLETE_INDEPENDENT_REVIEW")
    findings = result.get("findings")
    if not isinstance(findings, list) or any(
            not isinstance(v, str) or not v or len(v) > 350 for v in findings):
        raise runtime.ReviewBlocked("INVALID_REVIEW_FINDINGS")
    if result["decision"] == "APPROVE" and findings:
        raise runtime.ReviewBlocked("APPROVAL_WITH_OPEN_FINDINGS")
    if result.get("model_tools_used") is not False:
        raise runtime.ReviewBlocked("MODEL_TOOLS_UNVERIFIED")
    return {
        "packet_integrity": "MATCHES_UNTRUSTED_REPORT",
        "model_decision": result["decision"],
        "independent_fresh_context_proven": False,
        "trusted_review": False,
        "publish_status": False,
        "merge_authorized": False,
    }
