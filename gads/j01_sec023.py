"""SEC-02.3: pure read-only J-01 observation verifier.

It independently compares an observation with an already authenticated,
exact-head, complete canonical PR snapshot. It NEVER converts a local
observation to a GitHub-trusted run, approved merge or writer credential.
Callers MUST obtain snapshot via their own audited GET source; observation
content is untrusted, even when its decision says APPROVE.
"""
import hashlib
from gads import j01_runtime as rt
from gads import j01_batches as batches

VALID = ("APPROVE", "REQUEST_CHANGES")
SCHEMA = "gads.j01-local-observation.v1"


def verify_observation(snapshot, observed):
    if not isinstance(snapshot, dict) or not isinstance(observed, dict):
        raise rt.ReviewBlocked("OBSERVATION_OR_SNAPSHOT_ABSENT")
    if snapshot.get("schema") != "gads.j01-diff.v1":
        raise rt.ReviewBlocked("UNEXPECTED_SNAPSHOT_SCHEMA")
    if observed.get("schema") != SCHEMA or observed.get("trust_level") != "UNTRUSTED_LOCAL_OBSERVATION":
        raise rt.ReviewBlocked("OBSERVATION_TRUST_SPOOF")
    if any(observed.get(k) is not False for k in
           ("writer_authorized", "required_status_issued", "owner_approval_recorded")):
        raise rt.ReviewBlocked("UNAUTHORIZED_PRIVILEGE_CLAIM")
    if any(k in observed for k in
           ("trusted_main_sha", "run_id", "trusted_workflow_id", "app_token")):
        raise rt.ReviewBlocked("FORGED_TRUSTED_PROVENANCE")
    if (observed.get("reviewer") != "J-01" or
            observed.get("pr_number") != snapshot.get("pr_number") or
            observed.get("reviewed_head") != snapshot.get("reviewed_head") or
            observed.get("base_head") != snapshot.get("base_head") or
            observed.get("diff_sha256") != hashlib.sha256(rt.canonical(snapshot)).hexdigest()):
        raise rt.ReviewBlocked("LOCAL_REVIEW_SOURCE_BINDING_MISMATCH")
    expected = batches.partition(snapshot)
    actual = observed.get("review_batches")
    if (not isinstance(actual, list) or len(actual) != len(expected) or
            observed.get("review_batch_count") != len(expected) or
            observed.get("reviewed_file_count") != len(snapshot["files"])):
        raise rt.ReviewBlocked("REVIEW_BATCH_COVERAGE_INVALID")
    normalized_findings = []
    all_approved = True
    for i, pair in enumerate(zip(expected, actual), start=1):
        planned, got = pair
        if not isinstance(got, dict) or set(got) != {
                "batch_index", "sha256", "decision", "findings"}:
            raise rt.ReviewBlocked("INVALID_BATCH_ATTESTATION")
        if (got["batch_index"] != i or got["sha256"] != batches.batch_digest(planned)
                or got["decision"] not in VALID):
            raise rt.ReviewBlocked("BATCH_DIGEST_OR_ORDER_MISMATCH")
        findings = got["findings"]
        if not isinstance(findings, list) or len(findings) > 12 or any(
                not isinstance(v, str) or not 1 <= len(v) <= 350 for v in findings):
            raise rt.ReviewBlocked("INVALID_BATCH_FINDINGS")
        if got["decision"] == "APPROVE" and findings:
            raise rt.ReviewBlocked("CONFLICTING_BATCH_APPROVAL")
        all_approved &= got["decision"] == "APPROVE"
        normalized_findings.extend(f"batch {i}/{len(expected)}: {v}" for v in findings)
    aggregate = "APPROVE" if all_approved else "REQUEST_CHANGES"
    if (observed.get("decision") != aggregate or
            observed.get("findings") != normalized_findings):
        raise rt.ReviewBlocked("AGGREGATE_REVIEW_FORGED")
    if not isinstance(observed.get("model"), str) or not observed["model"]:
        raise rt.ReviewBlocked("MODEL_UNKNOWN")
    # Passing this integrity comparison does not authenticate provenance.
    return {"integrity": "CONSISTENT_UNTRUSTED_LOCAL_OBSERVATION",
            "reviewed_head": snapshot["reviewed_head"],
            "batches": len(expected), "files": len(snapshot["files"]),
            "model_decision": aggregate,
            "trusted_j01": False, "writer_authorized": False,
            "owner_approval": False, "required_status_issued": False}


def declared_sandbox_findings(policy):
    """Architecture lint, NOT enforcement of the local OS/network firewall."""
    required = {
        "schema": "gads.sandbox-requirements.v1",
        "status": "SPECIFICATION_NOT_DEPLOYED",
        "runner_registration": "FORBIDDEN",
        "github_api": {"auth": "NONE", "methods": ["GET"],
                       "repo": rt.REPO, "data": "PUBLIC_SYNTHETIC_ONLY"},
        "model": {"endpoint": rt.OLLAMA_URL, "tools": "FORBIDDEN",
                  "inherited_context": "FORBIDDEN"},
        "network": {"default": "DENY", "external_except_github_read": "DENY",
                    "model_service_only_loopback": True},
        "filesystem": {"source_checkout": "READ_ONLY",
                       "output": "NEW_FILES_ONLY",
                       "work_data": "NO_ACCESS",
                       "ssh_keys": "NO_ACCESS",
                       "docker_socket": "NO_ACCESS"},
        "identity": {"github_token": "NONE", "cloud_keys": "NONE",
                     "write_permissions": "NONE"},
    }
    if policy == required:
        return []
    if not isinstance(policy, dict):
        return ["SANDBOX_CONTRACT_ABSENT"]
    return ["SANDBOX_CONTRACT_DRIFT"]
