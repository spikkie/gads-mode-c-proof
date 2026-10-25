"""Fail-closed J-01 evidence policy. This module cannot mint trust or a check run.

All "trusted_run" and "artifact" arguments MUST be obtained independently by
reviewed code from authenticated GitHub APIs, not from a PR, runner artifact
contents, environment variable, model response, or user-supplied JSON.
"""
import hashlib
import io
import json
import re
import stat
import zipfile

HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")

SOURCE_REPO_ID = 1432047514
ARCHIVE_NAME = "gads-j01-attestation-v1"
MEMBER_NAME = "j01-attestation.json"
MAX_ARCHIVE_BYTES = 65536
MAX_REPORT_BYTES = 8192


def _unique_pairs(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError("DUPLICATE_JSON_KEY")
        obj[key] = value
    return obj


def _load_report(archive):
    if not isinstance(archive, bytes) or len(archive) > MAX_ARCHIVE_BYTES:
        raise ValueError("INVALID_ARCHIVE_SIZE_OR_TYPE")
    try:
        with zipfile.ZipFile(io.BytesIO(archive)) as z:
            infos = z.infolist()
            if len(infos) != 1 or infos[0].filename != MEMBER_NAME:
                raise ValueError("UNEXPECTED_ARCHIVE_MEMBERS")
            info = infos[0]
            kind = (info.external_attr >> 16) & 0o170000
            if (info.is_dir() or kind not in (0, stat.S_IFREG)
                    or info.file_size > MAX_REPORT_BYTES):
                raise ValueError("UNSAFE_ARCHIVE_ENTRY")
            raw = z.read(info)
            if len(raw) > MAX_REPORT_BYTES:
                raise ValueError("OVERSIZED_REPORT")
    except (zipfile.BadZipFile, OSError, RuntimeError, EOFError) as exc:
        raise ValueError("CORRUPT_ARCHIVE") from exc
    try:
        result = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs)
    except (ValueError, UnicodeError) as exc:
        raise ValueError("INVALID_REPORT") from exc
    if not isinstance(result, dict):
        raise ValueError("INVALID_REPORT_SHAPE")
    return result



def evidence_findings(archive_bytes, trusted_run, artifact, *,
                      reviewed_head, base_head, diff_digest, main_sha,
                      trusted_workflow_id, source_repo="spikkie/gads-mode-c-proof"):
    """Check a proposed attestation against independently observed provenance.

    A zero-finding *fixture* is only necessary, never authority to publish,
    merge, issue credentials, or write a ref.
    """
    findings = []
    def block(code):
        findings.append(code)

    if archive_bytes is None or not isinstance(trusted_run, dict) or not isinstance(artifact, dict):
        return ["J01_EVIDENCE_ABSENT"]
    if not all(isinstance(v, str) and HEX40.fullmatch(v)
               for v in (reviewed_head, base_head, main_sha)):
        block("J01_EXPECTED_GIT_ID_UNVERIFIED")
    if not isinstance(diff_digest, str) or not HEX64.fullmatch(diff_digest):
        block("J01_EXPECTED_DIFF_UNVERIFIED")
    if type(trusted_workflow_id) is not int or trusted_workflow_id <= 0:
        block("J01_TRUSTED_WORKFLOW_NOT_DEPLOYED")

    expected_identity = (
        trusted_run.get("repository", {}).get("full_name") if
        isinstance(trusted_run.get("repository"), dict) else None
    )
    if (expected_identity != source_repo or
            (trusted_run.get('repository') or {}).get('id') != SOURCE_REPO_ID or
            trusted_run.get("workflow_id") != trusted_workflow_id or
            trusted_run.get("event") != "workflow_dispatch" or
            trusted_run.get("head_branch") != "main" or
            trusted_run.get("head_sha") != main_sha or
            trusted_run.get("status") != "completed" or
            trusted_run.get("conclusion") != "success" or
            trusted_run.get("run_attempt") != 1 or
            type(trusted_run.get("id")) is not int or trusted_run["id"] <= 0):
        block("J01_TRUSTED_RUN_PROVENANCE_INVALID")
    expected_zip_digest = ("sha256:" + hashlib.sha256(archive_bytes).hexdigest()
                           if isinstance(archive_bytes, bytes) else None)
    source_run = artifact.get("workflow_run")
    if (type(artifact.get("id")) is not int or artifact["id"] <= 0 or
            artifact.get("name") != ARCHIVE_NAME or
            artifact.get("expired") is not False or
            artifact.get("digest") != expected_zip_digest or
            not isinstance(source_run, dict) or
            source_run.get("id") != trusted_run.get("id") or
            source_run.get("repository_id") != SOURCE_REPO_ID or
            source_run.get("head_sha") != main_sha):
        block("J01_ARTIFACT_PROVENANCE_INVALID")
        return findings  # Never process an unverified ZIP.
    try:
        attestation = _load_report(archive_bytes)
    except ValueError:
        return findings + ["J01_ARTIFACT_ARCHIVE_INVALID"]
    if (attestation.get("schema") != "gads.j01-attestation.v1" or
            attestation.get("reviewer") != "J-01" or
            attestation.get("decision") != "APPROVE" or
            attestation.get("reviewed_head") != reviewed_head or
            attestation.get("base_head") != base_head or
            attestation.get("diff_sha256") != diff_digest or
            attestation.get("trusted_main_sha") != main_sha or
            attestation.get("run_id") != trusted_run.get("id")):
        block("J01_REVIEW_CONTENT_MISMATCH")
    if (attestation.get("context_kind") != "fresh_independent" or
            not isinstance(attestation.get("model_execution_id"), str) or
            not attestation.get("model_execution_id").strip() or
            attestation.get("operator_final_decision") is not None):
        block("J01_INDEPENDENCE_CONTRACT_INVALID")
    # Source-verified protected J-01 execution and context isolation are
    # independent preconditions. This policy never grants a writer token.
    return findings
