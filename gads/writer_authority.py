"""GADS trusted-writer admission: solo operator plus independent J-01.

Read-only pure policy. This module does not authorize any token or write.
J-01 identity assertions are insufficient without authenticated provenance.
"""
from dataclasses import dataclass
from gads import j01_review

SOURCE_REPO = "spikkie/gads-mode-c-proof"
SOURCE_REPO_ID = 1432047514
SOURCE_RULESET_ID = 25778767
QUALITY_INTEGRATION_ID = 15368
LEGACY_REFS = (
    "qualification/c06-h00-live-20261024",
    "qualification/c07-trusted-cross-run-20261024",
    "qualification/c08-reconcile-20261024",
)
LEGACY_WORKFLOW_IDS = (395044779, 395058116, 395072504, 395083466, 395103255)
REQUIRED_CHECKS = ("quality", "j01_independent_review", "writer_authorization")


@dataclass(frozen=True)
class Finding:
    code: str
    detail: str = ""


def _add(out, code, detail=""):
    out.append(Finding(code, detail))


def source_ruleset_findings(ruleset):
    """No second human account required; independent J-01 check IS required.

    GitHub Actions integration ID alone cannot prove that a check comes from
    protected code: separately bind its run/workflow/source provenance.
    """
    out = []
    if not isinstance(ruleset, dict):
        return [Finding("RULESET_UNAVAILABLE")]
    if ruleset.get("id") != SOURCE_RULESET_ID or ruleset.get("name") != "protect-main":
        _add(out, "RULESET_IDENTITY")
    if ruleset.get("enforcement") != "active":
        _add(out, "RULESET_INACTIVE")
    if "~DEFAULT_BRANCH" not in (((ruleset.get("conditions") or {})
                                 .get("ref_name") or {}).get("include") or []):
        _add(out, "RULESET_DEFAULT_BRANCH_NOT_INCLUDED")
    if not isinstance(ruleset.get("bypass_actors"), list):
        _add(out, "RULESET_BYPASS_UNVERIFIED")
    elif ruleset["bypass_actors"]:
        _add(out, "RULESET_BYPASS_PRESENT")
    entries = ruleset.get("rules")
    if not isinstance(entries, list):
        return out + [Finding("RULES_UNAVAILABLE")]
    rules = {r["type"]: r.get("parameters") or {} for r in entries
             if isinstance(r, dict) and isinstance(r.get("type"), str)}
    for kind in ("deletion", "non_fast_forward", "pull_request", "required_status_checks"):
        if kind not in rules:
            _add(out, "MISSING_RULE_" + kind.upper())
    review = rules.get("pull_request", {})
    if type(review.get("required_approving_review_count")) is not int:
        _add(out, "SOLO_REVIEW_POLICY_UNVERIFIED")
    elif review["required_approving_review_count"] != 0:
        _add(out, "SECOND_HUMAN_ACCOUNT_REQUIRED")
    checks = rules.get("required_status_checks", {})
    if checks.get("strict_required_status_checks_policy") is not True:
        _add(out, "STRICT_CI_MISSING")
    required = checks.get("required_status_checks")
    for context in REQUIRED_CHECKS:
        if not isinstance(required, list) or not any(
            isinstance(c, dict) and c.get("context") == context
            and c.get("integration_id") == QUALITY_INTEGRATION_ID for c in required
        ):
            _add(out, "REQUIRED_TRUSTED_CHECK_MISSING", context)
    return out


def scoped_installation_findings(token_metadata, state_repo_id):
    out = []
    if type(state_repo_id) is not int or state_repo_id <= 0 or state_repo_id == SOURCE_REPO_ID:
        _add(out, "SEPARATE_STATE_REPO_REQUIRED")
    if not isinstance(token_metadata, dict):
        return out + [Finding("INSTALLATION_ATTESTATION_ABSENT")]
    repos = token_metadata.get("repositories")
    if not isinstance(repos, list) or len(repos) != 1 or not isinstance(repos[0], dict):
        _add(out, "TOKEN_REPOSITORY_SCOPE_NOT_SINGLE")
    elif repos[0].get("id") != state_repo_id or repos[0].get("id") == SOURCE_REPO_ID:
        _add(out, "TOKEN_REPOSITORY_NOT_DEDICATED_STATE")
    permissions = token_metadata.get("permissions")
    if not isinstance(permissions, dict) or permissions.get("contents") != "write":
        _add(out, "TOKEN_CONTENTS_WRITE_NOT_PROVEN")
    else:
        for key in permissions:
            if key not in ("contents", "metadata"):
                _add(out, "TOKEN_EXCESS_PERMISSION", key)
        if permissions.get("metadata") not in (None, "read"):
            _add(out, "TOKEN_METADATA_PERMISSION_UNEXPECTED")
    return out


def live_readiness(ruleset, legacy_branches, workflow_states=None,
                   j01_attestation=None, j01_run=None, j01_artifact=None,
                   expected_head=None, expected_base=None, diff_digest=None,
                   source_main_sha=None, j01_workflow_id=None,
                   state_repo_id=None, app_token_attestation=None,
                   trusted_source_deployed=False, state_repo_hardened=False,
                   owner_release_approved=False):
    """All missing security evidence fails closed. No approval is minted."""
    findings = source_ruleset_findings(ruleset)
    if not isinstance(legacy_branches, dict):
        _add(findings, "LEGACY_BRANCH_AUTHORITY_UNAVAILABLE")
    else:
        for ref in LEGACY_REFS:
            observed = legacy_branches.get(ref)
            if not isinstance(observed, dict) or observed.get("protected") is not True:
                _add(findings, "LEGACY_WRITER_BRANCH_NOT_PROTECTED", ref)
    if not isinstance(workflow_states, dict):
        _add(findings, "LEGACY_WORKFLOW_STATES_UNAVAILABLE")
    else:
        for wid in LEGACY_WORKFLOW_IDS:
            if workflow_states.get(wid) != "disabled_manually":
                _add(findings, "LEGACY_WORKFLOW_NOT_DISABLED", str(wid))
    if (j01_attestation is None or j01_run is None or j01_artifact is None):
        _add(findings, "J01_EVIDENCE_ABSENT")
    else:
        for problem in j01_review.evidence_findings(
            j01_attestation, j01_run, j01_artifact,
            reviewed_head=expected_head, base_head=expected_base,
            diff_digest=diff_digest, main_sha=source_main_sha,
            trusted_workflow_id=j01_workflow_id):
            _add(findings, problem)
    findings += scoped_installation_findings(app_token_attestation, state_repo_id)
    if trusted_source_deployed is not True:
        _add(findings, "TRUSTED_SOURCE_NOT_DEPLOYED")
    if state_repo_hardened is not True:
        _add(findings, "STATE_REPO_RULES_UNVERIFIED")
    if owner_release_approved is not True:
        _add(findings, "OWNER_RELEASE_APPROVAL_MISSING")
    return sorted(findings, key=lambda v: (v.code, v.detail))
