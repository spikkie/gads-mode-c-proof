"""GADS trusted-writer authorization contract (no writes, no credentials).

A positive *hypothetical* result is not an authorization: actual independent
review, protected deployed code, App installation/credential and repository
rules must each be independently confirmed before a real GraphQL CAS call.
"""
from dataclasses import dataclass

SOURCE_REPO = "spikkie/gads-mode-c-proof"
SOURCE_REPO_ID = 1432047514
SOURCE_RULESET_ID = 25778767
QUALITY_INTEGRATION_ID = 15368
LEGACY_REFS = (
    "qualification/c06-h00-live-20261024",
    "qualification/c07-trusted-cross-run-20261024",
    "qualification/c08-reconcile-20261024",
)
PR_STACK = (10, 11, 12, 13)


@dataclass(frozen=True)
class Finding:
    code: str
    detail: str = ""


def _add(out, code, detail=""):
    out.append(Finding(code, detail))


def source_ruleset_findings(ruleset):
    """Recognize required GitHub-enforced controls; unknown is never 'safe'."""
    out = []
    if not isinstance(ruleset, dict):
        return [Finding("RULESET_UNAVAILABLE")]
    if ruleset.get("id") != SOURCE_RULESET_ID or ruleset.get("name") != "protect-main":
        _add(out, "RULESET_IDENTITY")
    if ruleset.get("enforcement") != "active":
        _add(out, "RULESET_INACTIVE")
    conditions = ruleset.get("conditions") or {}
    if "~DEFAULT_BRANCH" not in ((conditions.get("ref_name") or {}).get("include") or []):
        _add(out, "RULESET_DEFAULT_BRANCH_NOT_INCLUDED")
    if "bypass_actors" not in ruleset:
        _add(out, "RULESET_BYPASS_UNVERIFIED")
    elif not isinstance(ruleset["bypass_actors"], list):
        _add(out, "RULESET_BYPASS_UNVERIFIED")
    elif ruleset["bypass_actors"]:
        _add(out, "RULESET_BYPASS_PRESENT")
    entries = ruleset.get("rules")
    if not isinstance(entries, list):
        return out + [Finding("RULES_UNAVAILABLE")]
    controls = {x["type"]: x.get("parameters") or {}
                for x in entries if isinstance(x, dict) and isinstance(x.get("type"), str)}
    for kind in ("deletion", "non_fast_forward", "pull_request", "required_status_checks"):
        if kind not in controls:
            _add(out, "MISSING_RULE_" + kind.upper())
    review = controls.get("pull_request") or {}
    count = review.get("required_approving_review_count")
    if type(count) is not int or count < 1:
        _add(out, "INDEPENDENT_APPROVAL_NOT_ENFORCED")
    if review.get("dismiss_stale_reviews_on_push") is not True:
        _add(out, "STALE_REVIEW_DISMISSAL_MISSING")
    if review.get("require_last_push_approval") is not True:
        _add(out, "LATEST_PUSH_APPROVAL_MISSING")
    checks = controls.get("required_status_checks") or {}
    if checks.get("strict_required_status_checks_policy") is not True:
        _add(out, "STRICT_CI_MISSING")
    required = checks.get("required_status_checks")
    if not isinstance(required, list) or not any(
        isinstance(c, dict) and c.get("context") == "quality"
        and c.get("integration_id") == QUALITY_INTEGRATION_ID
        for c in required
    ):
        _add(out, "REQUIRED_QUALITY_SOURCE_MISSING")
    if not isinstance(required, list) or not any(
        isinstance(c, dict) and c.get("context") == "writer_authorization"
        and c.get("integration_id") == QUALITY_INTEGRATION_ID
        for c in required
    ):
        _add(out, "WRITER_AUTHORIZATION_CHECK_NOT_REQUIRED")
    return out


def scoped_installation_findings(token_metadata, state_repo_id):
    """Review sanitized response from GitHub App token minting, not a bearer token.

    State repo MUST be separate, containing only synthetic state. The App must
    not have write access to the GADS source repository.
    """
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
        for key, value in permissions.items():
            if key not in ("contents", "metadata"):
                _add(out, "TOKEN_EXCESS_PERMISSION", key)
        if permissions.get("metadata") not in (None, "read"):
            _add(out, "TOKEN_METADATA_PERMISSION_UNEXPECTED")
    # A successful scope check is only necessary, never sufficient.
    return out


def review_findings(pulls, reviews):
    """Request independent latest-head reviews on each PR in the clean stack."""
    out = []
    if not isinstance(pulls, dict) or not isinstance(reviews, dict):
        return [Finding("REVIEW_EVIDENCE_MISSING")]
    for number in PR_STACK:
        p = pulls.get(number)
        rs = reviews.get(number)
        if not isinstance(p, dict) or not isinstance(rs, list):
            _add(out, "PR_REVIEW_UNAVAILABLE", str(number))
            continue
        head = (p.get("head") or {}).get("sha")
        owner = (p.get("user") or {}).get("login")
        if not (isinstance(head, str) and len(head) == 40 and isinstance(owner, str)):
            _add(out, "PR_IDENTITY_UNVERIFIED", str(number))
            continue
        # Review records may include a later dismissal or request-changes;
        # only the last dated review per independent reviewer can count.
        if any(not isinstance(r, dict) or not isinstance(r.get("submitted_at"), str)
               or not isinstance((r.get("user") or {}).get("login"), str) for r in rs):
            _add(out, "PR_REVIEW_TIMELINE_UNVERIFIED", str(number))
            continue
        latest = {}
        for r in sorted(rs, key=lambda x: x["submitted_at"]):
            latest[r["user"]["login"]] = r
        if not any(login != owner and r.get("state") == "APPROVED"
                   and r.get("commit_id") == head
                   for login,r in latest.items()):
            _add(out, "INDEPENDENT_LATEST_HEAD_REVIEW_MISSING", str(number))
    return out


def live_readiness(source_ruleset, pulls, reviews, legacy_branches,
                   state_repo_id=None, app_token_attestation=None,
                   trusted_source_deployed=False, state_repo_hardened=False):
    findings = source_ruleset_findings(source_ruleset)
    findings += review_findings(pulls, reviews)
    if not isinstance(legacy_branches, dict):
        _add(findings, "LEGACY_BRANCH_AUTHORITY_UNAVAILABLE")
    else:
        for branch in LEGACY_REFS:
            observed = legacy_branches.get(branch)
            if not isinstance(observed, dict) or observed.get("protected") is not True:
                _add(findings, "LEGACY_WRITER_BRANCH_NOT_PROTECTED", branch)
    findings += scoped_installation_findings(app_token_attestation, state_repo_id)
    if trusted_source_deployed is not True:
        _add(findings, "TRUSTED_SOURCE_NOT_DEPLOYED")
    if state_repo_hardened is not True:
        _add(findings, "STATE_REPO_RULES_UNVERIFIED")
    return sorted(findings, key=lambda v: (v.code, v.detail))
