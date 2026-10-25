"""SEC-02 adversarial policy tests; no GitHub writes, no human-account proxy."""
import copy
import hashlib
import json
import unittest
from gads import writer_authority as a
from gads import j01_review as j


def ruleset():
    return {"id": a.SOURCE_RULESET_ID, "name": "protect-main",
            "enforcement": "active", "bypass_actors": [],
            "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"]}},
            "rules": [
                {"type": "deletion"}, {"type": "non_fast_forward"},
                {"type": "pull_request", "parameters": {
                    "required_approving_review_count": 0}},
                {"type": "required_status_checks", "parameters": {
                    "strict_required_status_checks_policy": True,
                    "required_status_checks": [
                        {"context": name, "integration_id": a.QUALITY_INTEGRATION_ID}
                        for name in a.REQUIRED_CHECKS]}}]}


def token():
    return {"repositories": [{"id": 42, "full_name": "spikkie/public-synthetic-state"}],
            "permissions": {"contents": "write", "metadata": "read"}}


def j01():
    main, head, base = "a" * 40, "b" * 40, "c" * 40
    digest = "d" * 64
    run = {"id": 12345, "workflow_id": 8179, "repository": {
        "full_name": a.SOURCE_REPO}, "event": "workflow_dispatch",
        "head_branch": "main", "head_sha": main, "status": "completed",
        "conclusion": "success", "run_attempt": 1}
    report = {"schema": "gads.j01-attestation.v1", "reviewer": "J-01",
              "decision": "APPROVE", "reviewed_head": head,
              "base_head": base, "diff_sha256": digest, "trusted_main_sha": main,
              "run_id": 12345, "context_kind": "fresh_independent",
              "model_execution_id": "review-invocation-123"}
    canon = json.dumps(report, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True).encode("ascii")
    artifact = {"id": 17, "expired": False, "workflow_run": {"id": 12345},
                "digest": "sha256:" + hashlib.sha256(canon).hexdigest()}
    args = {"reviewed_head": head, "base_head": base, "diff_digest": digest,
            "main_sha": main, "trusted_workflow_id": 8179}
    return report, run, artifact, args


def codes(findings):
    return [f.code for f in findings]


class SoloRulesetTests(unittest.TestCase):
    def test_solo_policy_with_three_checks(self):
        self.assertEqual(a.source_ruleset_findings(ruleset()), [])

    def test_second_human_is_not_our_security_model(self):
        r = ruleset()
        r["rules"][2]["parameters"]["required_approving_review_count"] = 1
        self.assertIn("SECOND_HUMAN_ACCOUNT_REQUIRED",
                      codes(a.source_ruleset_findings(r)))

    def test_missing_j01_required_check_blocks(self):
        r = ruleset()
        r["rules"][3]["parameters"]["required_status_checks"].pop(1)
        self.assertIn(a.Finding("REQUIRED_TRUSTED_CHECK_MISSING",
                               "j01_independent_review"),
                      a.source_ruleset_findings(r))

    def test_missing_writer_check_blocks(self):
        r = ruleset()
        r["rules"][3]["parameters"]["required_status_checks"].pop(2)
        self.assertIn(a.Finding("REQUIRED_TRUSTED_CHECK_MISSING",
                               "writer_authorization"),
                      a.source_ruleset_findings(r))

    def test_wrong_check_integrator_blocks(self):
        r = ruleset()
        r["rules"][3]["parameters"]["required_status_checks"][1]["integration_id"] = 0
        self.assertIn(a.Finding("REQUIRED_TRUSTED_CHECK_MISSING",
                               "j01_independent_review"),
                      a.source_ruleset_findings(r))

    def test_loose_ci_blocks(self):
        r = ruleset()
        r["rules"][3]["parameters"]["strict_required_status_checks_policy"] = False
        self.assertIn("STRICT_CI_MISSING", codes(a.source_ruleset_findings(r)))

    def test_unavailable_bypass_blocks(self):
        r = ruleset()
        r.pop("bypass_actors")
        self.assertIn("RULESET_BYPASS_UNVERIFIED",
                      codes(a.source_ruleset_findings(r)))

    def test_bypass_actor_blocks(self):
        r = ruleset()
        r["bypass_actors"] = [{"actor_id": 42}]
        self.assertIn("RULESET_BYPASS_PRESENT",
                      codes(a.source_ruleset_findings(r)))

    def test_missing_pr_protection_blocks(self):
        r = ruleset()
        r["rules"].pop(2)
        self.assertIn("MISSING_RULE_PULL_REQUEST",
                      codes(a.source_ruleset_findings(r)))

    def test_inactive_ruleset_blocks(self):
        r = ruleset()
        r["enforcement"] = "evaluate"
        self.assertIn("RULESET_INACTIVE", codes(a.source_ruleset_findings(r)))

    def test_ruleset_unknown_blocks(self):
        self.assertIn("RULESET_UNAVAILABLE",
                      codes(a.source_ruleset_findings(None)))


class J01TrustTests(unittest.TestCase):
    def test_hypothetical_authenticated_fixture(self):
        report, run, art, kwargs = j01()
        self.assertEqual(j.evidence_findings(report, run, art, **kwargs), [])

    def test_absent_evidence_denied(self):
        self.assertEqual(j.evidence_findings(None, None, None,
                         reviewed_head=None, base_head=None, diff_digest=None,
                         main_sha=None, trusted_workflow_id=None),
                         ["J01_EVIDENCE_ABSENT"])

    def test_stale_head_denied(self):
        r, run, art, kw = j01()
        kw["reviewed_head"] = "e" * 40
        self.assertIn("J01_REVIEW_CONTENT_MISMATCH",
                      j.evidence_findings(r, run, art, **kw))

    def test_changed_diff_denied(self):
        r, run, art, kw = j01()
        kw["diff_digest"] = "0" * 64
        self.assertIn("J01_REVIEW_CONTENT_MISMATCH",
                      j.evidence_findings(r, run, art, **kw))

    def test_untrusted_branch_denied(self):
        r, run, art, kw = j01()
        run["head_branch"] = "development/untrusted"
        self.assertIn("J01_TRUSTED_RUN_PROVENANCE_INVALID",
                      j.evidence_findings(r, run, art, **kw))

    def test_untrusted_workflow_denied(self):
        r, run, art, kw = j01()
        run["workflow_id"] = 111
        self.assertIn("J01_TRUSTED_RUN_PROVENANCE_INVALID",
                      j.evidence_findings(r, run, art, **kw))

    def test_unverified_workflow_configuration_denied(self):
        r, run, art, kw = j01()
        kw["trusted_workflow_id"] = None
        self.assertIn("J01_TRUSTED_WORKFLOW_NOT_DEPLOYED",
                      j.evidence_findings(r, run, art, **kw))

    def test_wrong_repository_denied(self):
        r, run, art, kw = j01()
        run["repository"]["full_name"] = "attacker/untrusted"
        self.assertIn("J01_TRUSTED_RUN_PROVENANCE_INVALID",
                      j.evidence_findings(r, run, art, **kw))

    def test_failed_review_run_denied(self):
        r, run, art, kw = j01()
        run["conclusion"] = "failure"
        self.assertIn("J01_TRUSTED_RUN_PROVENANCE_INVALID",
                      j.evidence_findings(r, run, art, **kw))

    def test_retried_run_denied(self):
        r, run, art, kw = j01()
        run["run_attempt"] = 2
        self.assertIn("J01_TRUSTED_RUN_PROVENANCE_INVALID",
                      j.evidence_findings(r, run, art, **kw))

    def test_self_asserted_context_without_identity_denied(self):
        r, run, art, kw = j01()
        r["model_execution_id"] = ""
        self.assertIn("J01_INDEPENDENCE_CONTRACT_INVALID",
                      j.evidence_findings(r, run, art, **kw))

    def test_operator_decision_in_model_artifact_denied(self):
        r, run, art, kw = j01()
        r["operator_final_decision"] = "MERGE"
        self.assertIn("J01_INDEPENDENCE_CONTRACT_INVALID",
                      j.evidence_findings(r, run, art, **kw))

    def test_unapproved_review_denied(self):
        r, run, art, kw = j01()
        r["decision"] = "REQUEST_CHANGES"
        self.assertIn("J01_REVIEW_CONTENT_MISMATCH",
                      j.evidence_findings(r, run, art, **kw))

    def test_forged_artifact_digest_denied(self):
        r, run, art, kw = j01()
        r["decision"] = "REQUEST_CHANGES"
        self.assertIn("J01_ARTIFACT_PROVENANCE_INVALID",
                      j.evidence_findings(r, run, art, **kw))

    def test_expired_artifact_denied(self):
        r, run, art, kw = j01()
        art["expired"] = True
        self.assertIn("J01_ARTIFACT_PROVENANCE_INVALID",
                      j.evidence_findings(r, run, art, **kw))

    def test_artifact_run_mismatch_denied(self):
        r, run, art, kw = j01()
        art["workflow_run"]["id"] = 333
        self.assertIn("J01_ARTIFACT_PROVENANCE_INVALID",
                      j.evidence_findings(r, run, art, **kw))


class WriterBoundaryTests(unittest.TestCase):
    def test_single_state_only_app(self):
        self.assertEqual(a.scoped_installation_findings(token(), 42), [])

    def test_source_repo_as_state_denied(self):
        self.assertIn("SEPARATE_STATE_REPO_REQUIRED",
                      codes(a.scoped_installation_findings(token(), a.SOURCE_REPO_ID)))

    def test_missing_attestation_denied(self):
        self.assertIn("INSTALLATION_ATTESTATION_ABSENT",
                      codes(a.scoped_installation_findings(None, None)))

    def test_multi_repo_token_denied(self):
        t = token()
        t["repositories"].append({"id": a.SOURCE_REPO_ID})
        self.assertIn("TOKEN_REPOSITORY_SCOPE_NOT_SINGLE",
                      codes(a.scoped_installation_findings(t, 42)))

    def test_excess_privilege_denied(self):
        t = token()
        t["permissions"]["actions"] = "write"
        self.assertIn("TOKEN_EXCESS_PERMISSION",
                      codes(a.scoped_installation_findings(t, 42)))

    def test_lack_of_state_write_denied(self):
        t = token()
        t["permissions"]["contents"] = "read"
        self.assertIn("TOKEN_CONTENTS_WRITE_NOT_PROVEN",
                      codes(a.scoped_installation_findings(t, 42)))

    def test_missing_j01_blocks_even_when_history_safe(self):
        b = {ref: {"protected": True} for ref in a.LEGACY_REFS}
        w = {wid: "disabled_manually" for wid in a.LEGACY_WORKFLOW_IDS}
        f = a.live_readiness(ruleset(), b, w, state_repo_id=42,
                             app_token_attestation=token(),
                             trusted_source_deployed=True,
                             state_repo_hardened=True,
                             owner_release_approved=True)
        self.assertIn("J01_EVIDENCE_ABSENT", codes(f))

    def test_missing_owner_approval_denied(self):
        b = {ref: {"protected": True} for ref in a.LEGACY_REFS}
        w = {wid: "disabled_manually" for wid in a.LEGACY_WORKFLOW_IDS}
        f = a.live_readiness(ruleset(), b, w)
        self.assertIn("OWNER_RELEASE_APPROVAL_MISSING", codes(f))

    def test_historical_workflow_reenabled_denied(self):
        b = {ref: {"protected": True} for ref in a.LEGACY_REFS}
        w = {wid: "disabled_manually" for wid in a.LEGACY_WORKFLOW_IDS}
        w[a.LEGACY_WORKFLOW_IDS[0]] = "active"
        self.assertIn("LEGACY_WORKFLOW_NOT_DISABLED",
                      codes(a.live_readiness(ruleset(), b, w)))

    def test_historical_branch_unprotected_denied(self):
        b = {ref: {"protected": True} for ref in a.LEGACY_REFS}
        b[a.LEGACY_REFS[1]]["protected"] = False
        w = {wid: "disabled_manually" for wid in a.LEGACY_WORKFLOW_IDS}
        self.assertIn("LEGACY_WRITER_BRANCH_NOT_PROTECTED",
                      codes(a.live_readiness(ruleset(), b, w)))

    def test_missing_workflow_api_evidence_denied(self):
        b = {ref: {"protected": True} for ref in a.LEGACY_REFS}
        self.assertIn("LEGACY_WORKFLOW_STATES_UNAVAILABLE",
                      codes(a.live_readiness(ruleset(), b)))
