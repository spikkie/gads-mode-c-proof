"""GADS writer authority: fail-closed negative cases and clean positive fixtures."""
import copy
import unittest
from gads import writer_authority as a


def good_ruleset():
    return {
        "id":a.SOURCE_RULESET_ID,"name":"protect-main","enforcement":"active",
        "bypass_actors":[],"conditions":{"ref_name":{"include":["~DEFAULT_BRANCH"]}},
        "rules":[
            {"type":"deletion"},{"type":"non_fast_forward"},
            {"type":"pull_request","parameters":{
                "required_approving_review_count":1,
                "dismiss_stale_reviews_on_push":True,
                "require_last_push_approval":True}},
            {"type":"required_status_checks","parameters":{
                "strict_required_status_checks_policy":True,
                "required_status_checks":[{
                    "context":"quality",
                    "integration_id":a.QUALITY_INTEGRATION_ID},
                    {"context":"writer_authorization",
                    "integration_id":a.QUALITY_INTEGRATION_ID}]}}
        ]
    }


def good_review():
    prs={}
    reviews={}
    for n in a.PR_STACK:
        sha=(str(n)[-1] * 40)
        prs[n]={"head":{"sha":sha},"user":{"login":"author"}}
        reviews[n]=[{"state":"APPROVED","commit_id":sha,
                     "submitted_at":"2026-10-25T12:00:00Z",
                     "user":{"login":"security-reviewer"}}]
    return prs,reviews


def good_token():
    return {
        "repositories":[{"id":42,"full_name":"spikkie/gads-state-proof"}],
        "permissions":{"contents":"write","metadata":"read"}
    }


class RulesTest(unittest.TestCase):
    def test_safe_ruleset_contract(self):
        self.assertEqual(a.source_ruleset_findings(good_ruleset()),[])

    def test_zero_review_is_blocker(self):
        s=good_ruleset();s["rules"][2]["parameters"]["required_approving_review_count"]=0
        self.assertIn("INDEPENDENT_APPROVAL_NOT_ENFORCED",
                      [f.code for f in a.source_ruleset_findings(s)])

    def test_stale_reviews_disabled_is_blocker(self):
        s=good_ruleset();s["rules"][2]["parameters"]["dismiss_stale_reviews_on_push"]=False
        self.assertIn("STALE_REVIEW_DISMISSAL_MISSING",
                      [f.code for f in a.source_ruleset_findings(s)])

    def test_last_push_required(self):
        s=good_ruleset();s["rules"][2]["parameters"]["require_last_push_approval"]=False
        self.assertIn("LATEST_PUSH_APPROVAL_MISSING",
                      [f.code for f in a.source_ruleset_findings(s)])

    def test_strict_quality_required(self):
        s=good_ruleset();s["rules"][3]["parameters"]["strict_required_status_checks_policy"]=False
        self.assertIn("STRICT_CI_MISSING",
                      [f.code for f in a.source_ruleset_findings(s)])

    def test_wrong_quality_integration_rejected(self):
        s=good_ruleset();s["rules"][3]["parameters"]["required_status_checks"][0]["integration_id"]=0
        self.assertIn("REQUIRED_QUALITY_SOURCE_MISSING",
                      [f.code for f in a.source_ruleset_findings(s)])

    def test_unpublished_writer_check_is_not_clean(self):
        r=good_ruleset()
        r["rules"][3]["parameters"]["required_status_checks"].pop()
        self.assertIn("WRITER_AUTHORIZATION_CHECK_NOT_REQUIRED",
                      [f.code for f in a.source_ruleset_findings(r)])

    def test_unknown_bypass_is_not_clean(self):
        s=good_ruleset();s.pop("bypass_actors")
        self.assertIn("RULESET_BYPASS_UNVERIFIED",
                      [f.code for f in a.source_ruleset_findings(s)])

    def test_null_bypass_is_unknown_not_empty(self):
        r=good_ruleset();r["bypass_actors"]=None
        self.assertIn("RULESET_BYPASS_UNVERIFIED",
                      [f.code for f in a.source_ruleset_findings(r)])

    def test_explicit_bypass_denied(self):
        s=good_ruleset();s["bypass_actors"]=[{"actor_id":1}]
        self.assertIn("RULESET_BYPASS_PRESENT",
                      [f.code for f in a.source_ruleset_findings(s)])

    def test_unknown_or_inactive_ruleset_denied(self):
        self.assertIn("RULESET_UNAVAILABLE",
                      [f.code for f in a.source_ruleset_findings(None)])
        s=good_ruleset();s["enforcement"]="evaluate"
        self.assertIn("RULESET_INACTIVE",
                      [f.code for f in a.source_ruleset_findings(s)])


class AppTokenTests(unittest.TestCase):
    def test_separately_scoped_app_token_fixture(self):
        self.assertEqual(a.scoped_installation_findings(good_token(),42),[])

    def test_same_repo_is_never_a_state_authority(self):
        self.assertIn("SEPARATE_STATE_REPO_REQUIRED",
                      [f.code for f in a.scoped_installation_findings(good_token(),
                                                                 a.SOURCE_REPO_ID)])

    def test_missing_installation_attestation_denied(self):
        self.assertIn("INSTALLATION_ATTESTATION_ABSENT",
                      [f.code for f in a.scoped_installation_findings(None,None)])

    def test_multiple_accessible_repos_denied(self):
        x=good_token();x["repositories"].append({"id":a.SOURCE_REPO_ID})
        self.assertIn("TOKEN_REPOSITORY_SCOPE_NOT_SINGLE",
                      [f.code for f in a.scoped_installation_findings(x,42)])

    def test_wrong_target_repo_denied(self):
        x=good_token();x["repositories"][0]["id"]=71
        self.assertIn("TOKEN_REPOSITORY_NOT_DEDICATED_STATE",
                      [f.code for f in a.scoped_installation_findings(x,42)])

    def test_model_or_actions_write_permissions_denied(self):
        x=good_token();x["permissions"]["actions"]="write"
        self.assertIn("TOKEN_EXCESS_PERMISSION",
                      [f.code for f in a.scoped_installation_findings(x,42)])

    def test_admin_permission_denied(self):
        x=good_token();x["permissions"]["administration"]="write"
        self.assertIn("TOKEN_EXCESS_PERMISSION",
                      [f.code for f in a.scoped_installation_findings(x,42)])

    def test_no_contents_write_is_not_valid(self):
        x=good_token();x["permissions"]["contents"]="read"
        self.assertIn("TOKEN_CONTENTS_WRITE_NOT_PROVEN",
                      [f.code for f in a.scoped_installation_findings(x,42)])


class IndependentReviewTests(unittest.TestCase):
    def test_approved_latest_head(self):
        p,r=good_review();self.assertEqual(a.review_findings(p,r),[])

    def test_later_dismissal_cannot_revive_old_approval(self):
        p,r=good_review()
        r[12].append({"state":"DISMISSED","commit_id":p[12]["head"]["sha"],
                      "submitted_at":"2026-10-25T12:30:00Z",
                      "user":{"login":"security-reviewer"}})
        self.assertIn("INDEPENDENT_LATEST_HEAD_REVIEW_MISSING",
                      [f.code for f in a.review_findings(p,r)])

    def test_old_sha_approval_denied(self):
        p,r=good_review();r[12][0]["commit_id"]="f"*40
        self.assertIn("INDEPENDENT_LATEST_HEAD_REVIEW_MISSING",
                      [f.code for f in a.review_findings(p,r)])

    def test_author_self_review_denied(self):
        p,r=good_review();r[12][0]["user"]["login"]="author"
        self.assertIn("INDEPENDENT_LATEST_HEAD_REVIEW_MISSING",
                      [f.code for f in a.review_findings(p,r)])

    def test_undated_review_cannot_approve(self):
        p,r=good_review();r[12][0].pop("submitted_at")
        self.assertIn("PR_REVIEW_TIMELINE_UNVERIFIED",
                      [f.code for f in a.review_findings(p,r)])

    def test_missing_reviews_denied(self):
        p,r=good_review();r.pop(11)
        self.assertIn("PR_REVIEW_UNAVAILABLE",
                      [f.code for f in a.review_findings(p,r)])

    def test_live_gate_stays_blocked_without_deployment(self):
        p,r=good_review()
        b={ref:{"protected":True} for ref in a.LEGACY_REFS}
        findings=a.live_readiness(good_ruleset(),p,r,b,42,good_token())
        codes=[x.code for x in findings]
        self.assertIn("TRUSTED_SOURCE_NOT_DEPLOYED",codes)
        self.assertIn("STATE_REPO_RULES_UNVERIFIED",codes)

    def test_live_gate_denies_unprotected_historical_writer(self):
        p,r=good_review()
        b={ref:{"protected":True} for ref in a.LEGACY_REFS}
        b[a.LEGACY_REFS[0]]["protected"]=False
        findings=a.live_readiness(good_ruleset(),p,r,b,42,good_token(),True,True)
        self.assertIn("LEGACY_WRITER_BRANCH_NOT_PROTECTED",
                      [x.code for x in findings])
