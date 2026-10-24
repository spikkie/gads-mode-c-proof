"""C-09 fail-closed security posture policy fixture tests."""
import unittest
from scripts import c09_posture as p

def sample():
    r={"enforcement":"active","bypass_actors":[],"rules":[
       {"type":"deletion"},{"type":"non_fast_forward"},
       {"type":"pull_request","parameters":{"required_approving_review_count":1,
                                             "dismiss_stale_reviews_on_push":True,
                                             "require_last_push_approval":True}},
       {"type":"required_status_checks","parameters":{"strict_required_status_checks_policy":True,
             "required_status_checks":[{"context":"quality","integration_id":15368}]}}]}
    f={name:"on:\n  workflow_dispatch:\njobs:\n  read:\n    permissions:\n      contents: read\n"
       for name in p.WRITERS}
    f[p.LISTENER]="on:\n  workflow_run:\njobs:\n  admit:\n    permissions:\n      contents: read\n"
    return r,f

class PostureTests(unittest.TestCase):
    def test_safe_fixture(self):
        r,f=sample();self.assertEqual(p.assess(r,f),[])
    def test_review_zero_denied(self):
        r,f=sample();r["rules"][2]["parameters"]["required_approving_review_count"]=0
        self.assertIn("SEC-NO-HUMAN-APPROVAL",p.assess(r,f))
    def test_stale_reviews_denied(self):
        r,f=sample();r["rules"][2]["parameters"]["dismiss_stale_reviews_on_push"]=False
        self.assertIn("SEC-STALE-APPROVALS",p.assess(r,f))
    def test_loose_checks_denied(self):
        r,f=sample();r["rules"][3]["parameters"]["strict_required_status_checks_policy"]=False
        self.assertIn("SEC-LOOSE-CHECKS",p.assess(r,f))
    def test_branch_writer_denied(self):
        r,f=sample();f[p.WRITERS[0]]="on:\n  push:\n    branches:\n      - qualification/c06\njobs:\n  writer:\n    permissions:\n      contents: write\n"
        self.assertIn("SEC-UNPROTECTED-WRITER:"+p.WRITERS[0],p.assess(r,f))
    def test_actions_writer_denied(self):
        r,f=sample();f[p.WRITERS[3]]="on:\n  push:\n    branches:\n      - qualification/c07\njobs:\n  writer:\n    permissions:\n      actions: write\n"
        self.assertIn("SEC-UNPROTECTED-WRITER:"+p.WRITERS[3],p.assess(r,f))
    def test_listener_no_writes(self):
        r,f=sample();f[p.LISTENER]="on:\n  workflow_run:\njobs:\n  bad:\n    permissions:\n      contents: write\n"
        self.assertIn("SEC-PRIVILEGED-LISTENER",p.assess(r,f))
    def test_missing_policy_denied(self):
        self.assertIn("SEC-NO-HUMAN-APPROVAL",p.assess({},{}))
    def test_missing_workflow_denied(self):
        r,f=sample();f.pop(p.WRITERS[0])
        self.assertIn("SEC-MISSING:"+p.WRITERS[0],p.assess(r,f))
