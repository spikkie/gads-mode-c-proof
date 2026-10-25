"""Negative probe snapshot checks."""
import copy
import unittest
from gads.github_gateway import Blocked, Policy
from gads.readonly_probe import TARGET_RUN, verify_snapshot

def valid():
    p=Policy()
    return (
        {"id":p.repository_id,"full_name":p.repository,"private":False,
         "default_branch":"main"},
        {"protected":True,"commit":{"sha":p.trusted_main_sha}},
        {"id":TARGET_RUN,"workflow_id":p.workflow_id,
         "head_sha":p.trusted_main_sha,"head_branch":"main",
         "event":"workflow_dispatch","status":"completed",
         "conclusion":"success","actor":{"login":"github-actions[bot]"},
         "repository":{"id":p.repository_id},
         "head_repository":{"id":p.repository_id}},
    )

class ProbeTests(unittest.TestCase):
    def test_expected_historical_payload(self):
        self.assertTrue(verify_snapshot(*valid()))

    def test_wrong_repo_rejected(self):
        x=list(valid());x[0]["id"]=0
        with self.assertRaisesRegex(Blocked,"PROBE_REPOSITORY"):
            verify_snapshot(*x)

    def test_unprotected_main_rejected(self):
        x=list(valid());x[1]["protected"]=False
        with self.assertRaisesRegex(Blocked,"PROBE_MAIN_DRIFT"):
            verify_snapshot(*x)

    def test_wrong_target_denied(self):
        x=list(valid());x[2]["id"]=TARGET_RUN+1
        with self.assertRaisesRegex(Blocked,"PROBE_HISTORICAL_RUN"):
            verify_snapshot(*x)

    def test_failed_run_denied(self):
        x=list(valid());x[2]["conclusion"]="failure"
        with self.assertRaisesRegex(Blocked,"PROBE_HISTORICAL_RUN"):
            verify_snapshot(*x)
