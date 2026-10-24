"""Pure negative tests for privileged-event admission. No network / write tokens."""
import copy
import unittest
from scripts import c09_gate as g
from scripts.c06_h00 import Blocked


def real_shape():
    return {"id": g.FAILED_RUN_ID, "workflow_id": g.WORKFLOW_ID,
            "name": g.WORKFLOW_NAME, "event": "push", "head_branch": g.SOURCE_REF,
            "head_sha": g.SOURCE_SHA, "status": "completed",
            "conclusion": "failure", "run_attempt": 1,
            "actor": {"login": g.EXPECTED_ACTOR},
            "repository": {"id": g.REPO_ID, "full_name": g.REPO},
            "head_repository": {"id": g.REPO_ID, "full_name": g.REPO}}


class GateTests(unittest.TestCase):
    def setUp(self):
        self.actual = real_shape()
        self.event = {"action": "completed", "workflow_run": copy.deepcopy(self.actual)}

    def test_historical_failure_admitted(self):
        self.assertEqual(g.verify_event(self.event, self.actual), g.FAILED_RUN_ID)

    def reject(self, field, value, code):
        actual = copy.deepcopy(self.actual)
        actual[field] = value
        with self.assertRaisesRegex(Blocked, "C09_" + code):
            g.verify_event({"action": "completed", "workflow_run": actual}, actual)

    def test_other_run_rejected(self):
        self.reject("id", 40095804831, "RUN_ID")

    def test_other_workflow_rejected(self):
        self.reject("workflow_id", 123, "WORKFLOW_ID")

    def test_other_branch_rejected(self):
        self.reject("head_branch", "main", "SOURCE_BRANCH")

    def test_source_sha_rejected(self):
        self.reject("head_sha", "f"*40, "SOURCE_SHA")

    def test_success_not_a_crash(self):
        self.reject("conclusion", "success", "NOT_FAILURE")

    def test_queued_run_denied(self):
        self.reject("status", "queued", "NOT_COMPLETE")

    def test_rerun_denied(self):
        self.reject("run_attempt", 2, "RERUN_DENIED")

    def test_actor_spoof_denied(self):
        self.reject("actor", {"login": "mallory"}, "ACTOR")

    def test_fork_denied(self):
        self.reject("head_repository", {"id": 42, "full_name": "attacker/fork"},
                    "HEAD_REPOSITORY")

    def test_wrong_repository_denied(self):
        self.reject("repository", {"id": 42, "full_name": g.REPO}, "REPOSITORY")

    def test_unexpected_event_action(self):
        self.event["action"] = "requested"
        with self.assertRaisesRegex(Blocked, "EVENT_ACTION"):
            g.verify_event(self.event, self.actual)

    def test_event_run_mismatch(self):
        self.event["workflow_run"]["run_attempt"] = 2
        with self.assertRaisesRegex(Blocked, "RERUN_DENIED"):
            g.verify_event(self.event, self.actual)

    def test_incorrect_source_event(self):
        self.reject("event", "pull_request", "SOURCE_EVENT")

    def test_empty_payload(self):
        with self.assertRaisesRegex(Blocked, "EVENT_ACTION"):
            g.verify_event({}, self.actual)

    def test_github_api_metadata_is_mandatory(self):
        actual = copy.deepcopy(self.actual)
        actual.pop("repository")
        with self.assertRaisesRegex(Blocked, "REPOSITORY"):
            g.verify_event(self.event, actual)


if __name__ == "__main__":
    unittest.main()
