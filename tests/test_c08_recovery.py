"""C-08 fail-closed unknown-dispatch reconciliation / terminal replay."""
import unittest
from datetime import datetime, timezone
from scripts import c08_recovery as c
from scripts.c06_h00 import Blocked

BASE_INTENT={"source_run":c.EXPECTED_C07_RUN,"created_epoch":1792844497}


def candidate(when=1792844509, id=40093613654, sha=None, actor="github-actions[bot]",
              workflow_id=None, status="completed", conclusion="success"):
    return {"created_at":datetime.fromtimestamp(when,timezone.utc).isoformat(),
            "id":id,"workflow_id":workflow_id or c.TARGET_WORKFLOW_ID,
            "head_sha":sha or c.c07.TARGET_SHA,"head_branch":"main",
            "actor":{"login":actor},"event":"workflow_dispatch",
            "status":status,"conclusion":conclusion}


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.s=c.initial(BASE_INTENT,"a"*40)

    def test_good_actual_shape(self):
        self.assertEqual(c.matches(self.s,[candidate()]),"40093613654")

    def test_missing_is_undecidable_not_permission_to_dispatch(self):
        with self.assertRaisesRegex(Blocked,"NOT_FOUND_INCONCLUSIVE_NO_REDISPATCH"):
            c.matches(self.s,[])

    def test_ambiguous_is_denied(self):
        with self.assertRaisesRegex(Blocked,"AMBIGUOUS_MATCH"):
            c.matches(self.s,[candidate(),candidate(id=40093613655)])

    def test_wrong_actor_does_not_match(self):
        with self.assertRaisesRegex(Blocked,"NOT_FOUND_INCONCLUSIVE_NO_REDISPATCH"):
            c.matches(self.s,[candidate(actor="spikkie")])

    def test_old_run_does_not_match(self):
        with self.assertRaisesRegex(Blocked,"NOT_FOUND_INCONCLUSIVE_NO_REDISPATCH"):
            c.matches(self.s,[candidate(when=self.s["intent_epoch"]-1)])

    def test_late_run_does_not_match(self):
        with self.assertRaisesRegex(Blocked,"NOT_FOUND_INCONCLUSIVE_NO_REDISPATCH"):
            c.matches(self.s,[candidate(when=self.s["intent_epoch"]+c.WINDOW_SECONDS+1)])

    def test_wrong_target_sha_denied(self):
        with self.assertRaisesRegex(Blocked,"NOT_FOUND_INCONCLUSIVE_NO_REDISPATCH"):
            c.matches(self.s,[candidate(sha="b"*40)])

    def test_failed_target_is_not_success(self):
        with self.assertRaisesRegex(Blocked,"MATCH_NOT_SUCCESSFUL"):
            c.matches(self.s,[candidate(conclusion="failure")])

    def test_wrong_workflow_excluded(self):
        with self.assertRaisesRegex(Blocked,"NOT_FOUND_INCONCLUSIVE_NO_REDISPATCH"):
            c.matches(self.s,[candidate(workflow_id=987)])

    def test_reconcile_is_exactly_once(self):
        t=c.confirm(self.s,"40093613654")
        self.assertEqual(t["generation"],2)
        self.assertEqual(t["status"],"CONFIRMED_SUCCESS")
        self.assertEqual(t["history"],["injected-lost-ack-after-dispatch","reconciled:40093613654"])
        self.assertIsNone(c.confirm(t,"40093613654"))

    def test_status_corruption_rejected(self):
        t=c.confirm(self.s,"40093613654")
        t["checks"]=2
        with self.assertRaisesRegex(Blocked,"TERMINAL_INVARIANT"):
            c.validate(t)

    def test_unbound_source_rejected(self):
        with self.assertRaisesRegex(Blocked,"BAD_SEED_SHA"):
            c.initial(BASE_INTENT,"not-a-commit")
