"""Pure state-machine behavior and negative-path tests."""
import copy
import unittest
from gads import h00 as h

class TestH00(unittest.TestCase):
    def setUp(self):
        self.s=h.new("synthetic-p1","a"*40,1432047514,395007460,1,2)
        self.claim={"id":"evt-claim","kind":"claim","owner":"worker-1"}
    def leased(self): return h.transition(self.s,self.claim,100)
    def target(self,s):
        return {"id":40093613654,"repo_id":s["repo_id"],
                "workflow_id":s["workflow_id"],"source_sha":s["source_sha"],
                "correlation":s["correlation"],"event":"workflow_dispatch",
                "actor":"github-actions[bot]","status":"completed","conclusion":"success"}
    def test_reserves_before_external_effect(self):
        s=self.leased()
        self.assertEqual((s["stage"],s["attempts"],s["units_reserved"]),("LEASED",1,1))
        self.assertEqual((s["fence"],s["deadline"]),("f1",130))
    def test_idempotent_replay(self):
        s=self.leased();self.assertEqual(s,h.transition(s,self.claim,101))
    def test_duplicate_event_payload_conflict(self):
        s=self.leased()
        with self.assertRaisesRegex(h.Blocked,"REPLAY_COLLISION"):
            h.transition(s,{"id":"evt-claim","kind":"claim","owner":"attacker"},101)
    def test_stale_fence_blocks(self):
        s=self.leased()
        with self.assertRaisesRegex(h.Blocked,"FENCE_DENIED"):
            h.transition(s,{"id":"u","kind":"unknown","owner":"worker-1","fence":"f0"},102)
    def test_stale_owner_blocks(self):
        s=self.leased()
        with self.assertRaisesRegex(h.Blocked,"FENCE_DENIED"):
            h.transition(s,{"id":"u","kind":"unknown","owner":"attacker","fence":"f1"},102)
    def test_early_expiration_denied(self):
        s=self.leased()
        with self.assertRaisesRegex(h.Blocked,"LEASE_ACTIVE"):
            h.transition(s,{"id":"expire","kind":"expire"},129)
    def test_expiration_does_not_auto_retry(self):
        s=self.leased();s=h.transition(s,{"id":"expire","kind":"expire"},130)
        self.assertEqual(s["stage"],"UNKNOWN")
        with self.assertRaisesRegex(h.Blocked,"CLAIM_DENIED"):
            h.transition(s,{"id":"retry","kind":"claim","owner":"other"},131)
    def test_uncertain_owner_must_match(self):
        s=self.leased();u=h.transition(s,{"id":"u","kind":"unknown",
                         "owner":"worker-1","fence":"f1"},120)
        self.assertEqual((u["stage"],u["units_reserved"]),("UNKNOWN",1))
    def test_reconcile_attestation(self):
        s=self.leased();u=h.transition(s,{"id":"u","kind":"expire"},130)
        c=h.transition(u,{"id":"c","kind":"confirm","target":self.target(s)},131)
        self.assertEqual((c["stage"],c["target_run"],c["revision"]),
                         ("COMPLETED",40093613654,3))
        self.assertEqual(c,h.transition(c,{"id":"c","kind":"confirm","target":self.target(s)},200))
    def test_cross_source_attestation_denied(self):
        s=self.leased();v=self.target(s);v["source_sha"]="b"*40
        with self.assertRaisesRegex(h.Blocked,"ATTESTATION_MISMATCH"):
            h.transition(s,{"id":"c","kind":"confirm","target":v},101)
    def test_wrong_correlation_denied(self):
        s=self.leased();v=self.target(s);v["correlation"]="0"*64
        with self.assertRaisesRegex(h.Blocked,"ATTESTATION_MISMATCH"):
            h.transition(s,{"id":"c","kind":"confirm","target":v},101)
    def test_wrong_actor_denied(self):
        s=self.leased();v=self.target(s);v["actor"]="attacker"
        with self.assertRaisesRegex(h.Blocked,"ATTESTATION_MISMATCH"):
            h.transition(s,{"id":"c","kind":"confirm","target":v},101)
    def test_failed_external_run_denied(self):
        s=self.leased();v=self.target(s);v["conclusion"]="failure"
        with self.assertRaisesRegex(h.Blocked,"ATTESTATION_MISMATCH"):
            h.transition(s,{"id":"c","kind":"confirm","target":v},101)
    def test_terminal_no_new_effect(self):
        s=h.transition(self.s,{"id":"stop","kind":"block"},100)
        with self.assertRaisesRegex(h.Blocked,"TERMINAL"):
            h.transition(s,self.claim,101)
    def test_state_history_tampering_denied(self):
        s=self.leased();s["history"][0]["revision"]=2
        with self.assertRaisesRegex(h.Blocked,"HISTORY_ORDER"):h.validate(s)
    def test_budget_tampering_denied(self):
        s=self.leased();s["units_reserved"]=3
        with self.assertRaisesRegex(h.Blocked,"STATE_BUDGET"):h.validate(s)
    def test_boolean_is_not_integer(self):
        with self.assertRaises(h.Blocked):h.new("x","a"*40,True,1)
        with self.assertRaises(h.Blocked):h.transition(self.s,self.claim,True)
    def test_pure_original_unchanged(self):
        old=copy.deepcopy(self.s);ev=copy.deepcopy(self.claim);self.leased()
        self.assertEqual((self.s,self.claim),(old,ev))
    def test_claim_again_denied(self):
        s=self.leased()
        with self.assertRaisesRegex(h.Blocked,"CLAIM_DENIED"):
            h.transition(s,{"id":"next","kind":"claim","owner":"other"},101)
