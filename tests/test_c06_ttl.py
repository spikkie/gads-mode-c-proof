"""TTL and bounded retry tests for C-06 synthetic H-00."""
import unittest
from scripts.c06_h00 import Blocked
from scripts.c06_ttl import new_state, transition, valid, TTL

class TestLiveTtl(unittest.TestCase):
    def setUp(self):
        self.seed = new_state("100", "a"*40, 1000)

    def test_ttl_is_future(self):
        self.assertEqual(self.seed["deadline"], 1000+TTL)

    def test_premature_rejected(self):
        with self.assertRaisesRegex(Blocked, "TTL_LEASE_ACTIVE"):
            transition(self.seed, 1000+TTL-1, "101:alpha")

    def test_after_ttl_and_attempt_budget(self):
        n=transition(self.seed, 1000+TTL, "101:alpha")
        self.assertEqual((n["status"],n["generation"],n["attempts"]),("COMPLETED",2,1))
        self.assertIsNone(transition(n,1000+TTL+10,"102:beta"))

    def test_corrupt_budget_rejected(self):
        self.seed["max_attempts"]=10
        with self.assertRaisesRegex(Blocked,"TTL_BUDGET_OR_DEADLINE"):
            valid(self.seed)

    def test_corrupt_history_rejected(self):
        n=transition(self.seed,1000+TTL,"101:alpha")
        n["history"].append("recovered:102:beta")
        with self.assertRaisesRegex(Blocked,"TTL_BAD_COMPLETION"):
            valid(n)

    def test_invalid_actor_rejected(self):
        with self.assertRaisesRegex(Blocked,"TTL_ACTOR"):
            transition(self.seed,1000+TTL,"untrusted")

    def test_wrong_generation_rejected(self):
        self.seed["generation"]=3
        with self.assertRaisesRegex(Blocked,"TTL_BAD_LEASE"):
            valid(self.seed)

    def test_bad_source_sha_rejected(self):
        with self.assertRaisesRegex(Blocked,"TTL_IDENTITY"):
            new_state("100","wrong",1000)
