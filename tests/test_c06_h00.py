"""No-network security and deterministic transition tests for synthetic C-06."""
import unittest
from scripts.c06_h00 import Blocked, seed_state, validate, recover_state, encode_state

SHA = "a" * 40


class TestC06(unittest.TestCase):
    def test_seed_expired_lease_is_canonical(self):
        state = seed_state("4000", SHA)
        self.assertEqual(validate(state), state)
        self.assertEqual(state["generation"], 1)
        self.assertEqual(state["lease_deadline"], 0)
        self.assertEqual(encode_state(state), encode_state(state))

    def test_recovery_exactly_once(self):
        start = seed_state("4000", SHA)
        done = recover_state(start, "4001", "alpha")
        self.assertEqual(done["generation"], 2)
        self.assertEqual(done["history"], ["injected-crash:4000", "recovered:4001:alpha"])
        self.assertIsNone(recover_state(done, "4002", "beta"))
        self.assertEqual(start["status"], "LEASED")

    def test_different_contenders_same_initial_generation(self):
        state = seed_state("4000", SHA)
        a = recover_state(state, "4001", "alpha")
        b = recover_state(state, "4001", "beta")
        self.assertNotEqual(encode_state(a), encode_state(b))
        self.assertEqual(a["generation"], b["generation"])
        self.assertEqual(a["status"], b["status"])

    def test_unknown_source_rejected(self):
        with self.assertRaisesRegex(Blocked, "SOURCE_SHA_INVALID"):
            seed_state("4000", "bad")

    def test_bad_worker_id_rejected(self):
        with self.assertRaisesRegex(Blocked, "RECOVERY_IDENTITY"):
            recover_state(seed_state("4000", SHA), "4001", "admin")

    def test_duplicate_or_mutated_history_rejected(self):
        s = recover_state(seed_state("4000", SHA), "4001", "alpha")
        s["history"].append("recovered:4001:alpha")
        with self.assertRaisesRegex(Blocked, "INVALID_COMPLETION"):
            validate(s)

    def test_corrupt_generation_rejected(self):
        s = seed_state("4000", SHA)
        s["generation"] = 3
        with self.assertRaisesRegex(Blocked, "INVALID_LEASE"):
            validate(s)

    def test_bad_schema_rejected(self):
        s = seed_state("4000", SHA)
        s["unauthorized"] = True
        with self.assertRaisesRegex(Blocked, "STATE_SCHEMA"):
            validate(s)


if __name__ == "__main__":
    unittest.main()
