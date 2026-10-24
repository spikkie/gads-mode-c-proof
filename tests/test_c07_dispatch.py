"""C-07 fixed-target dispatch and single-use intent negative tests."""
import unittest
from scripts import c07_dispatch as d
from scripts.c06_h00 import Blocked


class TestC07(unittest.TestCase):
    def setUp(self):
        self.state=d.make_intent("a"*40,"400001",123456)

    def test_identity_and_fixed_target(self):
        self.assertEqual(d.validate(self.state),self.state)
        self.assertEqual(self.state["target_sha"],d.TARGET_SHA)
        self.assertEqual(self.state["target_workflow"],"c05-proof.yml")

    def test_no_external_ref(self):
        with self.assertRaisesRegex(Blocked,"C07_SOURCE_SHA"):
            d.intent_ref("refs/heads/main")

    def test_bad_clock(self):
        with self.assertRaisesRegex(Blocked,"C07_RUN_ID_OR_CLOCK"):
            d.make_intent("a"*40,"400001",0)

    def test_invalid_run_id(self):
        with self.assertRaisesRegex(Blocked,"C07_RUN_ID_OR_CLOCK"):
            d.make_intent("a"*40,"user-supplied",10)

    def test_target_tamper(self):
        self.state["target_workflow"]="evil.yml"
        with self.assertRaisesRegex(Blocked,"C07_INTENT_TAMPER"):
            d.validate(self.state)

    def test_target_sha_tamper(self):
        self.state["target_sha"]="b"*40
        with self.assertRaisesRegex(Blocked,"C07_INTENT_TAMPER"):
            d.validate(self.state)

    def test_unknown_state_field(self):
        self.state["evil"]="x"
        with self.assertRaisesRegex(Blocked,"C07_SCHEMA"):
            d.validate(self.state)

    def test_json_roundtrip(self):
        self.assertEqual(d.validate(__import__("json").loads(d.core.encode_state(self.state))),
                         self.state)
