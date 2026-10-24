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

    def test_second_workflow_attempt_blocked_before_network(self):
        import os
        from unittest.mock import patch
        with patch.dict(os.environ, {"GITHUB_RUN_ATTEMPT":"2"}):
            with self.assertRaisesRegex(Blocked,"C07_DISPATCH_REPLAY_DENIED"):
                d.dispatch(object())

    def test_prepare_duplicate_intent_denied_without_mutation(self):
        import os
        from unittest.mock import patch
        with patch.dict(os.environ, {"GITHUB_RUN_ID":"400001"}):
            with patch.object(d,"preflight",return_value="a"*40):
                with patch.object(d,"read_intent",return_value=("b"*40,self.state)):
                    with patch.object(d.core,"build_commit",side_effect=AssertionError("unexpected mutation")):
                        with self.assertRaisesRegex(Blocked,"C07_EXISTING_INTENT_DENY_DUPLICATE"):
                            d.prepare(object())

    def test_protected_main_mandatory(self):
        import os
        from unittest.mock import patch
        class Fake:
            def call(self,method,path):
                assert method=="GET" and path=="/branches/main"
                return {"protected":False,"commit":{"sha":d.TARGET_SHA}}
        with patch.dict(os.environ, {"GITHUB_REPOSITORY":d.REPO,
                "GITHUB_REF":"refs/heads/"+d.SOURCE_BRANCH,
                "GITHUB_SHA":"a"*40}):
            with self.assertRaisesRegex(Blocked,"C07_MAIN_PROTECTION_OR_SOURCE_CHANGED"):
                d.preflight(Fake())

    def test_source_scope_ref_denied_before_network(self):
        import os
        from unittest.mock import patch
        with patch.dict(os.environ, {"GITHUB_REPOSITORY":d.REPO,
                "GITHUB_REF":"refs/heads/main","GITHUB_SHA":"a"*40}):
            with self.assertRaisesRegex(Blocked,"C07_WRONG_SOURCE_BRANCH"):
                d.preflight(object())
