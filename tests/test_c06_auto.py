"""Bounded deterministic H-00 transition and fail-closed budget tests."""
import unittest
from scripts import c06_auto as m
from scripts.c06_h00 import Blocked

class AutoTests(unittest.TestCase):
    def setUp(self):
        self.seed=m.initial("123456","a"*40)
    def test_seed(self):
        self.assertEqual(m.validate(self.seed)["stage"],"READY")
    def test_full_chain(self):
        s=m.step(self.seed,"crash",100)
        s=m.step(s,"recover",101)
        s=m.step(s,"next",102)
        s=m.step(s,"deny",103)
        self.assertEqual((s["generation"],s["units_used"],s["p1_attempts"]),(4,2,2))
        self.assertEqual((s["p1"],s["p2"],s["p3"]),("DONE","DONE","BLOCKED_BUDGET"))
        self.assertIsNone(m.step(s,"next",104))
    def test_active_lease_denied(self):
        s=m.step(self.seed,"crash",100)
        s["deadline"]=200
        with self.assertRaisesRegex(Blocked,"AUTO_LEASE_ACTIVE"):
            m.step(s,"recover",150)
    def test_illegal_next_order(self):
        with self.assertRaisesRegex(Blocked,"AUTO_ILLEGAL_STEP"):
            m.step(self.seed,"next",100)
    def test_budget_overrun_denied(self):
        s=m.step(self.seed,"crash",100)
        s["units_used"]=3
        with self.assertRaisesRegex(Blocked,"AUTO_BUDGET_EXCEEDED"):
            m.validate(s)
    def test_budget_config_tamper_denied(self):
        self.seed["units_limit"]=100
        with self.assertRaisesRegex(Blocked,"AUTO_BUDGET_CONFIG"):
            m.validate(self.seed)
    def test_attempt_limit_tamper_denied(self):
        s=m.step(self.seed,"crash",100)
        s["p1_attempt_limit"]=999
        with self.assertRaisesRegex(Blocked,"AUTO_BUDGET_CONFIG"):
            m.validate(s)
    def test_history_tamper_denied(self):
        s=m.step(self.seed,"crash",100)
        s["history"].append("p2-completed")
        with self.assertRaisesRegex(Blocked,"AUTO_BAD_TRANSITION"):
            m.validate(s)
    def test_wrong_workpackage_order_denied(self):
        s=m.step(self.seed,"crash",100)
        with self.assertRaisesRegex(Blocked,"AUTO_ILLEGAL_STEP"):
            m.step(s,"next",200)
    def test_bad_run_id(self):
        with self.assertRaisesRegex(Blocked,"AUTO_RUN_ID"):
            m.state_ref("123;rm")
    def test_bad_source(self):
        with self.assertRaisesRegex(Blocked,"AUTO_SOURCE_SHA"):
            m.initial("123456","invalid")
    def test_terminal_replay_immutable(self):
        s=m.step(self.seed,"crash",100)
        s=m.step(s,"recover",101)
        s=m.step(s,"next",102)
        s=m.step(s,"deny",103)
        data=m.core.encode_state(s)
        self.assertIsNone(m.step(s,"crash",200))
        self.assertEqual(m.core.encode_state(s),data)
