"""SEC-02.8 E1 deterministic security eval suite, oracle and adversarial tests."""
import copy
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from gads import j01_runtime as rt
from gads import sec028_benchmark as bench

MODEL = "gemma4:12b"
FINDINGS = ("writer privilege enabled; audit log removed; required check bypass; "
            "force push; network wildcard URL; integrity error fail open; "
            "issuer signature unverified; nonce replay")


def local_get(path):
    if path == "/api/version":
        return {"version": "0.40.11"}
    if path == "/api/tags":
        return {"models": [{"name": m, "digest": d} for m, d
                           in bench.MODEL_DIGESTS.items()]}
    if path == "/api/ps":
        return {"models": []}
    raise AssertionError("UNEXPECTED_LOCAL_REQUEST")


def transport(expected_map, *, override=None):
    def call(payload):
        if len(payload["messages"]) != 2 or "tools" in payload:
            raise AssertionError("BROKEN_NO_TOOLS_ISOLATED_MESSAGES")
        body = payload["messages"][1]["content"]
        for leaked in ("oracle_reason", "expected_decision", "required_regex",
                       "forbidden_regex", "family", "case_id"):
            if leaked in body:
                raise AssertionError("LABEL_LEAK_TO_MODEL: " + leaked)
        for case_id, d in expected_map.items():
            if rt.canonical(bench.input_for_model(d["case"])).decode("ascii") in body:
                decision = override.get(case_id, d["case"]["expected_decision"]) if override else d["case"]["expected_decision"]
                findings = [FINDINGS] if decision == "REQUEST_CHANGES" else []
                return {"model": payload["model"], "done": True,
                        "message": {"role": "assistant", "content": json.dumps({
                            "decision": decision, "findings": findings})}}
        raise AssertionError("NO_MATCH_FOR_BLIND_MODEL_INPUT")
    return call


def mapping(oracle):
    return {case["id"]: {"case": case} for case in oracle["cases"]}


def report(batch=1, model=MODEL, overrides=None, repeats=1):
    oracle = bench.load_oracle()
    return bench.run_batch(
        oracle, model=model, batch=batch, repeats=repeats, get=local_get,
        call=transport(mapping(oracle), override=overrides))


class OracleCases(unittest.TestCase):
    def test_exactly_twenty_ten_ten(self):
        data = bench.load_oracle()
        self.assertEqual(len(data["cases"]), 20)
        self.assertEqual(sum(x["expected_decision"] == "APPROVE"
                             for x in data["cases"]), 10)
        self.assertEqual(sum(x["expected_decision"] == "REQUEST_CHANGES"
                             for x in data["cases"]), 10)

    def test_oracle_family_allocation(self):
        data = bench.load_oracle()
        self.assertEqual({f: sum(c["family"] == f for c in data["cases"])
                          for f in ("safe", "unsafe", "adversarial")},
                         {"safe": 8, "unsafe": 8, "adversarial": 4})

    def test_dataset_deterministic(self):
        data = bench.load_oracle()
        self.assertEqual(bench._sha(data), bench._sha(bench.load_oracle()))

    def test_oracle_separated_from_model_input(self):
        data = bench.load_oracle()
        for case in data["cases"]:
            prompt = json.dumps(bench.input_for_model(case), sort_keys=True)
            for field in ("expected_decision", "oracle_reason", "required_regex",
                          "forbidden_regex", "family", "case_id"):
                self.assertNotIn(field, prompt)
            self.assertIn("@@ -1 +1 @@", prompt)

    def test_full_suite_20_distinct_case_ids(self):
        self.assertEqual(len(set(bench.CASE_ORDER)), 20)
        for batch in range(1, 5):
            self.assertEqual(len(bench.CASE_ORDER[(batch-1)*5:batch*5]), 5)

    def test_directionality_contradiction_rule_detected(self):
        oracle = bench.load_oracle()
        case = next(x for x in oracle["cases"] if x["id"] == "U01")
        grade = bench.grade(case, decision="REQUEST_CHANGES",
                            findings=["Change disables writer gate without authorization"])
        self.assertTrue(grade["decision_correct"])
        self.assertTrue(grade["contradiction_signals"])
        self.assertFalse(grade["rule_based_case_pass"])

    def test_factual_signal_absent_separate_from_decision(self):
        oracle = bench.load_oracle()
        case = next(x for x in oracle["cases"] if x["id"] == "U01")
        grade = bench.grade(case, decision="REQUEST_CHANGES",
                            findings=["unclear"])
        self.assertTrue(grade["decision_correct"])
        self.assertFalse(grade["required_fact_signals_met"])
        self.assertFalse(grade["rule_based_case_pass"])

    def test_safe_approval_has_no_findings(self):
        case = bench.load_oracle()["cases"][0]
        grade = bench.grade(case, decision="APPROVE", findings=[])
        self.assertTrue(grade["rule_based_case_pass"])
        self.assertFalse(grade["semantic_correctness_independently_adjudicated"])

    def test_missing_fields_in_oracle_denied(self):
        oracle = bench.load_oracle()
        del oracle["cases"][0]["oracle_reason"]
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "oracle.json"
            path.write_text(json.dumps(oracle))
            with self.assertRaisesRegex(rt.ReviewBlocked, "CASE_SCHEMA"):
                bench.load_oracle(path)

    def test_wrong_case_count_denied(self):
        oracle = bench.load_oracle()
        oracle["cases"].pop()
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "oracle.json"
            path.write_text(json.dumps(oracle))
            with self.assertRaisesRegex(rt.ReviewBlocked, "CASE_SET"):
                bench.load_oracle(path)

    def test_duplicate_json_keys_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "bad.json"
            path.write_text('{"schema":"a","schema":"b"}')
            with self.assertRaisesRegex(rt.ReviewBlocked, "JSON_KEY"):
                bench._read_strict(str(path))

    def test_relative_path_denied(self):
        with self.assertRaisesRegex(rt.ReviewBlocked, "ABSOLUTE"):
            bench._read_strict("oracle.json")


class ModelBatch(unittest.TestCase):
    def test_first_batch_five_models_no_status(self):
        s = report()
        self.assertEqual(s["batch"], 1)
        self.assertEqual(len(s["samples"]), 5)
        self.assertEqual(s["classification"], "UNTRUSTED_DEVELOPMENT_BENCHMARK")
        self.assertFalse(s["trusted_status_issued"])
        self.assertFalse(s["writer_authorized"])

    def test_repeats_three_emit_all_samples(self):
        s = report(repeats=3)
        self.assertEqual(len(s["samples"]), 15)
        self.assertEqual({x["repeat"] for x in s["samples"]}, {1, 2, 3})

    def test_wrong_digest_fails_before_inference(self):
        invoked = []
        def tamper(path):
            if path == "/api/tags":
                return {"models": [{"name": MODEL, "digest": "0"*64}]}
            return local_get(path)
        with self.assertRaisesRegex(rt.ReviewBlocked, "DIGEST_DRIFT"):
            bench.run_batch(bench.load_oracle(), model=MODEL, batch=1,
                            repeats=1, get=tamper,
                            call=lambda p: invoked.append(p))
        self.assertEqual(invoked, [])

    def test_wrong_model_denied(self):
        with self.assertRaisesRegex(rt.ReviewBlocked, "UNPINNED"):
            bench.run_batch(bench.load_oracle(), model="unknown",
                            batch=1, repeats=1, get=local_get,
                            call=lambda _: {})

    def test_bad_batch_boolean_denied(self):
        with self.assertRaisesRegex(rt.ReviewBlocked, "BATCH_OR_REPEATS"):
            bench.run_batch(bench.load_oracle(), model=MODEL, batch=True,
                            repeats=1, get=local_get, call=lambda _: {})

    def test_bad_repeats_denied(self):
        with self.assertRaisesRegex(rt.ReviewBlocked, "BATCH_OR_REPEATS"):
            bench.run_batch(bench.load_oracle(), model=MODEL, batch=1,
                            repeats=4, get=local_get, call=lambda _: {})

    def test_model_bad_json_records_error_no_forged_approval(self):
        suite = bench.load_oracle()
        s = bench.run_batch(suite, model=MODEL, batch=1, repeats=1,
                            get=local_get, call=lambda _: {})
        self.assertTrue(all(row["decision"] == "ERROR" for row in s["samples"]))
        summary = bench.aggregate(suite, [s])
        self.assertEqual(summary["models"][0]["errors"], 5)
        self.assertEqual(summary["models"][0]["heuristic_case_pass"], 0)

    def test_wrong_decisions_become_fp_and_fn(self):
        s = report(overrides={"S01": "REQUEST_CHANGES", "U01": "APPROVE"})
        scores = bench.aggregate(bench.load_oracle(), [s])["models"][0]
        self.assertEqual(scores["false_positives"], 1)
        self.assertEqual(scores["false_negatives"], 1)
        self.assertFalse(scores["complete_20_case_coverage"])

    def test_three_model_partial_comparison_not_fully_qualified(self):
        suite = bench.load_oracle()
        rs = [report(model=m) for m in bench.MODEL_DIGESTS]
        summary = bench.aggregate(suite, rs)
        self.assertEqual(len(summary["models"]), 3)
        self.assertFalse(summary["all_three_models_complete"])
        self.assertFalse(summary["model_selection_authorized"])

    def test_all_twenty_each_model_coverage(self):
        suite = bench.load_oracle()
        rs = [report(batch=b, model=m)
              for m in bench.MODEL_DIGESTS for b in range(1, 5)]
        summary = bench.aggregate(suite, rs)
        self.assertTrue(summary["all_three_models_complete"])
        self.assertTrue(all(x["samples"] == 20 for x in summary["models"]))
        self.assertFalse(summary["semantic_ground_truth_proven"])
        self.assertFalse(summary["writer_authorized"])

    def test_duplicate_report_replay_denied(self):
        r = report()
        with self.assertRaisesRegex(rt.ReviewBlocked, "DUPLICATED_CASE"):
            bench.aggregate(bench.load_oracle(), [r, copy.deepcopy(r)])

    def test_missing_one_sample_denied(self):
        r = report()
        r["samples"].pop()
        with self.assertRaisesRegex(rt.ReviewBlocked, "REPORT_COVERAGE"):
            bench.aggregate(bench.load_oracle(), [r])

    def test_model_claimed_issuer_denied(self):
        r = report()
        r["trusted_status_issued"] = True
        with self.assertRaisesRegex(rt.ReviewBlocked, "REPORT_IDENTITY_OR_TRUST"):
            bench.aggregate(bench.load_oracle(), [r])

    def test_model_digest_spoofing_denied(self):
        r = report()
        r["local_model_digest"] = "0"*64
        with self.assertRaisesRegex(rt.ReviewBlocked, "REPORT_IDENTITY_OR_TRUST"):
            bench.aggregate(bench.load_oracle(), [r])

    def test_dataset_sha_change_denied(self):
        r = report()
        r["dataset_sha256"] = "0"*64
        with self.assertRaisesRegex(rt.ReviewBlocked, "REPORT_IDENTITY_OR_TRUST"):
            bench.aggregate(bench.load_oracle(), [r])

    def test_cross_batch_forged_case_denied(self):
        r = report()
        r["samples"][0]["case_id"] = "S08"
        with self.assertRaisesRegex(rt.ReviewBlocked, "SAMPLE_VALUE"):
            bench.aggregate(bench.load_oracle(), [r])

    def test_missing_error_content_denied(self):
        r = report()
        r["samples"][0]["error"] = "a forged error"
        with self.assertRaisesRegex(rt.ReviewBlocked, "SAMPLE_VALUE"):
            bench.aggregate(bench.load_oracle(), [r])

    def test_exact_score_recomputes_from_raw_results(self):
        r = report()
        r["samples"][1]["findings"] = ["Change disables writer gate without authorization"]
        scoreboard = bench.aggregate(bench.load_oracle(), [r])
        self.assertGreater(scoreboard["models"][0]["contradiction_signals"], 0)


class LocalFileAndConsent(unittest.TestCase):
    def test_plan_has_no_model_or_network(self):
        with patch("gads.sec028_benchmark.mac.local_get",
                   side_effect=AssertionError("NO_NETWORK")):
            with patch("builtins.print"):
                self.assertEqual(bench.main(["plan"]), 0)

    def test_no_explicit_consent(self):
        with patch("platform.system", return_value="Darwin"):
            with self.assertRaisesRegex(rt.ReviewBlocked, "EXPLICIT_CONSENT"):
                bench.main(["run", "--model", MODEL, "--batch", "1",
                            "--output", "/tmp/gads-sec028-unit.json"],
                           environ={})

    def test_linux_runner_forbidden(self):
        with patch("platform.system", return_value="Linux"):
            with self.assertRaisesRegex(rt.ReviewBlocked, "MACOS"):
                bench.main(["run", "--model", MODEL, "--batch", "1",
                            "--output", "/tmp/gads-sec028-unit.json",
                            "--confirm-synthetic-inference"], environ={})

    def test_secret_env_denied(self):
        with patch("platform.system", return_value="Darwin"):
            with self.assertRaisesRegex(rt.ReviewBlocked, "CREDENTIALS_PRESENT"):
                bench.main(["run", "--model", MODEL, "--batch", "1",
                            "--output", "/tmp/gads-sec028-unit.json",
                            "--confirm-synthetic-inference"],
                           environ={"GH_TOKEN": "private"})

    def test_private_0600_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as td:
            path = str(Path(td) / "result.json")
            bench._new_json(path, {"status": "untrusted"})
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                bench._new_json(path, {"status": "replace"})
            self.assertEqual(bench._read_strict(path)["status"], "untrusted")

    def test_symlink_output_denied(self):
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "secret.json"
            target.write_text("original")
            link = Path(td) / "link.json"
            link.symlink_to(target)
            with self.assertRaisesRegex(rt.ReviewBlocked, "ABSOLUTE_JSON"):
                bench._new_json(str(link), {})
            self.assertEqual(target.read_text(), "original")

    def test_relative_output_denied(self):
        with self.assertRaisesRegex(rt.ReviewBlocked, "ABSOLUTE_JSON"):
            bench._new_json("result.json", {})

    def test_all_these_run_fakes_do_not_claim_trust(self):
        report_data = report()
        self.assertFalse(report_data["independent_review_proven"])
        self.assertFalse(report_data["writer_authorized"])


if __name__ == "__main__":
    unittest.main()
