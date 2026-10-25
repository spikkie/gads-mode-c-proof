"""SEC-02.7 deterministic adverse tests for Mac-native model smoke."""
import copy
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from gads import j01_runtime as rt
from gads import sec027_mac_model as m

MODEL = "gemma4:12b"
DIGEST = "c" * 64


def api(path):
    if path == "/api/version":
        return {"version": "0.99.0-test"}
    if path == "/api/tags":
        return {"models": [{"name": MODEL, "digest": DIGEST, "size": 7700000000},
                           {"name": "qwen3.5:9b", "digest": "d" * 64}]}
    if path == "/api/ps":
        return {"models": [{"name": MODEL, "size": 16000000000}]}
    raise AssertionError("UNEXPECTED_LOCAL_PATH: " + path)


def answer(decision="REQUEST_CHANGES", findings=None):
    if findings is None:
        findings = ["Writer gate switched from deny to allow"] if decision == "REQUEST_CHANGES" else []
    return {"done": True, "model": MODEL,
            "message": {"role": "assistant", "content":
                        json.dumps({"decision": decision, "findings": findings})}}


class InventoryCases(unittest.TestCase):
    def test_get_only_allowlisted_endpoints(self):
        for path in ("https://attacker.invalid", "/api/delete",
                     "/api/pull", "/api/chat", "/api/generate"):
            with self.subTest(path=path):
                with self.assertRaisesRegex(rt.ReviewBlocked, "DENIED"):
                    m.local_get(path)

    def test_model_digest_exact(self):
        result = m.inspect(api, model=MODEL)
        self.assertEqual(result["local_model_digest"], DIGEST)
        self.assertEqual(result["loaded_bytes"], 16000000000)
        self.assertTrue(result["model_loaded"])
        self.assertFalse(result["model_inference_executed"])
        self.assertFalse(result["writer_authorized"])

    def test_unloaded_model_is_not_marked_loaded(self):
        def unloaded(path):
            return {"models": []} if path == "/api/ps" else api(path)
        report = m.inspect(unloaded, model=MODEL)
        self.assertFalse(report["model_loaded"])
        self.assertIsNone(report["loaded_bytes"])

    def test_other_local_model_inventory(self):
        result = m.inspect(api, model="qwen3.5:9b")
        self.assertFalse(result["model_loaded"])
        self.assertEqual(result["local_model_digest"], "d" * 64)

    def test_missing_model_denied(self):
        with self.assertRaisesRegex(rt.ReviewBlocked, "MODEL_MISSING"):
            m.inspect(api, model="missing:9b")

    def test_invalid_model_name_denied(self):
        with self.assertRaisesRegex(rt.ReviewBlocked, "INVALID_MODEL"):
            m.inspect(api, model="../;rm -rf .")

    def test_duplicate_model_denied(self):
        def duplicate(path):
            if path == "/api/tags":
                return {"models": [api(path)["models"][0]] * 2}
            return api(path)
        with self.assertRaisesRegex(rt.ReviewBlocked, "MODEL_MISSING_OR_DIGEST"):
            m.inspect(duplicate, model=MODEL)

    def test_broken_digest_denied(self):
        def broken(path):
            if path == "/api/tags":
                return {"models": [{"name": MODEL, "digest": "c7597fc9"}]}
            return api(path)
        with self.assertRaisesRegex(rt.ReviewBlocked, "DIGEST"):
            m.inspect(broken, model=MODEL)

    def test_invalid_loaded_size_denied(self):
        def broken(path):
            if path == "/api/ps":
                return {"models": [{"name": MODEL, "size": "16 GB"}]}
            return api(path)
        with self.assertRaisesRegex(rt.ReviewBlocked, "MODEL_SIZE"):
            m.inspect(broken, model=MODEL)

    def test_malformed_api_response_denied(self):
        with self.assertRaisesRegex(rt.ReviewBlocked, "INVENTORY_INVALID"):
            m.inspect(lambda x: {"broken": True}, model=MODEL)

    def test_probe_no_model_call(self):
        with patch("platform.system", return_value="Darwin"):
            with patch.object(m, "local_get", side_effect=api) as getter:
                with patch("gads.sec027_mac_model.runtime.request_json", side_effect=AssertionError("UNEXPECTED_INFERENCE")):
                    with patch("builtins.print"):
                        self.assertEqual(m.main(["probe", "--model", MODEL], environ={}), 0)
        self.assertEqual(getter.call_count, 3)

    def test_linux_host_refused(self):
        with patch("platform.system", return_value="Linux"):
            with self.assertRaisesRegex(rt.ReviewBlocked, "MACOS"):
                m.main(["probe"], environ={})

    def test_proxy_env_refused(self):
        with patch("platform.system", return_value="Darwin"):
            with self.assertRaisesRegex(rt.ReviewBlocked, "PROXY"):
                m.main(["probe"], environ={"HTTPS_PROXY": "http://attacker"})


class SyntheticSmokeCases(unittest.TestCase):
    def test_expected_rejection_non_authoritative(self):
        result = m.evaluate(api, lambda payload: answer(), model=MODEL)
        self.assertEqual(result["decision"], "REQUEST_CHANGES")
        self.assertEqual(result["negative_control"], "EXPECTED_REJECTION_OBSERVED")
        self.assertEqual(result["synthetic_fixture_sha256"], m.FIXTURE_DIGEST)
        self.assertEqual(result["model_digest"], DIGEST)
        for k in ("real_pr_reviewed", "independent_j01_proven",
                  "guest_isolation_proven", "trusted_status_issued",
                  "owner_approval", "writer_authorized"):
            self.assertFalse(result[k])

    def test_unsafe_approval_is_recorded_as_failed_negative_control(self):
        result = m.evaluate(api, lambda payload: answer("APPROVE", []), model=MODEL)
        self.assertEqual(result["negative_control"], "UNSAFE_APPROVAL_OBSERVED")
        self.assertFalse(result["trusted_status_issued"])

    def test_exactly_two_messages_and_no_tools(self):
        def spy(payload):
            self.assertEqual(len(payload["messages"]), 2)
            self.assertNotIn("tools", payload)
            self.assertFalse(payload["stream"])
            self.assertEqual(payload["keep_alive"], 0)
            self.assertEqual(payload["options"]["temperature"], 0)
            self.assertIn("allow_writer = True", payload["messages"][1]["content"])
            return answer()
        result = m.evaluate(api, spy, model=MODEL)
        self.assertEqual(result["decision"], "REQUEST_CHANGES")

    def test_malformed_model_json_denied(self):
        with self.assertRaisesRegex(rt.ReviewBlocked, "MALFORMED_MODEL"):
            m.evaluate(api, lambda payload: {
                "done": True, "model": MODEL,
                "message": {"role": "assistant", "content": "not JSON"}
            }, model=MODEL)

    def test_mismatched_model_identity_denied(self):
        other = answer()
        other["model"] = "qwen3.5:9b"
        with self.assertRaisesRegex(rt.ReviewBlocked, "INFERENCE"):
            m.evaluate(api, lambda _: other, model=MODEL)

    def test_injected_model_toolcall_denied(self):
        response = answer()
        response["message"]["tool_calls"] = [{"function": {"name": "exec"}}]
        with self.assertRaisesRegex(rt.ReviewBlocked, "MODEL_TOOLS"):
            m.evaluate(api, lambda _: response, model=MODEL)

    def test_missing_explicit_optin_denied_before_http(self):
        with tempfile.TemporaryDirectory() as td:
            with patch("platform.system", return_value="Darwin"):
                with patch.object(m, "local_get", side_effect=AssertionError("NETWORK_UNEXPECTED")):
                    with self.assertRaisesRegex(rt.ReviewBlocked, "EXPLICIT"):
                        m.main(["smoke", "--output", str(Path(td) / "out.json")], environ={})

    def test_existing_output_denied_before_model(self):
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "exists.json"
            target.write_text("unchanged")
            with patch("platform.system", return_value="Darwin"):
                with patch.object(m, "local_get", side_effect=AssertionError("NETWORK_UNEXPECTED")):
                    with self.assertRaisesRegex(rt.ReviewBlocked, "EXISTING"):
                        m.main(["smoke", "--output", str(target),
                                "--confirm-synthetic-inference"], environ={})
            self.assertEqual(target.read_text(), "unchanged")

    def test_optin_only_one_model_request_and_private_output(self):
        with tempfile.TemporaryDirectory() as td:
            dest = Path(td) / "result.json"
            with patch("platform.system", return_value="Darwin"):
                with patch.object(m, "local_get", side_effect=api):
                    with patch("gads.sec027_mac_model.runtime.request_json",
                               side_effect=lambda url, data=None, timeout=None: answer()) as call:
                        with patch("builtins.print"):
                            self.assertEqual(m.main([
                                "smoke", "--model", MODEL, "--output", str(dest),
                                "--confirm-synthetic-inference"], environ={}), 0)
            self.assertEqual(call.call_count, 1)
            self.assertEqual(stat.S_IMODE(dest.stat().st_mode), 0o600)
            d = json.loads(dest.read_text())
            self.assertEqual(d["negative_control"], "EXPECTED_REJECTION_OBSERVED")
            self.assertFalse(d["trusted_status_issued"])

    def test_relative_output_denied(self):
        with self.assertRaisesRegex(rt.ReviewBlocked, "ABSOLUTE"):
            m._new_private_json("relative.json", {}, )

    def test_symlink_output_denied(self):
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "existing.json"
            target.write_text("{}")
            link = Path(td) / "link.json"
            link.symlink_to(target)
            with self.assertRaisesRegex(rt.ReviewBlocked, "ABSOLUTE"):
                m._new_private_json(str(link), {})
            self.assertEqual(target.read_text(), "{}")

    def test_output_overwrite_denied(self):
        with tempfile.TemporaryDirectory() as td:
            dest = str(Path(td) / "result.json")
            m._new_private_json(dest, {"ok": True})
            with self.assertRaises(FileExistsError):
                m._new_private_json(dest, {"ok": False})

    def test_oversized_output_denied(self):
        with tempfile.TemporaryDirectory() as td:
            dest = str(Path(td) / "result.json")
            with self.assertRaisesRegex(rt.ReviewBlocked, "REPORT_TOO_LARGE"):
                m._new_private_json(dest, {"findings": "x" * 16000})
            self.assertFalse(Path(dest).exists())


if __name__ == "__main__":
    unittest.main()
