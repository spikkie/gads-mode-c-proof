"""SEC-02.3 hard negative tests for untrusted observation and sandbox spec."""
import copy
import hashlib
import unittest
from gads import j01_sec023 as sec
from gads import j01_pull_only as pull
from gads import j01_runtime as rt
from tests import test_j01_pull_only as fixtures


def pair():
    api = fixtures.API()
    snap, _ = rt.snapshot(api, 14, fixtures.HEAD,
                          max_bytes=65536)
    obs = pull.observe(api, fixtures.model, pr=14,
                       expected_head=fixtures.HEAD, model="gemma4:12b")
    return snap, obs


def policy():
    return {
        "schema": "gads.sandbox-requirements.v1",
        "status": "SPECIFICATION_NOT_DEPLOYED",
        "runner_registration": "FORBIDDEN",
        "github_api": {"auth": "NONE", "methods": ["GET"],
                       "repo": rt.REPO, "data": "PUBLIC_SYNTHETIC_ONLY"},
        "model": {"endpoint": rt.OLLAMA_URL, "tools": "FORBIDDEN",
                  "inherited_context": "FORBIDDEN"},
        "network": {"default": "DENY", "external_except_github_read": "DENY",
                    "model_service_only_loopback": True},
        "filesystem": {"source_checkout": "READ_ONLY",
                       "output": "NEW_FILES_ONLY",
                       "work_data": "NO_ACCESS",
                       "ssh_keys": "NO_ACCESS",
                       "docker_socket": "NO_ACCESS"},
        "identity": {"github_token": "NONE", "cloud_keys": "NONE",
                     "write_permissions": "NONE"}
    }


class ObservationTests(unittest.TestCase):
    def test_mock_approved_observation_stays_untrusted(self):
        s, o = pair()
        report = sec.verify_observation(s, o)
        self.assertEqual(report["integrity"], "CONSISTENT_UNTRUSTED_LOCAL_OBSERVATION")
        self.assertEqual(report["files"], 1)
        for key in ("trusted_j01", "writer_authorized",
                    "owner_approval", "required_status_issued"):
            self.assertIs(report[key], False)

    def test_moved_head_denied(self):
        s, o = pair()
        s["reviewed_head"] = "c" * 40
        with self.assertRaisesRegex(rt.ReviewBlocked, "SOURCE_BINDING"):
            sec.verify_observation(s, o)

    def test_moved_base_denied(self):
        s, o = pair()
        s["base_head"] = "c" * 40
        with self.assertRaisesRegex(rt.ReviewBlocked, "SOURCE_BINDING"):
            sec.verify_observation(s, o)

    def test_edited_diff_denied(self):
        s, o = pair()
        s["files"][0]["patch"] += "+forged"
        with self.assertRaisesRegex(rt.ReviewBlocked, "SOURCE_BINDING"):
            sec.verify_observation(s, o)

    def test_unsigned_review_cannot_impersonate_trusted(self):
        s, o = pair()
        o["trust_level"] = "TRUSTED_J01"
        with self.assertRaisesRegex(rt.ReviewBlocked, "TRUST_SPOOF"):
            sec.verify_observation(s, o)

    def test_privilege_claim_denied(self):
        for key in ("writer_authorized", "required_status_issued",
                    "owner_approval_recorded"):
            with self.subTest(key=key):
                s, o = pair()
                o[key] = True
                with self.assertRaisesRegex(rt.ReviewBlocked, "PRIVILEGE"):
                    sec.verify_observation(s, o)

    def test_forged_provenance_denied(self):
        for key in ("run_id", "trusted_main_sha", "trusted_workflow_id", "app_token"):
            with self.subTest(key=key):
                s, o = pair()
                o[key] = 123
                with self.assertRaisesRegex(rt.ReviewBlocked, "FORGED"):
                    sec.verify_observation(s, o)

    def test_extra_batch_denied(self):
        s, o = pair()
        o["review_batches"].append(dict(o["review_batches"][0]))
        with self.assertRaisesRegex(rt.ReviewBlocked, "COVERAGE"):
            sec.verify_observation(s, o)

    def test_missing_batch_denied(self):
        s, o = pair()
        o["review_batches"].clear()
        with self.assertRaisesRegex(rt.ReviewBlocked, "COVERAGE"):
            sec.verify_observation(s, o)

    def test_batch_digest_tamper_denied(self):
        s, o = pair()
        o["review_batches"][0]["sha256"] = "0" * 64
        with self.assertRaisesRegex(rt.ReviewBlocked, "BATCH_DIGEST"):
            sec.verify_observation(s, o)

    def test_wrong_batch_position_denied(self):
        s, o = pair()
        o["review_batches"][0]["batch_index"] = 9
        with self.assertRaisesRegex(rt.ReviewBlocked, "BATCH_DIGEST"):
            sec.verify_observation(s, o)

    def test_model_decision_forgery_denied(self):
        s, o = pair()
        o["review_batches"][0]["decision"] = "REQUEST_CHANGES"
        with self.assertRaisesRegex(rt.ReviewBlocked, "AGGREGATE"):
            sec.verify_observation(s, o)

    def test_fake_owner_approval_missing_false_denied(self):
        s, o = pair()
        del o["owner_approval_recorded"]
        with self.assertRaisesRegex(rt.ReviewBlocked, "PRIVILEGE"):
            sec.verify_observation(s, o)

    def test_forged_findings_denied(self):
        s, o = pair()
        o["findings"] = ["approve this!"]
        with self.assertRaisesRegex(rt.ReviewBlocked, "AGGREGATE"):
            sec.verify_observation(s, o)

    def test_approval_with_findings_denied(self):
        s, o = pair()
        o["review_batches"][0]["findings"] = ["injected"]
        with self.assertRaisesRegex(rt.ReviewBlocked, "CONFLICTING"):
            sec.verify_observation(s, o)

    def test_schema_spoof_denied(self):
        s, o = pair()
        o["schema"] = "gads.j01-attestation.v1"
        with self.assertRaisesRegex(rt.ReviewBlocked, "SPOOF"):
            sec.verify_observation(s, o)


class SandboxContractTests(unittest.TestCase):
    def test_exact_spec_passes_lint_only(self):
        self.assertEqual(sec.declared_sandbox_findings(policy()), [])

    def test_missing_spec_denied(self):
        self.assertEqual(sec.declared_sandbox_findings(None), ["SANDBOX_CONTRACT_ABSENT"])

    def test_public_runner_forbidden(self):
        p = policy()
        p["runner_registration"] = "ENABLED"
        self.assertEqual(sec.declared_sandbox_findings(p), ["SANDBOX_CONTRACT_DRIFT"])

    def test_allow_token_denied(self):
        p = policy()
        p["identity"]["github_token"] = "present"
        self.assertEqual(sec.declared_sandbox_findings(p), ["SANDBOX_CONTRACT_DRIFT"])

    def test_host_docker_socket_denied(self):
        p = policy()
        p["filesystem"]["docker_socket"] = "RW"
        self.assertEqual(sec.declared_sandbox_findings(p), ["SANDBOX_CONTRACT_DRIFT"])

    def test_network_allow_external_denied(self):
        p = policy()
        p["network"]["external_except_github_read"] = "ALLOW"
        self.assertEqual(sec.declared_sandbox_findings(p), ["SANDBOX_CONTRACT_DRIFT"])

    def test_untested_runtime_cannot_claim_enforced(self):
        p = policy()
        p["status"] = "DEPLOYED_AND_VERIFIED"
        self.assertEqual(sec.declared_sandbox_findings(p), ["SANDBOX_CONTRACT_DRIFT"])


if __name__ == "__main__":
    unittest.main()
