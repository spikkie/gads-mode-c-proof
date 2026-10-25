"""SEC-02.4 adversarial contract tests. Fixtures are NOT deployment evidence."""
import copy
import hashlib
import sqlite3
import unittest
from gads import j01_batches
from gads import j01_runtime as rt
from gads import sec024_sandbox as sandbox
from gads import sec024_handoff as handoff
from gads import sec024_challenge as issuer

HEAD = "a" * 40
BASE = "b" * 40
MAIN = "c" * 40
DIGEST = "d" * 64
KEY = b"synthetic-fake-key-only-in-unit-tests-32bytes"


def inspection():
    def container(role):
        mounts = ([{"destination": sandbox.SOURCE_MOUNT,
                    "read_only": True, "source_kind": "DEDICATED_SYNTHETIC"},
                   {"destination": sandbox.INPUT_MOUNT,
                    "read_only": True, "source_kind": "DEDICATED_SYNTHETIC"},
                   {"destination": sandbox.OUTPUT_MOUNT,
                    "read_only": False, "source_kind": "DEDICATED_SYNTHETIC"}]
                  if role == "reviewer" else
                  [{"destination": "/models", "read_only": True,
                    "source_kind": "DEDICATED_SYNTHETIC"}])
        return {"running": True, "networks": [sandbox.INTERNAL_NETWORK],
                "privileged": False, "read_only_rootfs": True,
                "no_new_privileges": True, "cap_drop": ["ALL"],
                "uid": 65532, "pids_limit": 64,
                "socket_mounts": [], "mounts": mounts}
    return {"schema": sandbox.CONTRACT,
            "provenance": "OPERATOR_OBSERVED_NOT_ATTESTED",
            "rootless": True, "host_os": "linux",
            "network": {"name": sandbox.INTERNAL_NETWORK,
                        "internal": True, "published_ports": [],
                        "egress_denied_probe": True,
                        "model_reachable_probe": True},
            "reviewer": container("reviewer"), "model": container("model"),
            "github_runner_registered": False, "secrets_present": False}


def snapshot():
    return {"schema": "gads.j01-diff.v1", "repository": rt.REPO,
            "pr_number": 16, "reviewed_head": HEAD, "base_head": BASE,
            "files": [{"path": "src/a.py", "status": "modified",
                       "patch": "@@ -1 +1 @@\n-old\n+new",
                       "additions": 1, "deletions": 1}]}


def handoff_report(packet):
    return {"packet_sha256": packet["packet_sha256"],
            "reviewer_identity": "J-01", "decision": "APPROVE",
            "batch_digests": [x["digest"] for x in packet["batches"]],
            "findings": [], "model_tools_used": False}


def signed():
    request = issuer.new_challenge(pr=16, head=HEAD, base=BASE,
                                   diff_sha256=DIGEST,
                                   packet_sha256="e" * 64,
                                   trusted_source_sha=MAIN,
                                   issued_at=1000, nonce="f" * 64)
    receipt = issuer.sign_prototype(request, secret=KEY,
                                    decision="APPROVE",
                                    model_evidence_sha256="1" * 64)
    expected = {k: request[k] for k in
                ("pr", "head", "base", "diff_sha256",
                 "packet_sha256", "trusted_source_sha")}
    return receipt, expected


class SandboxTests(unittest.TestCase):
    def test_fully_consistent_fixture_not_deployed(self):
        d = sandbox.verdict(inspection())
        self.assertEqual(d["decision"], "CONFIG_CONSISTENT_ONLY")
        self.assertFalse(d["host_isolation_independently_verified"])
        self.assertFalse(d["writer_authorized"])

    def test_missing_inspection_is_blocked(self):
        self.assertEqual(sandbox.verdict(None)["decision"], "BLOCKED")

    def test_non_rootless_host(self):
        x = inspection()
        x["rootless"] = False
        self.assertIn(sandbox.Finding("ROOTLESS_NOT_PROVEN"), sandbox.findings(x))

    def test_network_external_blocked(self):
        x = inspection()
        x["network"]["internal"] = False
        self.assertIn(sandbox.Finding("NETWORK_NOT_INTERNAL"), sandbox.findings(x))

    def test_egress_probe_missing(self):
        x = inspection()
        x["network"]["egress_denied_probe"] = None
        self.assertIn(sandbox.Finding("EXTERNAL_EGRESS_NEGATIVE_TEST_MISSING"),
                      sandbox.findings(x))

    def test_internal_model_unavailable(self):
        x = inspection()
        x["network"]["model_reachable_probe"] = False
        self.assertIn(sandbox.Finding("INTERNAL_MODEL_CONNECTIVITY_UNPROVEN"),
                      sandbox.findings(x))

    def test_publicly_published_port(self):
        x = inspection()
        x["network"]["published_ports"] = [11434]
        self.assertIn(sandbox.Finding("PUBLISHED_PORTS_NOT_ZERO"),
                      sandbox.findings(x))

    def test_network_added_to_reviewer(self):
        x = inspection()
        x["reviewer"]["networks"].append("host")
        self.assertIn(sandbox.Finding("UNEXPECTED_CONTAINER_NETWORK", "reviewer"),
                      sandbox.findings(x))

    def test_host_docker_socket_mounted(self):
        x = inspection()
        x["reviewer"]["socket_mounts"].append("/var/run/docker.sock")
        self.assertIn(sandbox.Finding("HOST_SOCKET_EXPOSED", "reviewer"),
                      sandbox.findings(x))

    def test_extra_secret_mount(self):
        x = inspection()
        x["model"]["mounts"].append({"destination": "/home/.ssh",
                                     "read_only": True,
                                     "source_kind": "DEDICATED_SYNTHETIC"})
        self.assertIn(sandbox.Finding("UNEXPECTED_HOST_MOUNT", "model"),
                      sandbox.findings(x))

    def test_privileged_process(self):
        x = inspection()
        x["reviewer"]["privileged"] = True
        self.assertIn(sandbox.Finding("PRIVILEGED_CONTAINER", "reviewer"),
                      sandbox.findings(x))

    def test_root_uid_denied(self):
        x = inspection()
        x["model"]["uid"] = 0
        self.assertIn(sandbox.Finding("NONROOT_IDENTITY_UNVERIFIED", "model"),
                      sandbox.findings(x))

    def test_runner_registration_denied(self):
        x = inspection()
        x["github_runner_registered"] = True
        self.assertIn(sandbox.Finding("PUBLIC_GITHUB_RUNNER_RISK"),
                      sandbox.findings(x))

    def test_unknown_or_missing_secrets_denied(self):
        x = inspection()
        x.pop("secrets_present")
        self.assertIn(sandbox.Finding("SECRET_ISOLATION_UNVERIFIED"),
                      sandbox.findings(x))

    def test_capabilities_added(self):
        x = inspection()
        x["model"]["cap_drop"] = []
        self.assertIn(sandbox.Finding("EXCESS_CAPABILITIES", "model"),
                      sandbox.findings(x))


class HandoffTests(unittest.TestCase):
    def test_pinned_packet_has_no_privileges(self):
        p = handoff.prepare(snapshot())
        self.assertEqual(p["head_sha"], HEAD)
        self.assertEqual(p["base_sha"], BASE)
        self.assertFalse(p["independent_review_proven"])
        self.assertFalse(p["writer_authorized"])
        self.assertTrue(p["batches"])

    def test_self_review_denied(self):
        with self.assertRaisesRegex(rt.ReviewBlocked, "NOT_INDEPENDENT"):
            handoff.prepare(snapshot(), worker_identity="W-01",
                            reviewer_identity="W-01")

    def test_wrong_sha_denied(self):
        x = snapshot()
        x["reviewed_head"] = "invalid"
        with self.assertRaisesRegex(rt.ReviewBlocked, "SOURCE_SHA"):
            handoff.prepare(x)

    def test_hypothetical_review_return_never_authorizes(self):
        p = handoff.prepare(snapshot())
        result = handoff.check_return(p, handoff_report(p))
        self.assertFalse(result["independent_fresh_context_proven"])
        self.assertFalse(result["trusted_review"])
        self.assertFalse(result["merge_authorized"])

    def test_tampered_packet_denied(self):
        p = handoff.prepare(snapshot())
        p["head_sha"] = "c" * 40
        with self.assertRaisesRegex(rt.ReviewBlocked, "PACKET_TAMPERED"):
            handoff.check_return(p, handoff_report(p))

    def test_wrong_review_packet_denied(self):
        p = handoff.prepare(snapshot())
        result = handoff_report(p)
        result["packet_sha256"] = "0" * 64
        with self.assertRaisesRegex(rt.ReviewBlocked, "SOURCE_MISMATCH"):
            handoff.check_return(p, result)

    def test_incomplete_review_denied(self):
        p = handoff.prepare(snapshot())
        result = handoff_report(p)
        result["batch_digests"] = []
        with self.assertRaisesRegex(rt.ReviewBlocked, "INCOMPLETE"):
            handoff.check_return(p, result)

    def test_changed_batch_digest_denied(self):
        p = handoff.prepare(snapshot())
        result = handoff_report(p)
        result["batch_digests"][0] = "0" * 64
        with self.assertRaisesRegex(rt.ReviewBlocked, "INCOMPLETE"):
            handoff.check_return(p, result)

    def test_untrusted_reviewer_identity_denied(self):
        p = handoff.prepare(snapshot())
        result = handoff_report(p)
        result["reviewer_identity"] = "W-01"
        with self.assertRaisesRegex(rt.ReviewBlocked, "IDENTITY_MISMATCH"):
            handoff.check_return(p, result)

    def test_model_tools_invocation_denied(self):
        p = handoff.prepare(snapshot())
        result = handoff_report(p)
        result["model_tools_used"] = True
        with self.assertRaisesRegex(rt.ReviewBlocked, "MODEL_TOOLS"):
            handoff.check_return(p, result)

    def test_approval_with_findings_denied(self):
        p = handoff.prepare(snapshot())
        result = handoff_report(p)
        result["findings"] = ["not safe"]
        with self.assertRaisesRegex(rt.ReviewBlocked, "OPEN_FINDINGS"):
            handoff.check_return(p, result)

    def test_decision_wrong_type_denied(self):
        p = handoff.prepare(snapshot())
        result = handoff_report(p)
        result["decision"] = []
        with self.assertRaises(rt.ReviewBlocked):
            handoff.check_return(p, result)


class ChallengeTests(unittest.TestCase):
    def test_signed_synthetic_receipt_still_untrusted(self):
        receipt, expected = signed()
        with sqlite3.connect(":memory:") as ledger:
            out = issuer.verify_and_consume_prototype(
                receipt, secret=KEY, expected=expected, now=1040, ledger=ledger)
        self.assertTrue(out["nonce_consumed"])
        self.assertFalse(out["independent_j01_verified"])
        self.assertFalse(out["github_status_issued"])
        self.assertFalse(out["writer_authorized"])

    def test_replay_same_nonce_denied(self):
        receipt, expected = signed()
        with sqlite3.connect(":memory:") as ledger:
            issuer.verify_and_consume_prototype(
                receipt, secret=KEY, expected=expected, now=1040, ledger=ledger)
            with self.assertRaisesRegex(issuer.ChallengeBlocked, "REPLAY"):
                issuer.verify_and_consume_prototype(
                    receipt, secret=KEY, expected=expected, now=1041, ledger=ledger)

    def test_signature_tamper_denied(self):
        receipt, expected = signed()
        receipt["decision"] = "REQUEST_CHANGES"
        with sqlite3.connect(":memory:") as ledger:
            with self.assertRaisesRegex(issuer.ChallengeBlocked, "SIGNATURE"):
                issuer.verify_and_consume_prototype(
                    receipt, secret=KEY, expected=expected, now=1040, ledger=ledger)

    def test_wrong_secret_denied(self):
        receipt, expected = signed()
        with sqlite3.connect(":memory:") as ledger:
            with self.assertRaisesRegex(issuer.ChallengeBlocked, "SIGNATURE"):
                issuer.verify_and_consume_prototype(
                    receipt, secret=b"z" * 32, expected=expected,
                    now=1040, ledger=ledger)

    def test_wrong_target_head_denied(self):
        receipt, expected = signed()
        expected["head"] = "0" * 40
        with sqlite3.connect(":memory:") as ledger:
            with self.assertRaisesRegex(issuer.ChallengeBlocked, "BINDING"):
                issuer.verify_and_consume_prototype(
                    receipt, secret=KEY, expected=expected,
                    now=1040, ledger=ledger)

    def test_wrong_diff_denied(self):
        receipt, expected = signed()
        expected["diff_sha256"] = "0" * 64
        with sqlite3.connect(":memory:") as ledger:
            with self.assertRaisesRegex(issuer.ChallengeBlocked, "BINDING"):
                issuer.verify_and_consume_prototype(
                    receipt, secret=KEY, expected=expected,
                    now=1040, ledger=ledger)

    def test_expired_challenge_denied(self):
        receipt, expected = signed()
        with sqlite3.connect(":memory:") as ledger:
            with self.assertRaisesRegex(issuer.ChallengeBlocked, "EXPIRED"):
                issuer.verify_and_consume_prototype(
                    receipt, secret=KEY, expected=expected, now=1121, ledger=ledger)

    def test_future_challenge_denied(self):
        receipt, expected = signed()
        with sqlite3.connect(":memory:") as ledger:
            with self.assertRaisesRegex(issuer.ChallengeBlocked, "EXPIRED"):
                issuer.verify_and_consume_prototype(
                    receipt, secret=KEY, expected=expected, now=999, ledger=ledger)

    def test_bad_ttl_rejected_at_issue(self):
        with self.assertRaisesRegex(issuer.ChallengeBlocked, "TTL"):
            issuer.new_challenge(pr=16, head=HEAD, base=BASE, diff_sha256=DIGEST,
                                 packet_sha256="e" * 64, trusted_source_sha=MAIN,
                                 issued_at=1000, ttl_seconds=301)

    def test_bad_nonce_rejected_at_issue(self):
        with self.assertRaisesRegex(issuer.ChallengeBlocked, "NONCE"):
            issuer.new_challenge(pr=16, head=HEAD, base=BASE, diff_sha256=DIGEST,
                                 packet_sha256="e" * 64, trusted_source_sha=MAIN,
                                 issued_at=1000, nonce="guessable")

    def test_spoofed_status_denied(self):
        receipt, expected = signed()
        receipt["github_status_issued"] = True
        with sqlite3.connect(":memory:") as ledger:
            with self.assertRaisesRegex(issuer.ChallengeBlocked, "PRIVILEGE"):
                issuer.verify_and_consume_prototype(
                    receipt, secret=KEY, expected=expected, now=1040, ledger=ledger)

    def test_extra_fields_denied(self):
        receipt, expected = signed()
        receipt["github_app_authorization"] = "yes"
        with sqlite3.connect(":memory:") as ledger:
            with self.assertRaisesRegex(issuer.ChallengeBlocked, "FIELDS"):
                issuer.verify_and_consume_prototype(
                    receipt, secret=KEY, expected=expected, now=1040, ledger=ledger)

    def test_missing_ledger_denied(self):
        receipt, expected = signed()
        with self.assertRaisesRegex(issuer.ChallengeBlocked, "LEDGER"):
            issuer.verify_and_consume_prototype(
                receipt, secret=KEY, expected=expected, now=1040, ledger=None)

    def test_no_key_in_source(self):
        with self.assertRaisesRegex(issuer.ChallengeBlocked, "TEST_KEY"):
            receipt, expected = signed()
            issuer.sign_prototype(receipt["challenge"], secret=b"short",
                                  decision="APPROVE",
                                  model_evidence_sha256="1" * 64)


if __name__ == "__main__":
    unittest.main()
