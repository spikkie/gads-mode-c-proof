"""SEC-02.5 Mac and Linux guest isolation adversarial tests."""
import copy
import json
import unittest
from unittest.mock import patch
from gads import sec025_macos as mac

TOOLS = {"python3": True, "git": True, "gh": True,
         "ollama": True, "podman": True, "limactl": False}


def report(**changes):
    original = {
        "schema": mac.VM_SCHEMA, "backend": "PODMAN_MACHINE",
        "guest_os": "linux", "running": True,
        "mac_home_mounts": [], "work_data_mounts": [], "host_sockets": [],
        "github_tokens": False, "public_actions_runner": False,
        "issuer_secret_inside_guest": False, "privileged_guest": False,
        "other_secrets": False,
        "host_loopback": "DENIED", "guest_internet": "DENIED",
        "mac_host_ollama": "DENIED", "guest_local_ollama": "AVAILABLE",
        "model_location": "GUEST_LOCAL_ONLY",
        "input": "OFFLINE_PINNED_SYNTHETIC_PR",
        "output": "NON_AUTHORITATIVE_OBSERVATION",
    }
    original.update(changes)
    return original


class MacInventoryTests(unittest.TestCase):
    def scan(self, *, os_name="Darwin", arch="arm64", tools=None, env=None):
        return mac.preflight(os_name, arch, TOOLS if tools is None else tools,
                             {} if env is None else env)

    def test_arm64_is_not_security_attestation(self):
        obs = self.scan()
        self.assertEqual(obs["status"], "INVENTORY_ONLY")
        self.assertFalse(obs["os_sandbox_proven"])
        self.assertFalse(obs["independent_j01_proven"])
        self.assertFalse(obs["writer_authorized"])

    def test_intel_mac_inventory(self):
        self.assertEqual(self.scan(arch="x86_64")["arch"], "x86_64")

    def test_linux_host_denied(self):
        self.assertIn("NOT_MACOS", self.scan(os_name="Linux")["findings"])

    def test_invalid_arch_denied(self):
        self.assertIn("UNKNOWN_MAC_ARCH", self.scan(arch="mips")["findings"])

    def test_vm_backend_missing_denied(self):
        t = dict(TOOLS, podman=False, limactl=False)
        self.assertIn("VM_BACKEND_NOT_FOUND", self.scan(tools=t)["findings"])

    def test_lima_valid_for_inventory_only(self):
        t = dict(TOOLS, podman=False, limactl=True)
        self.assertEqual(self.scan(tools=t)["status"], "INVENTORY_ONLY")

    def test_mac_host_ollama_not_present(self):
        t = dict(TOOLS, ollama=False)
        self.assertIn("MAC_OLLAMA_NOT_FOUND", self.scan(tools=t)["findings"])

    def test_missing_baseline_tools(self):
        t = dict(TOOLS, git=False)
        self.assertIn("BASE_DEVELOPMENT_TOOLS_MISSING", self.scan(tools=t)["findings"])

    def test_tool_strings_not_accepted(self):
        t = dict(TOOLS, podman="yes", limactl=False)
        self.assertIn("VM_BACKEND_NOT_FOUND", self.scan(tools=t)["findings"])

    def test_token_values_never_printed(self):
        result = self.scan(env={"GH_TOKEN": "DANGEROUS_SECRET"})
        self.assertIn("AMBIENT_SECRET_OR_PROXY_RISK", result["findings"])
        self.assertIn("GH_TOKEN", result["sensitive_environment_variable_NAMES_only"])
        self.assertNotIn("DANGEROUS_SECRET", json.dumps(result))

    def test_proxy_variables_fails_closed(self):
        for k in ("https_proxy", "ALL_PROXY", "NO_PROXY"):
            with self.subTest(k=k):
                self.assertIn("AMBIENT_SECRET_OR_PROXY_RISK",
                              self.scan(env={k: "proxy-value"})["findings"])

    def test_python_ca_override_denied(self):
        self.assertIn("AMBIENT_SECRET_OR_PROXY_RISK",
                      self.scan(env={"PYTHONPATH": "untrusted"})["findings"])

    def test_discovery_only_uses_which_and_platform(self):
        with patch("shutil.which", return_value="/fake"):
            with patch("platform.system", return_value="Darwin"):
                with patch("platform.machine", return_value="arm64"):
                    with patch.dict("os.environ", {}, clear=True):
                        result = mac.collect()
        self.assertEqual(result["status"], "INVENTORY_ONLY")


class VMClaimTests(unittest.TestCase):
    def test_consistent_fixture_never_authorizes(self):
        result = mac.vm_verdict(report())
        self.assertEqual(result["status"], "CONFIG_CONSISTENT_ONLY")
        self.assertFalse(result["actual_network_proof"])
        self.assertFalse(result["model_independence_proof"])
        self.assertFalse(result["github_status_authorized"])
        self.assertFalse(result["writer_authorized"])

    def test_absent_fails_closed(self):
        self.assertEqual(mac.vm_verdict(None)["status"], "BLOCKED")

    def test_mac_home_mount(self):
        self.assertIn("MAC_HOME_MOUNTS_EXPOSED",
                      mac.vm_findings(report(mac_home_mounts=["/Users/private"])))

    def test_work_data_mount(self):
        self.assertIn("WORK_DATA_MOUNTS_EXPOSED",
                      mac.vm_findings(report(work_data_mounts=["company"])) )

    def test_host_docker_socket(self):
        self.assertIn("HOST_SOCKETS_EXPOSED",
                      mac.vm_findings(report(host_sockets=["docker.sock"])))

    def test_host_loopback_default_untrusted(self):
        self.assertIn("HOST_LOOPBACK_NOT_DENIED",
                      mac.vm_findings(report(host_loopback="UNKNOWN")))

    def test_external_egress_denied_proof_needed(self):
        self.assertIn("GUEST_INTERNET_NOT_DENIED",
                      mac.vm_findings(report(guest_internet=None)))

    def test_host_ollama_not_exposed(self):
        self.assertIn("MAC_HOST_OLLAMA_NOT_DENIED",
                      mac.vm_findings(report(mac_host_ollama="ALLOW")))

    def test_guest_ollama_required(self):
        self.assertIn("GUEST_MODEL_UNAVAILABLE",
                      mac.vm_findings(report(guest_local_ollama="UNKNOWN")))

    def test_host_model_not_equivalent_to_guest_model(self):
        self.assertIn("MODEL_HOST_BOUNDARY_INVALID",
                      mac.vm_findings(report(model_location="MAC_HOST")))

    def test_unsigned_source_unacceptable(self):
        self.assertIn("INPUT_NOT_PINNED",
                      mac.vm_findings(report(input="MAC_HOME_SHARE")))

    def test_github_runner_registration_forbidden(self):
        self.assertIn("PUBLIC_ACTIONS_RUNNER_UNSAFE",
                      mac.vm_findings(report(public_actions_runner=True)))

    def test_token_in_guest_forbidden(self):
        self.assertIn("GITHUB_TOKENS_UNSAFE",
                      mac.vm_findings(report(github_tokens=True)))

    def test_issuer_in_guest_forbidden(self):
        self.assertIn("ISSUER_SECRET_INSIDE_GUEST_UNSAFE",
                      mac.vm_findings(report(issuer_secret_inside_guest=True)))

    def test_untrusted_backend_denied(self):
        self.assertIn("VM_BACKEND_UNKNOWN",
                      mac.vm_findings(report(backend="HOST_PROCESS")))

    def test_intel_lima_vm_claim_is_still_untrusted(self):
        self.assertEqual(mac.vm_verdict(report(backend="LIMA"))["status"],
                         "CONFIG_CONSISTENT_ONLY")

    def test_wrong_output_trust_level_denied(self):
        self.assertIn("TRUST_SPOOF",
                      mac.vm_findings(report(output="TRUSTED_GITHUB_CHECK")))

    def test_other_secrets_denied(self):
        self.assertIn("OTHER_SECRETS_UNSAFE",
                      mac.vm_findings(report(other_secrets=True)))

    def test_wrong_guest_os_denied(self):
        self.assertIn("GUEST_NOT_LINUX",
                      mac.vm_findings(report(guest_os="darwin")))


if __name__ == "__main__":
    unittest.main()
