"""SEC-02.5 macOS inventory and proposed isolated Linux VM boundary.

No subprocess is executed. Tool presence is only an inventory observation,
not proof of installed/running VM, sandbox, independent model or issuer.
"""
import argparse
import json
import os
import platform
import shutil

SCHEMA = "gads.sec025.macos-inventory.v1"
VM_SCHEMA = "gads.sec025.vm-boundary.v1"
TOOLS = ("python3", "git", "gh", "ollama", "podman", "limactl")
BAD_ENV = {"GH_TOKEN", "GITHUB_TOKEN", "GH_ENTERPRISE_TOKEN", "GITHUB_APP_TOKEN",
           "GADS_WRITER_TOKEN", "GADS_APP_PRIVATE_KEY", "GITHUB_ACTIONS",
           "PYTHONPATH", "PYTHONSTARTUP", "PYTHONINSPECT", "SSL_CERT_FILE",
           "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"}


def preflight(host_os, arch, tools, environ):
    if not isinstance(tools, dict) or not isinstance(environ, dict):
        raise ValueError("INVALID_INVENTORY")
    detected = {t: tools.get(t) is True for t in TOOLS}
    ambient = sorted(set(str(k).upper() for k in environ)
                     & BAD_ENV |
                     {str(k).upper() for k in environ
                      if str(k).upper().endswith("_PROXY")})
    failures = []
    if host_os != "Darwin":
        failures.append("NOT_MACOS")
    if arch not in ("arm64", "x86_64"):
        failures.append("UNKNOWN_MAC_ARCH")
    if not detected["python3"] or not detected["git"]:
        failures.append("BASE_DEVELOPMENT_TOOLS_MISSING")
    if not detected["podman"] and not detected["limactl"]:
        failures.append("VM_BACKEND_NOT_FOUND")
    if not detected["ollama"]:
        failures.append("MAC_OLLAMA_NOT_FOUND")
    if ambient:
        failures.append("AMBIENT_SECRET_OR_PROXY_RISK")
    return {"schema": SCHEMA, "host": "macOS" if host_os == "Darwin" else "OTHER",
            "arch": arch if arch in ("arm64", "x86_64") else "UNKNOWN",
            "tools": detected, "sensitive_environment_variable_NAMES_only": ambient,
            "status": "BLOCKED" if failures else "INVENTORY_ONLY",
            "findings": sorted(failures),
            "os_sandbox_proven": False, "independent_j01_proven": False,
            "trusted_status_issued": False, "writer_authorized": False}


def vm_findings(observed):
    """Strict assertions of claimed guest constraints, never OS attestation."""
    if not isinstance(observed, dict) or observed.get("schema") != VM_SCHEMA:
        return ["VM_EVIDENCE_ABSENT"]
    failures = []
    def check(yes, name):
        if not yes:
            failures.append(name)
    check(observed.get("backend") in ("PODMAN_MACHINE", "LIMA"), "VM_BACKEND_UNKNOWN")
    check(observed.get("guest_os") == "linux", "GUEST_NOT_LINUX")
    check(observed.get("running") is True, "GUEST_NOT_RUNNING")
    for key in ("mac_home_mounts", "work_data_mounts", "host_sockets"):
        check(observed.get(key) == [], key.upper() + "_EXPOSED")
    for key in ("github_tokens", "public_actions_runner", "issuer_secret_inside_guest",
                "privileged_guest", "other_secrets"):
        check(observed.get(key) is False, key.upper() + "_UNSAFE")
    for key in ("host_loopback", "guest_internet", "mac_host_ollama"):
        check(observed.get(key) == "DENIED", key.upper() + "_NOT_DENIED")
    check(observed.get("guest_local_ollama") == "AVAILABLE",
          "GUEST_MODEL_UNAVAILABLE")
    check(observed.get("model_location") == "GUEST_LOCAL_ONLY",
          "MODEL_HOST_BOUNDARY_INVALID")
    check(observed.get("input") == "OFFLINE_PINNED_SYNTHETIC_PR",
          "INPUT_NOT_PINNED")
    check(observed.get("output") == "NON_AUTHORITATIVE_OBSERVATION",
          "TRUST_SPOOF")
    return sorted(failures)


def vm_verdict(data):
    errors = vm_findings(data)
    return {"schema": "gads.sec025.vm-verdict.v1",
            "status": "BLOCKED" if errors else "CONFIG_CONSISTENT_ONLY",
            "findings": errors,
            "actual_network_proof": False, "model_independence_proof": False,
            "github_status_authorized": False, "writer_authorized": False}


def collect():
    commands = {name: shutil.which(name) is not None for name in TOOLS}
    return preflight(platform.system(), platform.machine(), commands,
                     dict(os.environ))


def main(argv=None):
    parser = argparse.ArgumentParser(description="Read-only macOS development preflight")
    parser.add_argument("command", choices=["preflight"])
    args = parser.parse_args(argv)
    if args.command == "preflight":
        print(json.dumps(collect(), indent=2, sort_keys=True))
    return 0  # Informational only, never authorization.


if __name__ == "__main__":
    raise SystemExit(main())
