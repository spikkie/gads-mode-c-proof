"""SEC-02.4A - offline Podman sandbox inspection contract, fail closed.

Pure policy over an operator-obtained, NORMALIZED Podman inspection.
Valid metadata is NOT a tested firewall, live container, or OS attestation.
Do not execute untrusted code or register a public GitHub Actions runner.
"""
from dataclasses import dataclass

CONTRACT = "gads.sec024.sandbox.v1"
INTERNAL_NETWORK = "gads-j01-offline"
SOURCE_MOUNT = "/review/source"
INPUT_MOUNT = "/review/input"
OUTPUT_MOUNT = "/review/output"

@dataclass(frozen=True)
class Finding:
    code: str
    detail: str = ""


def findings(evidence):
    out = []
    def reject(code, detail=""):
        out.append(Finding(code, detail))

    if not isinstance(evidence, dict) or evidence.get("schema") != CONTRACT:
        return [Finding("INSPECTION_EVIDENCE_ABSENT_OR_INVALID")]
    if evidence.get("provenance") != "OPERATOR_OBSERVED_NOT_ATTESTED":
        reject("PROVENANCE_CLAIM_UNVERIFIED")
    if evidence.get("rootless") is not True:
        reject("ROOTLESS_NOT_PROVEN")
    if evidence.get("host_os") != "linux":
        reject("UNSUPPORTED_HOST")
    net = evidence.get("network")
    if not isinstance(net, dict):
        reject("NETWORK_NOT_VERIFIED")
    else:
        if net.get("name") != INTERNAL_NETWORK or net.get("internal") is not True:
            reject("NETWORK_NOT_INTERNAL")
        if net.get("published_ports") != []:
            reject("PUBLISHED_PORTS_NOT_ZERO")
        if net.get("egress_denied_probe") is not True:
            reject("EXTERNAL_EGRESS_NEGATIVE_TEST_MISSING")
        if net.get("model_reachable_probe") is not True:
            reject("INTERNAL_MODEL_CONNECTIVITY_UNPROVEN")
    for role in ("reviewer", "model"):
        c = evidence.get(role)
        if not isinstance(c, dict):
            reject("CONTAINER_NOT_OBSERVED", role)
            continue
        if c.get("running") is not True:
            reject("CONTAINER_NOT_RUNNING", role)
        if c.get("networks") != [INTERNAL_NETWORK]:
            reject("UNEXPECTED_CONTAINER_NETWORK", role)
        if c.get("privileged") is not False:
            reject("PRIVILEGED_CONTAINER", role)
        if c.get("read_only_rootfs") is not True:
            reject("ROOTFS_NOT_READONLY", role)
        if c.get("no_new_privileges") is not True:
            reject("NO_NEW_PRIVILEGES_MISSING", role)
        if c.get("cap_drop") != ["ALL"]:
            reject("EXCESS_CAPABILITIES", role)
        if type(c.get("uid")) is not int or c["uid"] == 0:
            reject("NONROOT_IDENTITY_UNVERIFIED", role)
        if type(c.get("pids_limit")) is not int or not 1 <= c["pids_limit"] <= 128:
            reject("PIDS_UNBOUNDED", role)
        if c.get("socket_mounts") != []:
            reject("HOST_SOCKET_EXPOSED", role)
        mounts = c.get("mounts")
        if not isinstance(mounts, list):
            reject("MOUNTS_UNVERIFIED", role)
            continue
        destinations = [m.get("destination") for m in mounts if isinstance(m, dict)]
        if len(destinations) != len(mounts) or len(set(destinations)) != len(destinations):
            reject("MOUNT_IDENTITY_INVALID", role)
        expected = ({SOURCE_MOUNT: True, INPUT_MOUNT: True, OUTPUT_MOUNT: False}
                    if role == "reviewer" else {"/models": True})
        if set(destinations) != set(expected):
            reject("UNEXPECTED_HOST_MOUNT", role)
        for m in mounts:
            if (not isinstance(m, dict) or m.get("destination") not in expected
                    or m.get("read_only") is not expected[m["destination"]]
                    or m.get("source_kind") != "DEDICATED_SYNTHETIC"):
                reject("MOUNT_SCOPE_OR_MODE", role)
    if evidence.get("github_runner_registered") is not False:
        reject("PUBLIC_GITHUB_RUNNER_RISK")
    if evidence.get("secrets_present") is not False:
        reject("SECRET_ISOLATION_UNVERIFIED")
    return sorted(out, key=lambda x: (x.code, x.detail))


def verdict(evidence):
    violations = findings(evidence)
    return {
        "schema": "gads.sec024.sandbox-verdict.v1",
        "decision": "BLOCKED" if violations else "CONFIG_CONSISTENT_ONLY",
        "findings": [{"code": x.code, "detail": x.detail} for x in violations],
        "host_isolation_independently_verified": False,
        "external_attestation_accepted": False,
        "writer_authorized": False,
        "github_status_authorized": False,
    }
