# SEC-02.4 — parallel bundle: A sandbox, B independent review, C issuer

Date: 2026-10-25. GitHub Free public synthetic code only.
**Source implementation candidate. Not a trusted runtime deployment.**

## A — Rootless sandbox qualification contract
`gads/sec024_sandbox.py` checks normalized read-only Podman inspection
data: rootless Linux, named internal-only bridge, no host-published ports,
negative internet egress, model-only internal network reachability,
no Docker/Podman sockets, no extra mounts, no host keys, a dedicated
nonroot identity, read-only root filesystems and dropped capabilities.
Positive fixtures intentionally return `CONFIG_CONSISTENT_ONLY`;
`host_isolation_independently_verified=false` in EVERY code path.

Operator-side read-only inspection to capture BEFORE enabling review:
```sh
podman info --format json
podman network inspect gads-j01-offline
podman container inspect gads-j01-reviewer gads-j01-model
```
Do NOT run these against an employer device or paste tokens/host paths.
Actual rootless network creation (Podman `--internal`), containers,
cross-namespace connectivity and fail-closed egress must be assessed on
the intended Ubuntu personal host. Current code neither provisions nor
changes any local machine. Inspection statements do not replace negative
egress probes, independent review and OS enforcement.

## B — independent review handoff
`gads/sec024_handoff.py` prepares a deterministic packet bound to the
GitHub snapshot source SHA, base SHA, full diff digest and every review
batch. W-01 and J-01 roles must be distinct. Review return is checked
for immutable packet digest, complete batches, decision, findings and
tools flag. It *always* returns `trusted_review=false`:
model-asserted reviewer identity and 'fresh context' are not
independently authenticated. A separate J-01 runtime/process/host
and independently audited provenance are still required.

## C — authentic issuer, anti-replay and status check design
`gads/sec024_challenge.py` supports a **synthetic-reference** HMAC
challenge signed with a caller-supplied TEST secret. It binds repo,
PR, exact head/base, diff SHA, handoff packet SHA, source code SHA,
random nonce and <=300-second expiration. It consumes nonce in a
local SQLite unique-key transaction, and rejects replay/expiry/tampering.
Even a passing receipt is `PROTOTYPE_RECEIPT_CONSISTENT_NOT_TRUSTED`,
`github_status_issued=false`, `writer_authorized=false`.

Open: trusted external GitHub App checks:write issuer limited to this
synthetic source repo, independent proof of J-01 execution, durable
multi-instance nonce reconciliation, challenge key separation,
source-main approval and PR-target SHA lifecycle/expiry/revocation.
The isolated AI model must NEVER access signing credentials. No
App installation, token, check run or GitHub branch rule is changed.

## Risk/security review disposition
- Critical: untrusted reviewer reply alone, even with valid packet SHA,
  cannot prove independent context or safe code review.
- High: synthetic/local HMAC is not a GitHub App proof, and SQLite nonce
  ledger is not yet a distributed durable issuer.
- High: normalized Podman inspection is not authenticated host isolation.
- High: current GitHub main ruleset lacks strict trusted J-01 required
  checks. Do not require a nonexistent check and deadlock main.
- Medium: model context and cross-file review quality need real bounded
  tests and separate evaluation before trusting any model approval.

Do not declare SEC-02.4 done until actual independent J-01 and sandbox
proofs are available. Current DoD is implementation/test candidate only.

References:
- https://docs.github.com/en/actions/reference/security/secure-use
- https://docs.github.com/en/pull-requests/how-tos/merge-and-close-pull-requests/troubleshooting-required-status-checks
- https://docs.podman.io/en/latest/markdown/podman-network-create.1.html
