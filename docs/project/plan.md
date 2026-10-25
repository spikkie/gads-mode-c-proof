# GADS plan — GitHub Free canonical security sequence

Current work: v0.2.7 SEC-02.4 one combined candidate.
Workstreams develop concurrently; production/privileged gates remain sequential.

A. [candidate] Rootless Podman internal offline network, read-only rootfs,
   non-root identity, restricted mounts and negative egress inspection contract.
   [OPEN] Provision/test actual user-owned isolated host and record evidence.
B. [candidate] Immutable head/base/diff/batch J-01 clean-context handoff.
   [OPEN] Truly separate AI execution, independent source review and quality.
C. [candidate] Short-lived HMAC challenge, synthetic fixture-only signer,
   durable LOCAL SQLite nonce replay test; status is never authorized.
   [OPEN] Audited external identity, distributed replay store, signature
   issuer, GitHub trusted exact-head check and branch ruleset enforcement.

Immediate: exact v0.2.7 manifest + push/PR E1; keep live security BLOCKED.
After candidate review: operator decides actual local sandbox qualification,
then independent model run with source SHA, then separately authorizes
protected main integration. Never merge automatically.
Later: approved state-only GitHub App, authenticated beforeOid CAS,
durable outbox/correlation, model spend ceilings, H-00 recovery, E1-E4.

GitLab Self-Managed `gitlab.spikkies-it.nl` remains a future provider
adapter, not a second duplicated H-00 implementation.
