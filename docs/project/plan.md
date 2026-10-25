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

## SEC-02.5 Mac execution readiness
A. [candidate] Mac Python-only read-only CLI inventory.
B. [candidate] Mac->isolated Linux guest, no automatic shared home or host loopback; real VM qualification pending.
C. [candidate] Mac Ollama remains developer-only; for trusted guest review model must be guest local or later separately approved secure model relay.
D. [pending] Exact SHA CI, true independent reviewer, sandbox evidence, safe issuer and human-only main integration.

## SEC-02.6 next gate — offline Mac/guest qualification
A. [candidate] Public synthetic exact-head GET and source package on Mac.
B. [candidate] Offline no-GitHub guest J-01 evaluation and negative tests.
C. [candidate] SHA/batch consistency proof; deliberately not authenticated.
D. [pending] Final-head GitHub E1 + writer gate expected BLOCKED.
E. [pending] Owner-provided Mac inventory and VM approval, actual negative
   VM-network/mount/secret probes, real guest-local Ollama review.
F. [pending] Separate trusted issuer/check provenance and human-only merge.

## SEC-02.7 next bundle — native Mac baseline
A. [candidate] GET-only local Ollama API probe to confirm model digest.
B. [candidate] Opt-in negative-control synthetic J-01 model run; never trusted.
C. [candidate] Adversarial source & output tests plus exact-head E1.
D. [operator] Execute probe on Mac, then optional one-model smoke and
   report only nonsecret output; consider sequential qwen comparison.
E. [later] Independently qualified VM GPU/security (krunkit is experimental),
   true isolated reviewer, signed exact-head check, owner-only main merge.

## SEC-02.8 development and operator qualification
A. [candidate] 20 predeclared balanced security cases, disjoint oracle metadata.
B. [candidate] Mac one-model five-case batch runner, no GitHub API/tool calls.
C. [candidate] Deterministic offline scorer including Qwen directionality
   contradictions, FP/FN, time and error/coverage.
D. [pending] E1 at final source SHA; main/writer gates unchanged.
E. [operator] Optional sequential Gemma/GPT-OSS/Qwen real 20-case runs,
   first run only batch 1 for each; never concurrent GPU models.
F. [independent] Audit model findings and corpus labeling, expand hidden
   cases and repeat stability; VM trusted J-01 and issuer remain later gates.
