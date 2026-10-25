# GADS SEC-02.3 — parallel qualification / static audit

Date: 2026-10-25. Version: 0.2.6 CANDIDATE. This is a **first-party static analysis**, not a genuinely independent fresh-context J-01 result.

## Simultaneously develop; sequentially authorize
A. Sandbox isolation specification and fail-closed drift tests.
B. Source-code/adversarial review and exact SHA evidence plan.
C. Pure read-only observation-integrity verification and trusted publisher architecture.
Actual sandbox deployment, live Ollama model, protected-main integration, and GitHub App rights remain separate owner-controlled gates.

## Findings from existing public v0.2.5 source (still open)
- HIGH: local URL allowlist and credential-filter Python code is not OS process/firewall isolation. Ambient HTTPS_PROXY/ALL_PROXY, injected PYTHONPATH/PYTHONSTARTUP and custom CA settings can change network or import behavior. Candidate preflight rejects these, but host/VM controls must still be separately verified.
- HIGH: local J-01 observation has no independent authenticated signing identity, nonce, expiry, trusted source runtime or GitHub-issued reviewed-head check. JSON approval is NOT authorization. New validator ensures an observation is consistent with a separately obtained canonical full diff, then always returns trusted=false.
- HIGH: protected public main presently has strict_required_status_checks_policy=false, no required J-01/check-issuer status, and zero native required human approvals. The design relies on one human operator plus independent AI J-01; currently equivalent GitHub enforcement is unproven.
- HIGH: unsafe public self-hosted runner is removed from canonical v0.2.5+ (its v0.2.4 proposal remains draft audit history), not deployed.
- MEDIUM: up to 16 KiB byte-sized batches do not establish a model's available token context or cross-file reasoning. Complete-file batch coverage is necessary but not sufficient.
- MEDIUM: review observations with large findings may exceed the 8 KiB local output bound and fail closed. Performance/AI cost not yet qualified.
- MEDIUM: original PR snapshot completeness is inferred from GitHub per-file patch counts rather than a separately fetched/verified full Git tree. It rejects missing/binary/truncated patches but does not prove all semantic context is captured.

## Sandbox contract
`sandbox-contract-v0.2.6.json` declares network default DENY, public anonymous GET-only GitHub acquisition, no local runner registration, secretless review process, local-only Ollama, no work files/SSH/Docker socket, and new-only output. Its `SPECIFICATION_NOT_DEPLOYED` status is deliberate. A passing policy lint or mock test MUST NEVER be represented as a deployed VM, firewall, filesystem or egress boundary.

A truly independent reviewer should run in a fresh context/process, with no W-01 previous reasoning, while reviewing exact canonical head and full bounded diff. The operator must separately verify VM policy and repo identity/source SHA before running local Ollama. No real model call has occurred during this candidate implementation.

## Trusted issuer (future, NOT implemented)
Design a distinct audited status issuer/verification process, separate from model and untrusted PR source. Require a verified issuer GitHub App identity, short-lived owner-approved authorization, per-run challenge/nonce, expiry, exact reviewed source/base/diff, full coverage evidence, anti-replay, and fresh GitHub branch readback. A plain GitHub Actions workflow_dispatch job does not satisfy required PR check semantics. An App with checks:write is not authorized by this design alone.

Do not merge into protected `main`, provision tokens, change private repositories, or mark full Mode C accepted without explicit owner consent and independent live evidence.

Reference:
- https://docs.github.com/en/actions/reference/security/secure-use
- https://docs.github.com/en/pull-requests/how-tos/merge-and-close-pull-requests/troubleshooting-required-status-checks
