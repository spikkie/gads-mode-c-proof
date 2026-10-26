# Changelog — canonical GADS

## v0.2.11.1 — SEC-02.8 approval-format repair candidate (2026-10-26)
- Actual macOS Gemma batch-1 S01/S02 failed output contract with
  CONFLICTING_APPROVAL; all three negative controls correctly REQUEST_CHANGES.
- Clarified APPROVE -> empty findings solely in the synthetic benchmark prompt.
- Kept trusted J-01 `rt.infer` validator unchanged; no permissive normalization.
- Introduced v2 untrusted report/score contract with prompt SHA256 fingerprint;
  reject mixed v1/v2 results, and expose per-error-code failure histogram.
- Added regression tests reproducing two failed safe cases. Prior observations
  remain immutable and counted as errors. No privileged/writer gate changes.


## v0.2.11 — SEC-02.8 Mac security evaluation (2026-10-25)
- Added immutable twenty-case synthetic corpus (8 safe, 8 unsafe, 4 adversarial).
- Added blind model inputs with oracle labels excluded from prompts.
- Added Mac local-only one-model, five-case repeatable evaluation batches.
- Added strict offline scorer: FP, FN, inference errors, regex contradiction signals,
  coverage, latency and all three model comparison without trust promotion.
- Source tests use fake Ollama responses, not live model execution; independent
  human oracle validation, VM isolation, GitHub App issuer and merge remain open.

## v0.2.10 — SEC-02.7 Mac model development candidate (2026-10-25)
- Qualify observed 24 GiB macOS/ARM64 MLX Gemma 4 12B and alternate Qwen 3.5 9B.
- Added local-only GET inventory with full model digest and loaded-state report.
- Added opt-in one-model synthetic security negative-control and 0600 evidence.
- Rejected unsafe model approval as development-control failure, never trusted status.
- Kept GPU-in-VM acceleration a separate unproven resource/isolation gate.
- No actual Mac inference in hosted E1, source-main merge or writer token.

## v0.2.9 — SEC-02.6 offline J-01 candidate (2026-10-25)
- Added Mac anonymous public-GET exact-head review package export.
- Added independent offline guest-local Ollama review path without GitHub access.
- Added strict package schema, SHA/batch/diff coverage and filesystem protections.
- Added malicious/broken packet, missing batch, model failure and token-negative tests.
- No trusted reviewer, Mac/VM execution, source-main merge or writer permissions.

## v0.2.8 — SEC-02.5 Mac host (2026-10-25)
- Corrected Linux-host assumption: development runs on macOS, with an isolated Linux guest as future proof boundary.
- Added non-mutating macOS inventory CLI and fail-closed guest/network/mount/credential contract.
- Added tests for host home exposure, guest-to-Mac loopback, Mac Ollama bridging, and status spoofing.
- No real VM/model execution, independent J-01, GitHub issuer, writer or merge.

## v0.2.7 — SEC-02.4 candidate (2026-10-25)
- Bundled three security development workstreams: local sandbox inspection,
  independent J-01 review handoff, and synthetic HMAC/SQLite replay contract.
- Added strictly untrusted decision/report semantics; no check publication,
  owner approval, model review or writer permissions.
- Added adversarial tests for privileged containers, network/secret exposure,
  stale review SHA, forged handoff, invalid/replayed/expired receipts.
- Reconciled canonical MVP, Definition of Done, Plan, status and release notes.
- Kept GitHub Free, public synthetic, and protected source main unchanged.

## Prior candidate evidence (audit-only, not backward compatibility)
- v0.2.6 SEC-02.3: 193/193 E1, 50 SHA256 entries, writer gate BLOCKED.
- v0.2.5 SEC-02.2: retired unsafe public self-hosted reviewer proposal.
- v0.2.4 SEC-02.1: initial read-only J-01 runtime candidate.
- v0.2.3: solo human operator + AI J-01 policy, read-only authority.
- v0.2.2: mocked exact-beforeOid GraphQL state compare-and-swap.
- v0.2.0–v0.2.1: clean canonical H-00 and bounded GitHub adapter.
