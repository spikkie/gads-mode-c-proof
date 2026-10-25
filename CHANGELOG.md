# Changelog

## 0.2.5 SEC-02.2 candidate — 2026-10-25
- Reject public GitHub self-hosted runner due to trust-boundary exposure.
- Correct workflow_dispatch/required PR-status design assumption.
- Add credentialless pull-only local reviewer, tests and threat model.
- Bound complete-file batch coverage for PRs exceeding single-context limits.
- No trusted model review, protected-main merge, release or writer grant.

## 0.2.4 SEC-02.1 candidate — 2026-10-25
- Added read-only bounded J-01 GitHub PR snapshot + local-only Ollama runner.
- Added new two-message context, model output contract and exact-head attestation.
- Staged main-only manually dispatched workflow with pinned upload-artifact.
- Added adversarial tests, patch-count completeness and duplicate-key rejection.
- No live model call / writer / main merge.

## 0.2.3 SEC-02 candidate - 2026-10-25
- Reconciled sole human operator and independent J-01 review semantics.
- Added fail-closed independent J-01 run/artifact/head/diff evidence policy.
- Corrected to whole-artifact ZIP SHA256; reject hostile archive structure.
- Replaced second-human reviewer rule in writer authorization policy.
- Read-only live probe now checks historical workflow disabled states.
- Added adversarial tests and reconciled project MVP/DoD/plan/status.
- SEC-01 five historic workflows disabled and 3 refs frozen: ruleset 25822045.
- Trusted J-01 and state writer NOT deployed; no merge or adoption.

## 0.2.3 initial candidate - 2026-10-25
- Added read-only GitHub writer-authority and negative tests.
- Live gate intentionally BLOCKED.

## 0.2.2 candidate - 2026-10-25
- Corrected REST fast-forward vs atomic beforeOid CAS semantics.
- GraphQL updateRefs injected gateway and deterministic negative tests.

## 0.2.1 candidate - 2026-10-25
- Bounded read-only GitHub state gateway contract and E1.

## 0.2.0 candidate - 2026-10-25
- Clean canonical deterministic H-00 baseline and integrity manifest.
