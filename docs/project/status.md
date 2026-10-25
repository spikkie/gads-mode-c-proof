# GADS status — 2026-10-25 / v0.2.7 SEC-02.4 candidate

Canonical source on public synthetic GitHub Free branch
`development/gads-sec02-4-bundle-v0.2.7-20261025`, stacked over v0.2.6.
Protected `main` remains unchanged unless separately verified otherwise.

Three new components: A pure Podman inspection policy, B immutable source
review handoff, C synthetic HMAC/nonce/replay verification with local
SQLite ledger. All explicitly produce untrusted/prototype decisions,
NEVER GitHub write authority or merge approval. Hardened requirements
do NOT constitute host installation or independent model inference.

Previous v0.2.6 exact-head E1: 193/193 tests, manifest 50 PASS, live
writer authority BLOCKED with ten remaining blockers.
Those results do NOT qualify current v0.2.7 head. New E1 pending.
Historical disabled workflows and protected refs remain audit-only.

OPEN: live isolated sandbox; fresh independent actual model execution;
authentic trusted issuer/check, human owner approval, separate source/state
writer, live exact-beforeOid CAS, full Mode C.
**NO MERGE / NO PRIVATE WRITES / NO TOKEN / NOT ADOPTED.**

## SEC-02.5 v0.2.8 candidate — macOS correction
Source branch `development/gads-sec02-5-macos-v0.2.8-20261025` stacked on v0.2.7 SHA `652dbef9d0128ad198873853ddb2aac20d538acc`. Public synthetic only. Mac read-only preflight and stricter isolated guest policy. No actual Mac inspection, VM startup, guest egress probe, model run, independent J-01 or accepted release. Exact-head CI pending.

## SEC-02.6 v0.2.9 candidate (Mac -> offline VM)
Child branch `development/gads-sec02-6-offline-v0.2.9-20261025` extends
v0.2.8 `158feebeb7ec802a9fdeef5b87434bdf29c9567f`.
Mac public synthetic GET-only export, strict source hashes, VM offline
model path and adversarial tests. Mac inventory and guest runtime have NOT
been executed or observed. Independent review / trusted status / writer
remain BLOCKED. New exact-head E1 pending.

## SEC-02.7 v0.2.10 candidate — Mac Ollama observations
Operator Mac: Apple Silicon 24.0 GiB, Gemma4:12b 7.7 GB installed,
qwen3.5:9b 6.6 GB installed; Gemma running ~16 GB MLX/100% GPU,
16384 context reported. New local GET probe and deliberate synthetic
model smoketest code; NO actual model call by CI/ChatGPT. No VM backend,
no trusted source/status, no owner-approved merge. Final-head E1 pending.

## SEC-02.8 v0.2.11 (2026-10-25)
Three actual operator-provided Mac smoke results for one common negative
fixture: all decision-level REQUEST_CHANGES; Gemma found permission +
prompt injection, GPT-OSS permission without injection classification,
Qwen prompt injection but wrongly claimed writer gate DISABLED. These are
single untrusted model observations, not accuracy ranking evidence.
New fixed balanced 20-case benchmark, model-blind inputs and offline
heuristic scoring. Local 20-case evaluations NOT run; no Mac host access,
no trusted status, no source-main merge. Candidate head CI pending.
