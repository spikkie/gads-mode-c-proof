# GADS — MVP scope (v0.2.7 candidate)

Goal: deterministic H-00 orchestrates bounded candidate workpackages and
enforces fail-closed authorization, with independent J-01 security review,
SHA-bound evidence and explicit human merge/adoption.

Implementation in public synthetic GitHub Free only: canonical H-00,
read-only GitHub state/snapshot, exact-beforeOid gateway policy, local
anonymous J-01 model-observation protocol and integrity tests.

SEC-02.4 increment: local sandbox inspection contract (A), reproducible
clean-context J-01 review packet (B), prototype challenge/HMAC/nonce and
SQLite anti-replay policy (C). These do not deploy a sandbox or sign an
independent model run. No actual Ollama call from hosted CI.

Excluded: private source/NMTP writes, GitHub Pro upgrade, legacy C05–C10
runners or compatibility, unapproved source-main merge, production
publisher, real model budget, durable outbox and complete Mode C.

## v0.2.8 macOS host correction
Mac is the operator development host. Actual trusted model evaluation requires a separately provisioned, isolated Linux guest. Preflight/source tests only; no Mac configuration or real Ollama invocation in this slice.

## v0.2.9 SEC-02.6 offline model boundary
Prepare complete immutable synthetic review inputs via anonymous GitHub
GET on Mac; transfer single packet into separately authorized offline
Linux guest for local Ollama. Both package and model result remain
untrusted and do not authorize GitHub changes.

## SEC-02.7 macOS model smoke MVP
Real operator baseline: macOS arm64, 24 GiB, installed gemma4:12b and
qwen3.5:9b; Gemma active MLX 100% GPU, ~16 GB loaded and 16384 context
at CLI observation. New read-only Ollama model probe and opt-in *synthetic*
negative-control inference; results are UNTRUSTED dev-only observations.

## SEC-02.8 v0.2.11 evaluation MVP
Deterministic 20-case synthetic benchmark and predeclared test oracle:
10 expected approvals, 10 denials. One Mac local Ollama model/batch
per explicit opt-in, offline deterministic confusion metrics and
heuristic fact checks; no signed provenance or privileged actions.

## v0.2.11.1 benchmark response repair
Keep strict runtime parsing: model responses APPROVE with nonempty findings
remain ERROR. Clarify response rules inside benchmark-only system prompt;
source-bound prompt SHA256 and explicit per-error-code reporting distinguish
new evidence from historical v1 result (Gemma batch 1: 3 decision-correct,
2 schema errors). No silent rewriting, no private data or writer privileges.
