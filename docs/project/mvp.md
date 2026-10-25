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
