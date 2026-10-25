# Changelog — canonical GADS

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
