# GADS v0.2.7 SEC-02.4 — Definition of Done

## Source candidate
- [x] Canonical H-00 branch, no C05–C10 compatibility runtime.
- [x] SEC-01 five retired workflows disabled and three historical
      qualification refs protected via verified GitHub Free ruleset.
- [x] Local J-01 observation remains untrusted even if model approves.
- [x] A: rootless/internal-network/no-secret sandbox inspection policy.
- [x] B: deterministic pinned-head, complete batch review handoff contract.
- [x] C: synthetic HMAC SHA-bound bounded challenge + local nonce ledger
      including replay, expired and forged-receipt negative tests.
- [ ] Final SHA256 manifest verified on exact candidate HEAD.
- [ ] Exact-head GitHub push E1 and PR E1 pass.
- [ ] Read-only live writer-authority gate deliberately BLOCKED on exact SHA.

## Security/runtime adoption (not satisfied)
- [ ] Independent J-01 source review executed in separately isolated context.
- [ ] Actual OS-enforced rootless container sandbox, egress and secrets tests.
- [ ] Real local Ollama execution with complete diff/cross-file review proof.
- [ ] Immutable, authenticated source/model/run/attestation provenance.
- [ ] Trusted check issuer using approved scoped GitHub App, replay-safe
      durable challenge store and exact PR-head required checks.
- [ ] Human owner reviews/approves source-main merge, state-only writer
      installation and release adoption independently.
- [ ] Live authenticated GraphQL CAS, durable outbox, correlation,
      true model budget and crash recovery E1–E4 full Mode C qualification.

**NOT RELEASED / NOT MERGED / NOT ADOPTED / WRITER BLOCKED.**
A passing synthetic HMAC or normalized Podman metadata is not independent
execution trust, OS isolation, production signature, or check authorization.

## SEC-02.5 v0.2.8
- [x] Model developer host as macOS, not Linux.
- [x] Non-mutating Mac inventory and deterministic fail-closed guest security checks.
- [ ] Exact-head GitHub E1 + expected BLOCKED writer-gate.
- [ ] Actual operator Mac inventory verified (with no secret or private paths).
- [ ] Independently verified OS guest isolation: host mounts, host loopback, external egress and guest Ollama.
- [ ] Real independent SHA-bound J-01 model review and authenticated evidence.
- [ ] Trusted issuer, explicit human merge approval and Mode C security exit.
