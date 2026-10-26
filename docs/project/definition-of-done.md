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

## SEC-02.6 v0.2.9 — offline review handoff
- [x] Mac read-only public synthetic PR export with exact-head binding.
- [x] Guest offline model path with NO direct GitHub APIs or credentials.
- [x] Complete bounded patch/batch revalidation and untrusted outputs.
- [x] Negative tests for replay-like tampering, forged trust, paths, model failures.
- [ ] Exact-head 0.2.9 manifest / GitHub push+PR E1 PASS.
- [ ] Independently assessed code + provisioned hardened guest VM.
- [ ] Real guest-only local Ollama and no-host-network/secret proof.
- [ ] Trusted verifier authenticating independently fetched GitHub source.
- [ ] Actual independent J-01 judgment and owner-approved protected main.

## SEC-02.7 v0.2.10 Mac MLX development gate
- [x] Actual Mac inventory/RAM/Ollama model details supplied by operator.
- [x] Local GET-only version/tags/ps probe and full model identity checks.
- [x] Explicit opt-in synthetic one-model inference with 0600 output.
- [x] Adversarial tests for bad model JSON, toolcalls, unsafe approvals,
      secret/proxy env and inadmissible output overwrite.
- [ ] v0.2.10 final-head GitHub E1 and writer-authority BLOCKED evidence.
- [ ] Actual probe and opt-in model run on operator's Mac.
- [ ] Measured macOS memory pressure and model latency under workload.
- [ ] Proven OS guest isolation/egress, independent J-01 code review,
      real PR head review and authenticated trusted status.
- [ ] Owner approval for protected-main merge/writer adoption.

## SEC-02.8 v0.2.11 benchmark
- [x] Twenty immutable cases, exactly 8 safe / 8 unsafe / 4 adversarial.
- [x] Ground-truth decisions specified OUTSIDE every model prompt.
- [x] Test oracle and deterministic offline FP/FN/error/coverage metrics.
- [x] Separate heuristic factual-directionality/contradiction signals.
- [x] Explicit Mac-only local model execution, five-case bounded batches,
      one model per run; unsafe outputs never become trusted J-01 checks.
- [ ] Exact-head v0.2.11 GitHub push and PR E1 and deliberately BLOCKED gate.
- [ ] Operator executes four batches for each of three models on Mac.
- [ ] Independently audit semantic oracle and findings, repeat tests/blindness.
- [ ] Actually provision/test isolated VM and authenticated J-01 issuer.
- [ ] Approved source main + state repo writer; full Mode C DoD.

## v0.2.11.1 SEC-02.8 approval protocol repair
- [x] Diagnose Gemma macOS S01/S02: CONFLICTING_APPROVAL, not wrong verdict.
- [x] Preserve trusted rt.infer strict validator (APPROVE requires findings=[]).
- [x] Benchmark-only explicit approval contract instruction; hash/version bind.
- [x] v2 report/score reject v1 mixing; error breakdown and adversarial tests.
- [ ] Exact-head v0.2.11.1 CI and writer-authority fail-closed evidence.
- [ ] Operator rerun Mac batch 1 under repaired prompt using a NEW file.
- [ ] Interpret actual model outputs; 20-case three-model comparison later.
- [ ] Independently audited oracle, isolated J-01, verified trusted issuer and
      required checks, explicit owner-approved main merge, state repository writer.
