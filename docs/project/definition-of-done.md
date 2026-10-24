# Definition of Done — public synthetic qualification only

## C-05 bounded publisher

- [x] Protected public `main` verified server-side; required `quality` CI.
- [x] Full immutable source SHA owner-authorized for the successful synthetic workflow.
- [x] Real W-01 model call with read-only repository access.
- [x] Tokenless E1 and a distinct fresh J-01 inference on SHA-bound source.
- [x] Tokenless stage/preflight and trusted publisher created exactly one draft PR, exactly two allowed files.
- [x] Publisher rerun reused draft PR #2 without duplicate commits or PRs.
- [x] Hosted read-only negative tests (tamper, reviewer reject, wrong scopes, stale base and unprotected-ref model) plus PR CI.
- [ ] Explicit live GitHub rejected unauthorized-source workflow dispatch and server-enforced protected-ref denial.
- [ ] Independent security review/signoff of repo roles, boundaries and evidence.

## C-06 synthetic H-00 state

- [x] Durable Git ref checkpoint survives actual injected workflow failure across different runs.
- [x] Separate concurrent GitHub writers use non-force CAS, one wins, loser avoids duplicate completion.
- [x] Independent fresh-runner readback and third-run replay confirm exactly two state transitions.
- [x] Version-bound unit security tests and source SHA256/E1 pass on latest replay candidate.
- [x] Real wall-clock lease TTL tested on separate GitHub Actions runs: premature recovery denied, 15-second expiry then CAS takeover; state attempt budget fixed at one (see `docs/c06-evidence.md`).
- [ ] Model/API cost budgets, overall workflow deadlines, exhaustive bounded-retry failure-path evidence under interruption.
- [x] Bounded synthetic multi-workpackage queue: P1 failure/recovery, P2 automatically started in next GitHub job, P3 denied at 2/2 synthetic units; durable ref verified and replay unchanged.
- [ ] Fully unattended cross-workflow-run crash recovery, real provider/API cost caps, hostile-writer fencing, larger multi-package scheduling and fairness.
- [ ] Independent security review and controller integration with second distinct consumer.

**None of these public checks authorizes** protected `main` merges, private repository writes, other projects, or full Mode C activation. Candidate only, NOT ADOPTED.

## C-07 bounded cross-run trigger

- [x] Branch-only publisher code sends fixed-workflow dispatch to protected, SHA-approved C-05 on main, no private repository writes.
- [x] Durable single-use intent ref created by dedicated `contents:write` job; dispatcher has only `actions:write` and read access.
- [x] Independent actual GitHub `workflow_dispatch` run observed from `github-actions[bot]`; all C-05 jobs succeed; existing draft PR reused.
- [x] Negative unit cases for duplicate intent, unprotected main, wrong source branch and rerun replay, subject to final-head GitHub E1.
- [ ] Trusted H-00 cross-run recovery workflow reviewed and integrated into protected default branch.
- [ ] Crash-window uncertain-dispatch reconciliation and true provider-spending/budget enforcement.
- [ ] Independent security signoff of write-token scope and adversarial untrusted branch controls.

C-07 PASS is an isolated public infrastructure proof, not adoption of Mode C in private repositories.
