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
- [ ] Real wall-clock lease TTL/deadline expiry; bounded retries and cost budgets under interruption.
- [ ] Hostile stale-owner fencing, multiple queued workpackages and automatic next-package dispatch.
- [ ] Independent security review and controller integration with second distinct consumer.

**None of these public checks authorizes** protected `main` merges, private repository writes, other projects, or full Mode C activation. Candidate only, NOT ADOPTED.
