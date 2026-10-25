# DoD — GADS 0.2.2 atomic state candidate

- [x] Clean canonical H-00 implementation and no legacy C06–C10 wrappers.
- [x] Reviewed REST non-force semantics; removed false general CAS assertion.
- [x] GraphQL `updateRefs` implementation contract includes immutable
      `beforeOid`, `afterOid`, `force:false`, exact ref and repo ID.
- [x] Ambiguous/timeout GraphQL responses do not authorize retries.
- [x] Public synthetic live branch exercise with two competing Git commits;
      writer A persists and B yields unknown result; readback confirms A.
- [ ] Final-head GitHub E1 on all deterministic/adversarial unit tests.
- [ ] Actual GraphQL `beforeOid` live mutation and conflict response test
      with a separately approved privileged trusted runner.
- [ ] Enforced ref writer authority (repository-scoped tokens are insufficient).
- [ ] Security issue #8, protected-main independent approvals, strict CI.
- [ ] Real source correlation, vendor usage budget, outbox, unattended recovery.
- [ ] Independent reviewer and owner approve any merge/deployment/adoption.

Not released. Green E1 is not security signoff.

## 0.2.3 — trusted writer authorization

- [x] Define source branch/ruleset/review admission and separate state-only
      GitHub App least-privilege contract; reject stale or missing approvals.
- [x] Host negative tests and read-only current-GitHub preflight.
- [ ] Writer-authority live gate PASS — currently intentionally BLOCKED.
- [ ] Current clean PRs #10, #11, #12 and #13 independently reviewed.
- [ ] Source main security controls enforced, old writer refs quarantined.
- [ ] State-only repository and App install approved and scoped by owner.
- [ ] Trusted gateway refactored for separate source-reader/state-writer.
- [ ] Real GraphQL beforeOid CAS proof under approved trusted runtime.
- [ ] Real outbox, run correlation, AI budget and unattended crash recovery.

This slice adds no writer privileges; full Mode C remains NOT PROVEN.
