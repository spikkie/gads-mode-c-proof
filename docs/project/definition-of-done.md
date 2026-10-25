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
