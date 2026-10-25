# DoD — GADS v0.2.1 trusted gateway candidate

- [x] Canonical H-00 pure deterministic state machine, no old compatibility.
- [x] Bounded GitHub REST adapter for one fixed ref/file, no force push.
- [x] Policy verifies repository ID, protected-main source SHA, runner ref.
- [x] Immutable ref/state/blob digest and strict scope validation.
- [x] 409/422 CAS conflicts fail closed, without automatic retry.
- [x] Correlated target attestation contract independently requests GitHub run.
- [x] Security unit tests simulate write conflict, forged target and stale owner.
- [x] Hosted E1: manifest, all tests and historical GET-only probe PASS on repaired gateway source SHA; documentation-head CI must be reconfirmed.
- [ ] Unique run-name correlation proven with a new reviewed target workflow.
- [ ] Real approved protected-main writer uses durable GitHub CAS (NOT deployed).
- [ ] Real external-cost provider budgets and uncertain-dispatch outbox.
- [ ] Historical SEC-01 branch writers and SEC-02 approval rules remediated.
- [ ] Full unattended recovery and separate independent security review.
- [ ] Explicit owner merge/adoption decision.

This code may have data-writing functions but **no production authorization**.
