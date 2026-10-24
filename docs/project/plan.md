# Plan — public synthetic proof

1. **COMPLETE**: public bootstrap, protected `main`, complete manifest, E1, owner-bound SHA, five-job C-05 autonomous draft PR #2, idempotency replay, PR CI and 12 hosted negative-code-path tests in draft PR #3.
2. **EVIDENCED**: C-06 one-workpackage Git-ref CAS, deliberate persistent-state crash, two competing recovery workers and independent replay on different GitHub runs; see `docs/c06-evidence.md`. Keep isolated branch and state ref.
3. **NEXT**: focused independent security review; real unauthorized SHA-dispatch and protected-ref-denial tests only with verified non-escalating principals. Validate genuine lease TTL, deadline and bounded budgets without expanding control-plane architecture.
4. Extend from one synthetic workpackage to H-00 durable queue, live fencing and fail-closed recovery; prove unattended next-workpackage trigger rather than human-pushed phase changes.
5. Qualify a second unlike-stack synthetic consumer, then separately review safe private-repository publisher architecture. No production or private code copy.
6. Preserve current public draft PRs unmerged and protected `main`; adoption and integration to any private repository require explicit independent security/human approval.

7. **EVIDENCED:** Follow-up clock-based 15-second TTL and one allowed state recovery attempt on real GitHub runners. Verify exact live runs in `docs/c06-evidence.md`; deadline proof does not imply cost management.
8. **NEXT:** bounded cost/deadline enforcement, stale-writer fencing beyond honest Git ref CAS, and unattended transition to the next workpackage. Independent review before merge/adoption.

9. **EVIDENCED:** One GitHub Actions invocation autonomously recovers P1 across jobs, starts P2, denies P3 over a synthetic budget, verifies durable state, and repeats verifier without write. See `docs/c06-auto-evidence.md`, run #40092471386.
10. **NEXT:** measure real Copilot/API usage rather than treating synthetic units as billed spend; prove time/event-driven restart across independent workflow runs with fail-closed credential boundaries; independent security review before protected-main integration.

11. **EVIDENCED:** C-07 cross-run dispatch from public synthetic source branch to pinned, already-trusted default-branch C-05 using `actions:write` in a separate token scope and durable single-use intent. Live runs #40093584738 and #40093613654 PASS; evidence in `docs/c07-cross-run-evidence.md`.
12. **NEXT:** review a minimal H-00 recovery dispatcher on protected main and safely test terminated-*whole-run* recovery with durable outbox reconciliation, stale-owner fencing and provider metering; do not merge draft PRs without independent security and owner approval.

13. **EVIDENCED:** C-08 persisted a synthetic lost-dispatch acknowledgement and ended an entire GitHub workflow with injected failure (run #40095804830). A separate manually initiated run (#40095926987) matched the genuine C-07->C-05 target via GitHub API, committed CONFIRMED_SUCCESS and passed idempotent verifier replay. See `docs/c08-recovery-evidence.md`.
14. **NEXT:** independent review of the trusted default-branch recovery controller and authority isolation, followed by safe unattended full-run wakeup, reconciliation of genuinely uncertain network responses and real provider cost budgeting. Do not merge unreviewed state-writer code into protected main.

17. **C-10 LIVE INVENTORY — BLOCKED AS DESIGNED:** GitHub run #40127588074 inspected immutable actual branch HEADs and found 12 permission grants on three unprotected historical branches, despite source-quality and 11 deterministic scanner tests passing. See `docs/c10-branch-authority.md` and blocker issue #8.
18. **NEXT SEC-01 remediation:** independently review and quarantine those historical branch execution paths (or protect them with effective GitHub rulesets), then rescan the original refs. Move future state-writing authority into protected, reviewed code; only subsequently consider changes to protected main and mandatory security status checks. No independent authorization yet.
