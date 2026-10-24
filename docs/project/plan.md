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
