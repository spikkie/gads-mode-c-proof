# Status

**2026-10-24: PUBLIC SYNTHETIC CANDIDATE / NOT ADOPTED / MODE C NOT PROVEN.**

- Public proof `main` protected by active ruleset `protect-main` with no bypass and required `quality`. Accepted source baseline `43cb1e6924d208288350d70b7b273f7cd3def0c4` remains unchanged.
- **C-05 positive:** five-job W-01/E1/J-01/stage/publisher GitHub Actions [#40087492203](https://github.com/spikkie/gads-mode-c-proof/actions/runs/40087492203) SUCCESS, generated [draft PR #2](https://github.com/spikkie/gads-mode-c-proof/pull/2), exactly two files and one commit. Publisher rerun attempt 2 idempotent. PR #2 CI [#40087575476](https://github.com/spikkie/gads-mode-c-proof/actions/runs/40087575476) SUCCESS after operator approval.
- **C-05 negatives:** separate [draft PR #3](https://github.com/spikkie/gads-mode-c-proof/pull/3) read-only hosted suite [#40088502497](https://github.com/spikkie/gads-mode-c-proof/actions/runs/40088502497) 12/12 negative checks PASS; E1 #40088502484 and PR CI #40088664953 SUCCESS. Independently authorized security review and live denial with a deliberately unapproved workflow SHA remain open.
- **C-06 synthetic H-00 CAS/crash:** intentionally crashed seed run #40089451870 persisted expired generation-1 lease; next independent run #40089583773: CAS winner alpha, loser beta safely backed off, verifier confirmed generation-2 completion; third run #40089782206 verified immutable terminal state. E1 #40089782232 SUCCESS. Exact immutable state ref: `302874960a0afe9b310a2bd71dcda57a154811ca`. Full details in `docs/c06-evidence.md`.
- **Open:** real lease TTL/deadline budgets, hostile stale-writer fencing, multi-workpackage H-00 control-loop scheduling, unattended future dispatch, independent security approval, second consumer and private-repository qualification. No main merge, production change, or private repository source publication.

**Verdict:** `C05_PUBLIC_POSITIVE_NEGATIVE_PASS / C06_SYNTHETIC_GITCAS_RESTART_PASS / SECURITY_AND_AUTONOMY_GATES_OPEN`.
