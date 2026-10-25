# Status — GADS v0.2.1 trusted gateway candidate

2026-10-25: Separate development branch directly based on the canonical H-00
v0.2.0 draft PR #10. The new gateway is a **candidate only**; no approved
protected-main runner, writable token or Git state ref bootstrap is installed.

Added fixed-policy Git-CAS read/update adapter with readback and fail-closed
conflict handling, independent target-run GET checks, simulated adversarial
API tests and a read-only live historical GitHub provenance probe.

GitHub E1 on final source SHA still required. Earlier v0.2.0 clean H-00 E1
succeeded with 26/26 tests; do not treat that as v0.2.1 acceptance.

Security issue #8, historical unprotected branch writers, independent human
approval/strict checks, real billable Copilot ceilings and unattended cross-run
recovery remain OPEN. No merge, private writes or production use.

## Live v0.2.1 validation — 2026-10-25

- [Read-only gateway CI #40186008343](https://github.com/spikkie/gads-mode-c-proof/actions/runs/40186008343), source SHA `d33e13f56619c5e12facf7b42557566cd931534d`: **SUCCESS**, 57/57 E1 tests, complete 25-file manifest and `GADS_GATEWAY_LIVE_READONLY_PASS` against protected main SHA `43cb1e6924d208288350d70b7b273f7cd3def0c4` plus prior target run `40093613654`.
- First run #40185898162 failed one error-classification regression for corrupt Git blob; repaired without weakening the integrity check. Final successful source is the repaired SHA above.
- No real state-ref write, no privileged token, no model spending and no new dispatch. The correlated target-run-name assumption remains pending independent real-world verification.
- Final documented PR-head requires fresh CI after this report commit.
