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
