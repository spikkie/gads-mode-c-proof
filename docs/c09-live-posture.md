# C-09 live repository-security posture gate

A **read-only** gate reads the active GitHub ruleset and checked-out workflows.
It emits a deterministic `PASS` or `BLOCKED`. A `BLOCKED` job must remain
**failed** until requirements are actually fixed; never interpret ordinary
green unit tests or `quality` as security approval.

Current known defects: required approval count zero; loose `quality` checks;
stale/last-push approvals not required; `contents:write` or `actions:write`
runs unprotected `qualification/*` branch source.

The gate is not an independent reviewer, does not mutate the ruleset or any
branch, does not inspect external model billing and does not authorize merging.
Formal blocker register: issue #8. Native unattended H-00 remains NOT PROVEN.
