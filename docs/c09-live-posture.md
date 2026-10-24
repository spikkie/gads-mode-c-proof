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

## Initial live detection and API-field precision

Initial [read-only posture run #40121110314](https://github.com/spikkie/gads-mode-c-proof/actions/runs/40121110314) reported **BLOCKED**, while its 9 deterministic unit tests passed. Findings included no required approver, loose status checks, non-expiring approval controls and five write-capable push workflows on qualification branches.

If GitHub does not expose `bypass_actors` to the job token, classify it as **`SEC-BYPASS-DATA-UNAVAILABLE`** (unknown; fail closed), NOT as evidence that a bypass actor actually exists. An explicit nonempty actor list is classified separately. Independent administrator verification is needed to close uncertain governance metadata.
