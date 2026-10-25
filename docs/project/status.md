# Status — v0.2.0 clean candidate

2026-10-25: New branch starts directly at protected main SHA
`43cb1e6924d208288350d70b7b273f7cd3def0c4`. Old C05 runtime is removed
from this candidate, C06..C10 temporary code is not inherited. Historical
source/run evidence indexed in `docs/evidence/historical-index.md`.

E1 and manifest must pass on final GitHub source SHA before claiming readiness.
The core is in-memory only and cannot autonomously write or recover GitHub jobs.
SEC-01/SEC-02 and formal security review remain unresolved.

## Hosted candidate evidence

- [Run #40184639155](https://github.com/spikkie/gads-mode-c-proof/actions/runs/40184639155) PASS on exact source `491e1d7a2b664db7dd75f04104fee5d694591593`; `MANIFEST_PASS files=19`, **26/26 unit tests PASS**.
- New independent [draft PR #10](https://github.com/spikkie/gads-mode-c-proof/pull/10) targets protected `main`, not the stacked experimental branches. No merge.
- Current baseline uses one read-only source-quality workflow; final documentary commit requires fresh PR E1 again.
- Security [issue #8](https://github.com/spikkie/gads-mode-c-proof/issues/8) remains OPEN: older C06–C08 branches still contain potentially runnable write-capable workflows and protected-main review policy still needs strengthening.
