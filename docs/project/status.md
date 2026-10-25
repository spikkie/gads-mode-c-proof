# Status — v0.2.0 clean candidate

2026-10-25: New branch starts directly at protected main SHA
`43cb1e6924d208288350d70b7b273f7cd3def0c4`. Old C05 runtime is removed
from this candidate, C06..C10 temporary code is not inherited. Historical
source/run evidence indexed in `docs/evidence/historical-index.md`.

E1 and manifest must pass on final GitHub source SHA before claiming readiness.
The core is in-memory only and cannot autonomously write or recover GitHub jobs.
SEC-01/SEC-02 and formal security review remain unresolved.
