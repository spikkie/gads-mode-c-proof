# Release status

**GADS 0.2.1-candidate — NOT RELEASED / NOT MERGED / NOT ADOPTED.**

Current scope: one canonical H-00 pure state machine, one injected GitHub
gateway for bounded CAS and independently validated run metadata, a read-only
live GitHub provenance smoke, strict manifest and positive/negative unit tests.

No actual GH write-token gateway job has been deployed. No model calls, user
secrets, private repos, provider budget or unattended full-run recovery.
Final SHA GitHub CI, review and issue #8 closure remain required.

2026-10-25: repaired v0.2.1 source `d33e13f56619c5e12facf7b42557566cd931534d` passed hosted E1 #40186008343 with 57/57 tests, 25 manifest files and live read-only GitHub metadata. Candidate remains **NOT MERGED / NOT ADOPTED**, no real CAS writes or provider-cost enforcement.
