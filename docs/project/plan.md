# Plan — canonical H-00, no backward compatibility

1. [EVIDENCED v0.2.0] Pure H-00 state machine and read-only E1.
2. [CANDIDATE v0.2.1] Exact-policy trusted GitHub gateway: source readback,
   non-force CAS state writes, independent run-metadata attestation.
3. Qualify all adversarial gateway tests and historical live GET-only smoke.
4. Independently security-review GitHub auth boundary, untrusted workflows,
   ref permission granularity, and run-name correlation assumptions.
5. Close security issue #8 for historical branch writers and require human
   approval plus strict CI.
6. Only after owner and independent authorization, install minimal trusted
   writer from reviewed protected main and verify CAS at real GitHub refs.
7. Implement durable outbox, actual Copilot request budgets, fresh unattended
   cross-run failure recovery, and independent adversarial certification.

No deprecated C05..C10 compatibility code, unreviewed merges, or private repos.
