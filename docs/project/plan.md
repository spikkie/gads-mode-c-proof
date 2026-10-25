# Plan — canonical H-00 without backward compatibility

1. Build clean read-only H-00 state machine and strict integrity/negative tests.
2. Independently review the pure transition contract.
3. Design an isolated trusted protected-source GitHub CAS publisher, separate
   from untrusted workpackage source execution.
4. Introduce durable outbox, uniquely correlated provider evidence and real
   bounded AI usage accounting.
5. Resolve SEC-01 writer authority and SEC-02 required independent approvals.
6. Qualify true unattended recovery after a fresh full-workflow interruption.
7. Only with explicit owner and independent review approval consider adoption.

Never merge unreviewed draft PRs, import C06..C10 modules or keep deprecated
compatibility wrappers during this new development.
