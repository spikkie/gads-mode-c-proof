# Architecture decisions - canonical GADS

- D-001: No backward compatibility with experimental C05-C10 runtime.
  Historical frozen refs and run evidence are audit-only.
- D-002: Pure H-00 deterministic workpackage state, bounded effects.
- D-003: Any ambiguous dispatch/lease/ACK is sticky UNKNOWN, no blind retry.
- D-004: Synthetic budget is NOT a real model-spend ceiling.
- D-005: Pin reviewed protected source SHA; a token scoped to a repository
  is not limited by GitHub to one branch/ref.
- D-006: Exact-old-SHA atomic CAS requires GraphQL updateRefs beforeOid.
- D-007: Real target run identity/correlation remains unproven.
- D-008: Never let W-01 or unprotected feature workflows write or merge.
- D-009 (SEC-02): ONE human operator decides adoption/merge. J-01 is
  independent fresh-context read-only AI, not another GitHub account.
- D-010: A required trusted exact-head J-01 status, strict CI and audited
  protected-main provenance must replace any assertion of independent
  human-GitHub approval. Zero native required human approvals alone is
  NOT safe nor does it complete SEC-02.
- D-011: Attestation provenance comes from authenticated run/artifact APIs;
  W-01/PR/model-supplied assertions alone NEVER authorize writer access.
- D-012: Public synthetic GitHub Free testbed. GitLab Self-Managed is a
  future provider adapter, not a second H-00 runtime.

- D-013 (SEC-02.1): J-01 receives a bounded read-only GitHub diff pinned
  to exact SHA and uses loopback Ollama with only two fresh messages, no
  tools, no retries and no execution of PR code.
- D-014: Only independently audited protected-main code on a restricted
  ephemeral runner can claim trusted J-01 artifacts; a candidate workflow
  running on an unprotected branch NEVER grants writer authority.

- D-015 SEC-02.2: No public-repository self-hosted GitHub Actions runner.
  Existing J-01 workflow proposal is insecure and must not be deployed.
- D-016: Local pull-only J-01 yields non-authoritative observation only;
  model APPROVE is never owner release or writer authorization.
- D-017: Independently verified sandbox, authenticated trusted publisher
  and exact-PR-head required checks are separate open gates.

- D-018: Parallelize sandbox spec, source audit and verification-contract
  development, but retain sequential trusted deployment and owner gates.
- D-019: Verified local J-01 observation remains untrusted, even if
  model APPROVE and hashes match; separate audited issuer required.
- D-020: Python URL/proxy restrictions do not establish OS-enforced
  egress, identity, secret or filesystem isolation.
