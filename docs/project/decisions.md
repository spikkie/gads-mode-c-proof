# Canonical GADS architecture decisions

- D-001: One H-00 implementation; no runtime compatibility with C05–C10
  prototypes. Historical refs/runs are retained solely as audit evidence.
- D-002: Pure deterministic workpackage transitions, fail-closed UNKNOWN.
- D-003: Exactly-old-SHA CAS via GraphQL updateRefs.beforeOid, not REST
  fast-forward-only force:false; live credentialed proof still open.
- D-004: One human operator exclusively controls merging/release/adoption;
  independent fresh-context J-01 is AI, NOT a second human account.
- D-005: Unprotected W-01/PR code never gets writer credentials.
- D-006: Public synthetic GitHub Free qualification, private repos untouched.
- D-007: Do not attach a self-hosted Actions runner to public repo.
- D-008: Local pull-only J-01 review observation cannot publish status or
  impersonate authenticated GitHub protected-run provenance.
- D-009: Sandbox controls must be OS enforced, not a Python URL allowlist.
- D-010: Develop sandbox, reviewer handoff and issuer design together, but
  authorize protected merges, model execution and writer rights separately.
- D-011: Native required status must come from audited authorized issuer
  and bind the exact PR commit; Actions workflow_dispatch is not enough.
- D-012: SEC-02.4 synthetic HMAC+SQLite replay test is a contract sample,
  not deployed issuer or proof of independent J-01. No secret shared with AI.
- D-013: GitLab Self-Managed adapter is future scope with same H-00 policy,
  separate provider-specific credential issuer.
