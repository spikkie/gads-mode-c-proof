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

- D-014: This project's development workstation is Mac; Linux host assumptions are superseded.
- D-015: No Mac home/work mounts, implicit host loopback or Mac Ollama exposure into untrusted review VM. Guest-local model is baseline for trusted experiment.
- D-016: Read-only Mac model observations are untrusted; any future trusted status needs separate issuer and explicit human gate.

- D-017: Separate public synthetic acquisition on Mac (anonymous GitHub
  GET) from model evaluation in an offline Linux guest (no GitHub calls).
- D-018: Full SHA/batch self-consistency does NOT authenticate source
  provenance or model independence. Local result remains untrusted.
- D-019: Require isolated guest-local Ollama and explicitly verified
  host/mount/egress restrictions; no host wildcard bind or public runner.

- D-020: With Mac 24 GiB RAM and native Gemma 4 12B consuming ~16 GB,
  prefer sequential one-model-at-a-time smoke. Actual free RAM unmeasured.
- D-021: Use native Mac MLX for fast UNTRUSTED synthetic development tests;
  do not claim guest-local GPU equivalence or expose Mac Ollama to LAN.
- D-022: Future libkrun/krunkit GPU-VM path is experimentally possible,
  but requires distinct memory, network, performance and security gates.

- D-023: J-01 candidate choice requires a balanced blind benchmark,
  independent expected decisions, manual factual review and repeated
  stable performance, not a single negative smoke.
- D-024: Source-authored labels and regex scoring are separated from
  LLM prompt but NOT independently adjudicated; this limit is explicit.
- D-025: Three known local model digests pinned; fail-closed on drift.
  Mac runs explicit, one model/five cases at a time; no auto promotion.
- D-026: Publish only synthetic development code. Scores cannot issue
  trusted status, merge, authorize writers or attest isolated J-01.
