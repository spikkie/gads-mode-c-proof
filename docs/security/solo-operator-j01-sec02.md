# GADS SEC-02 - solo operator and independent J-01 (candidate)

Date: 2026-10-25. Public synthetic GitHub Free only.
Decision: DESIGN RECONCILED / ENFORCEMENT NOT DEPLOYED / WRITES BLOCKED.

## Responsibilities
- One human operator can approve deployment/adoption and manually merge.
- W-01 authors bounded changes without a repository writer token.
- J-01 is a new, independent read-only AI execution with fresh context; it
  reviews immutable source SHA, base SHA and exact diff digest.
- H-00 owns admission/state, never infers approval from a chat answer.
- A separate trusted state-only App may write only synthetic state after
  source protection, J-01 and owner approval are independently verified.

## Security invariants
- Branch ruleset must require PR, deletion/non-fast-forward protections,
  strict up-to-date `quality`, `j01_independent_review`, and
  `writer_authorization` from the expected trusted integration.
- A GitHub human review count of zero is *not* independent-review proof.
  It is acceptable only if the stronger J-01/owner controls are actually
  deployed, independent and enforced. Until then SEC-02 stays OPEN.
- J-01 evidence must be obtained by a trusted verifier from an independent
  protected-main workflow run and authenticated GitHub artifact metadata.
  Never accept JSON supplied by a PR, W-01, the model itself, untrusted
  branch code, workflow input or a previously approved source SHA.
- The trusted J-01 workflow ID and protected-main SHA must be configured
  from reviewed and deployed source, not merely passed in as assertions.
  The reviewer must see a fresh context, not W-01's reasoning or mutable state.
- Authenticated workflow provenance is necessary but NOT sufficient:
  GitHub Actions App integration IDs are shared by multiple workflows.
  Independently attest real model invocation/context isolation, scoped
  read-only permissions, unchanged reviewed diff and artifact integrity.
- The human owner approval is separate from J-01 approval and cannot be
  synthesized by the AI. No user approval means no unattended merge.
- A trusted required status must be published only by audited protected
  code and bound to the exact PR SHA. It cannot be made required until
  it is deployed on main and demonstrated on a real PR.

## Implemented in current candidate
`gads/j01_review.py` validates a proposed reviewed-head/base/diff,
attestation schema and digest against expected run/artifact provenance.
`gads/writer_authority.py` no longer requires a second human account;
it instead checks the mandatory J-01 status plus separate human release
approval and live-disabled historical writers. Deterministic negative
tests cover stale commits, forged artifacts, wrong workflow/source,
retries, untrusted branches, bypass, rights and missing owner approval.

## Evidence and outstanding work
- Historical C06/C07/C08 five workflows: operator-reported disabled_manually.
- Historical branches protected by active ruleset 25822045, no bypass.
- Canonical read-only E1 must pass on this exact candidate commit.
- No trusted deployed J-01 workflow, real provider execution, verified
  artifact retrieval, signed/recorded owner approval, required trusted
  checks or privileged state App currently exists.
- This code is a *policy contract*, not a deployed trust boundary. A
  hypothetical positive unit fixture must never turn into a live token.
- J-01 and a human account are not the same kind of independent approval.
  GitHub native rules cannot enforce AI independence on their own.
- Verify sole-operator repository access, rule bypass and merge authority;
  a writable admin token may bypass weaker protected-branch assumptions.

## Exit criteria (not achieved)
1. Independent adversarial audit of J-01 context/session isolation.
2. Trusted protected-main J-01 workflow and artifact provenance verified.
3. Required exact-head checks deployed from protected code with adversarial
   forged-status and malicious-branch tests.
4. Human-owned adoption gate verified, no unattended main merge.
5. Live read-only SEC-02 gate PASS on current PR head; SEC-01 remains sound.
6. Separate final owner approval for any state writer privileges.

## GitHub ZIP artifact digest
The native `artifact.digest` is SHA256 of the uploaded ZIP archive,
NOT the canonical attestation JSON. The trusted verifier MUST retrieve
the ZIP from the authenticated GitHub artifact API, check the entire
archive digest, accept exactly one bounded JSON entry and reject duplicate
JSON keys, symlinks and extra paths. That downloader is NOT deployed yet.
