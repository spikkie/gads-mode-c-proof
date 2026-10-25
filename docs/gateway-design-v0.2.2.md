# Trusted H-00 state gateway — corrected CAS contract

## Review finding / repair candidate 0.2.2 (2026-10-25)

A non-force REST `PATCH /git/refs` is a *fast-forward check*, not an exact
expected-old-SHA compare-and-swap operation. Therefore the original 0.2.1
implementation must **not** be described or adopted as general atomic CAS.

0.2.2 uses GitHub GraphQL `updateRefs` with **`beforeOid`** (observed
head SHA), **`afterOid`** (new commit SHA), and `force:false`, targeting the
one fixed state ref. The GraphQL response must include the exact
`clientMutationId`. An API rejection stops without retry. Timeouts, missing
acknowledgements, or ambiguous replies are treated as
`CAS_OUTCOME_UNKNOWN_NO_RETRY`; a client mutation ID is *not* a provider
idempotency guarantee.

Transport is injected; no feature-branch Actions job is permitted to receive
`contents:write`. The `repositoryId` GraphQL node ID comes from the verified
public repository metadata, and the trusted pinned source policy must be
reviewed after any protected-main change.

### Isolated real GitHub Git-ref exercise

A separate public synthetic branch
`qualification/gads-cas-isolated-20261025` was created at original protected
main SHA `43cb1e6924d208288350d70b7b273f7cd3def0c4`.

- Initial state commit: `af4e34d4bd1f687cc38b8f1474df8f7ff751173b`.
- Writer A from that parent: `f7cb812abf53279672320e318060b4dd1c629015`.
- Writer B, independently from the SAME parent:
  `7559074b193e8814525a2e073322e3f297b69591`.
- Connector update of writer A succeeded. Writer B got a generic GraphQL
  connector/API failure (not a reliably classified 409/422 or explicit CAS
  result). Independent GitHub readback found the ref still at writer A and
  `state/cas-proof.json` containing `generation=1`, `winner=writer-a`.
- No subsequent blind retry was attempted. No Actions write token was used,
  and this exercise does **not** prove the new GraphQL `beforeOid` transport
  end-to-end. It demonstrates a real competing Git commit / immutable ref
  readback and explicit handling of an unknown competing-write error.

### Authority and deployment boundary

This is **not a fully authorized trusted writer**: GitHub `contents:write`
permission remains repository-wide, even though application code binds to
one ref. GitHub proof connector authorization is NOT an Actions runtime token.
Historic qualification branch writers remain security findings in issue #8.
The feature-branch E1 must remain entirely GET-only.

The proposed model also has no default-branch active gateway, initialized
dedicated state ref, real provider billing cap, durable dispatch outbox, or
verified run-name correlation. Fresh independent review and explicit owner
decision remain required for those integrations.

### Remaining acceptance

- [ ] Test an actual GraphQL `updateRefs(beforeOid)` via a separately
  approved isolated trusted writer, including collision and transport timeout.
- [ ] Prove source SHA authorizer update after approved protected main change.
- [ ] Close SEC-01 writer trust boundary and SEC-02 mandatory approvals.
- [ ] Enforce authenticated correlation and externally metered model budgets.
- [ ] Demonstrate automated, bounded recovery after an actually terminated
  workflow without extra operator triggers.

**Stage:** development candidate only / Mode C NOT PROVEN.
