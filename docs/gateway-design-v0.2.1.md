# GADS 0.2.1 trusted GitHub gateway — bounded implementation candidate

**Status:** DEVELOPED / E1 UNDER VALIDATION / NO DEPLOYED WRITE AUTHORITY.
**Base:** clean H-00 [draft PR #10](https://github.com/spikkie/gads-mode-c-proof/pull/10).
**Branch:** `development/gads-trusted-gateway-v0.2.1-20261025`.

## Scope and separation of duties

`gads/h00.py` remains a pure deterministic workpackage state machine.
`gads/github_gateway.py` adds an injectable, bounded REST adapter to exactly
one existing state branch and one JSON state file. It is **not a runnable
privileged GitHub Actions workflow** and carries no credentials.

1. Authenticate provenance using independently requested GitHub repository and
   protected-main data. Pin the exact public proof repository ID, approved
   main SHA, workflow ID, work ID, trusted H-00 owner and runner main SHA/ref.
   A feature-branch runner or changed/unknown main fails closed.
2. Read the fixed `refs/heads/qualification/gads-h00-state-v1` ref and
   `state/h00.json` at that immutable commit, verify Git blob SHA1 and exact
   canonical JSON bytes, then enforce H-00 state/source scope.
3. Perform one pure H-00 transition and reserve synthetic budget before any
   potential external effect. An identical request replay produces **no
   object write or ref update**.
4. For changed state only: `POST /git/blobs`, `POST /git/trees` with
   base tree, `POST /git/commits` with exactly one parent, then
   `PATCH /git/refs/heads/qualification/gads-h00-state-v1` with
   `force:false`. Treat conflict 409/422 as `CAS_CONFLICT_NO_RETRY`.
   Independently re-read and validate the resulting tip and state.
5. When confirming an existing GitHub workflow run, take only a numeric
   target ID from the caller. Fetch the run via GitHub API and require
   actor, repository IDs, workflow ID, exact SHA, branch `main`,
   `workflow_dispatch`, completed successful result and exact correlation
   in `display_title`. No caller-supplied metadata can substitute.

**Git API caveat:** Non-force ref updates reject non-fast-forward pushes, but
that is not a generic transaction across multiple refs or external effects.
Orphan Git objects may be created on conflicts; they are not committed state.
A repository-scoped `contents:write` token is **not restricted** to this
single ref by these code-level checks. Deployment requires reviewed trusted
code and separate enforced token/branch trust boundaries.

## Live qualification bounds

The isolated CI job uses **only read access** (`contents:read`,
`actions:read`), pinned checkout and no preserved credentials. Unit tests
use an in-memory fake REST server, including simulated Git ref conflicts.
The separate real GitHub API read-only smoke checks the current protected
main and known prior C-05 run #40093613654. It does not access or mutate
the new state ref.

The gateway `Policy` is tied to historic protected main SHA
`43cb1e6924d208288350d70b7b273f7cd3def0c4`; it is deliberately
non-general until an independent reviewer approves the trusted runner
installation and how approved SHAs rotate.

**Correlation assumption remains OPEN:** A future separately reviewed
default-branch target needs a trusted workflow declaration similar to
`run-name: GADS-H00-${{ inputs.correlation }}` and GitHub live proof that
`display_title` is a unique, durable, unforgeable-enough identity source
under the threat model. Existing C-05 workflow did **not** implement this
contract. No claim of actual correlated live target attestation is made.

**Still not implemented:**
- Seeding the initial dedicated state ref by trusted bootstrap;
- On-GitHub privileged writer deployment and real CAS concurrency proof;
- Durable outbox+exactly-once external side effects; 
- Automatic full-run continuation after crash;
- Provider premium-request/cost reservation and reconciliation;
- Protection of historical untrusted branch writers and required independent
  human review (security issue #8).

**No backward compatibility** with temporary C-06..C-10 modules, no merge
to protected main, no private repo writes, no billing or production calls.
