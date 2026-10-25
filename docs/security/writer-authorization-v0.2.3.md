# GADS v0.2.3 - Trusted writer authorization preflight

**Decision: NOT AUTHORIZED.** Updated SEC-02 model 2026-10-25.

The canonical architecture has ONE human operator. Independent software
review is by a fresh, read-only AI J-01 with a trusted, immutable, source-
bound attestation. Human approval for main merge, release and deployment
remains explicit; the AI cannot issue it. A second GitHub human reviewer
is not a requirement and is not silently substituted by author self-review.

SEC-01 mitigation: five historical C06/C07/C08 writer workflows
`disabled_manually` according to the operator's verified CLI transcript;
the three frozen branches are covered by active ruleset 25822045 with no
bypass actors and `protected=true` observed via GitHub API. Historical
code is audit-only, with NO backward-compatibility runtime.

The source `protect-main` ruleset 25778767 is still insufficient:
strict checks are not enabled, and the expected protected trusted
`j01_independent_review` and `writer_authorization` required statuses do
not exist yet. Do not make a nonexistent check required prematurely.

The state writer would need a distinct PUBLIC SYNTHETIC state-only repo,
protected refs, and a minimal GitHub App installation scoped to only
that state repo with Contents:write and Metadata:read. It must never receive
GADS source or NMTP write rights. This is a proposed architecture, NOT a
repo/App/credential already approved or created.

Existing v0.2.2 gateway still couples source and state and must be
refactored before live authorization. No branch CI executes privileged
writer code or calls a model. The current preflight is GET-only and
intentionally exits BLOCKED.

See `docs/security/solo-operator-j01-sec02.md` for the exact J-01
evidence protocol, adversarial obligations and remaining exit criteria.

**Open gates:** audited trusted reviewer deployment, exact-head proof,
reliable protected required checks, independent security assessment,
owner-only decision, separate App/state repo, state writer split,
live GraphQL beforeOid CAS, durable outbox, correlation, real model
budget and unattended crash recovery.

**NO MAIN MERGE / NO PRIVATE WRITES / NO TOKEN / NO FULL MODE C.**
