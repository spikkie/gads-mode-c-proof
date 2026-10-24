# C-09 security-gated H-00 recovery trigger — design candidate

**Status:** DRAFT / READ-ONLY VALIDATION ONLY / INDEPENDENT REVIEW REQUESTED.
**Repository:** public synthetic `spikkie/gads-mode-c-proof`.

## Architecture and trust boundaries

The proposed `workflow_run: completed` trigger is GitHub's native mechanism to wake a new workflow **after an entire earlier workflow run has failed**. GitHub requires the triggered workflow file on the repository's **default branch**. That workflow can receive sensitive secrets/write access independently from its originator, so an untrusted source checkout is prohibited.

**Phase 1 — this candidate:** only a `contents:read`, `actions:read` admission/verification job. It checks out reviewed code at the *default-branch event SHA* rather than from `github.event.workflow_run.head_sha`, disables checkout credential persistence, rejects all unapproved triggers by real-run ID, immutable head SHA, workflow ID, repository ID, head-repository ID, actor, exact failure conclusion and run attempt. It re-reads GitHub's server run instead of accepting the webhook payload alone, then verifies the already terminal C-08 state. **No credentials with write capability, no dispatch or branch mutation.**

**Phase 2 — NOT YET AUTHORIZED:** after independent review, introduce a separate bounded state writer (or a GitHub App with single-repo minimum rights), CAS-safe outbox semantics, a trusted scheduler and a provably bounded trigger on a *new* synthetic failure. Never execute code or artifacts from the triggering branch with write tokens.

## Evidence limits

- Current historic source: failed C-08 run `40095804830` (workflow ID `395103255`) on SHA `05c031e8a95fa725a7b4a0f8d685fe0dd93096e8`.
- C-08 later recovered run `40095926987` and reached state SHA `d09cabb5c384ab376bb52b85541a8118c90785c8`, matched C-05 target run `40093613654`. The C-09 smoke test can safely verify these facts without privileged mutation.
- The exact-run allowlist is deliberately single-case; it **cannot** recover an arbitrary future run or dispatch a fresh action.
- A `workflow_run` listener **will not run from this feature branch**. Live native event trigger evidence therefore remains unavailable until explicit independent review and owner-approved merge into protected main.
- This candidate's positive `push` smoke tests are NOT proof that the native `workflow_run` event fired or that unattended full-run recovery works.

## Independent-review checklist (required before any merge)

- [ ] Reviewer independent from code author and implementation context examines the full **stacked PRs #2–#7**, file and workflow dependency graph, permissions and event routing.
- [ ] Check fork/branch trust confusion and use of attacker-controlled `workflow_run` fields, cache and artifact poisoning.
- [ ] Confirm `workflow_run` default-branch-only behavior, GitHub's three-level chained `workflow_run` restriction, rerun semantics and protected-default-branch source provenance.
- [ ] Confirm absence of `contents:write`, `pull_request_target`, dynamic shell interpolation, untrusted checkout, secrets and model calls in privileged listener.
- [ ] Require independent post-merge acceptance with a **fresh bounded synthetic failure** and no human continuation; fail closed for missing/ambiguous acknowledgement; preserve exact target SHA.
- [ ] Separate decision for any future write token, real provider budget meter and hostile-writer fencing. No auto-merge.

**Decision requested:** `SECURITY_REVIEW_REQUIRED`; no adoption or main integration yet.

## Github-hosted read-only evidence — 2026-10-24

- [C-09 smoke workflow #40119549833](https://github.com/spikkie/gads-mode-c-proof/actions/runs/40119549833) SUCCESS at SHA `8cc76aa0fd08d1d1a2683f30f796305703d5b5c1`. **16/16** negative/positive identity unit tests PASS. Live GitHub API readback confirmed actual failed C-08 run `40095804830`, its correct immutable SHA and workflow ID, and reconciled C-08 terminal ref SHA `d09cabb5c384ab376bb52b85541a8118c90785c8` without mutation.
- [E1 workflow #40119549792](https://github.com/spikkie/gads-mode-c-proof/actions/runs/40119549792) SUCCESS on that same source SHA.
- A follow-up static contract suite now enforces read-only permissions, default-branch-only source checkout and absence of unsafe event-derived execution. Final-head GitHub CI acceptance is mandatory.
- **NO NATIVE `workflow_run` EVENT PROVEN:** GitHub requires the listener file on default `main`. This is deliberately a DRAFT candidate, NOT permission to merge.

Open: independent third-party review, freshness-aware generalized run allowlist, read-only-to-writer authorization split, actual unattended recovery after a *new* crash, and real AI-spend quotas.
