# GADS v0.2.3 — Trusted writer authorization gate

**Review decision: REQUEST_CHANGES / NOT AUTHORIZED.**
**Date:** 2026-10-25. Public synthetic GADS proof only.

## Architecture boundary

```text
Protected source repo: spikkie/gads-mode-c-proof
  - reviewed main workflow, source/identity controls
  - unprivileged checkout, GET-only source API
  - independent GitHub Actions E1 and external human review
              |
              | signed/approved intent + exact commit SHA
              v
Trusted H-00 state writer, only reviewed/pinned code
  - separate short-lived GitHub App installation token
  - *one* dedicated PUBLIC SYNTHETIC state-only repository
  - state repo: Contents WRITE, Metadata READ
  - no source repository write authorization
  - no Actions / Workflows / Administration / Secrets grants
              |
              v
State-only repo (not provisioned)
  - protected branch/ref and limited state objects
  - GraphQL updateRefs beforeOid/afterOid, force:false
  - full durable readback, no retry after unknown HTTP result
```

**Important:** The proposed dedicated state repository has no approved
name/repository ID or installed App yet. Do **not** infer they exist. Existing
v0.2.2 gateway binds source and state to the same repository and MUST BE
REFRACTORED to use separate source-read/state-write clients before a real
writer is enabled. The existing repository-scoped contents:write token is
not sufficient authorization for a single state ref.

GitHub App tokens can be restricted to a single installed repository and
permissions when minted; they still have repository-wide Contents permission
within that dedicated state repository. Therefore the latter must contain
*only public synthetic non-production state* and carry its own protections.
See GitHub docs:
https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/authenticating-as-a-github-app-installation

## Source-policy approval requirements

1. Protected `main`: active `protect-main` ruleset id 25778767, no
   unverified/bypass actors, no deletion or non-fast-forward mutations.
2. Required independent human approval >=1, stale approvals dismissed and
   last-push approval. Require strict up-to-date status checks.
3. Required statuses from trusted GitHub Actions App: `quality` and
   `writer_authorization` *after the latter has been deployed and run on
   the protected main branch*. Do not pre-require an unavailable check.
4. Independent reviewer approval of the entire current clean stack (PRs
   #10–#13), on each exact final head. Future merge/push invalidates prior
   reviewer authority according to the effective GitHub rules.
5. Historical write-enabled C06/C07/C08 source branches must be retired/
   quarantined with verified effective protection; unknown means BLOCKED.
6. Writer implementation must execute only approved protected-main source,
   without checking out or executing workflow-run/PR-head code, artifacts or
   caches with credentials.
7. Read-only `GITHUB_TOKEN` in normal E1. Mint the GitHub App installation
   token only in the separately reviewed trusted writer and, where relevant,
   within an environment requiring human approval. Never log tokens.
8. No real model inference/billing, dispatch or source-repository writes as
   part of this preflight.

## Live findings at start of gate

Source `main` remained at
`43cb1e6924d208288350d70b7b273f7cd3def0c4`.

Ruleset `protect-main` was active, with no bypass actors in the
administrative inspection; however:
- `required_approving_review_count=0`;
- `dismiss_stale_reviews_on_push=false`;
- `require_last_push_approval=false`;
- `strict_required_status_checks_policy=false`;
- only `quality` is required, not `writer_authorization`.
- PR #12 currently has no submitted independent reviews.
- Three historical C06/C07/C08 writer-enabled branches are unprotected.
- Dedicated state-only repository, App-token authorization and trusted
  source deployment do not exist.

**Therefore the live read-only authorization workflow MUST return BLOCKED.**
The automated rules checks are only supporting diagnostics; no AI system
can give itself independent reviewer approval.

## Hosted gate design and acceptance

`gads/writer_authority.py` defines pure fail-closed policy validators and
adversarial tests for repository scope, write permissions, real GitHub rules,
review freshness and legacy writer protection.

`gads/writer_authority_probe.py` uses GET-only GitHub API calls to observe
current ruleset, latest PR reviews and historical writer branches. The
separate `.github/workflows/writer-authority-gate.yml` has only
`contents:read`, `pull-requests:read` and `actions:read`, plus pinned
checkout with `persist-credentials:false`. A missing GitHub API permission
causes `READONLY_METADATA_UNAVAILABLE` => BLOCKED, not accidental approval.

**Gate to authorize future writes** (all required, currently OPEN):
- [ ] SEC-01 historical workflow isolation, no unprotected writer execution.
- [ ] SEC-02 enforced independent reviews, strict required CI, no bypass.
- [ ] Real independent reviewer approves complete current final-head stack.
- [ ] State-only repo created and separately protected by owner.
- [ ] GitHub App installed for **selected state-only repository**, Contents
      write / Metadata read only. Scoped token evidence read by trusted code.
- [ ] Gateway refactored to split source-read and state-write repositories.
- [ ] Approved writer from pinned protected-main source, isolated secrets and
      trusted state-only App credentials; independent adversarial review.
- [ ] Only then, after an explicit owner decision, perform the isolated live
      `updateRefs(beforeOid)` collision and unknown-ack proof.

**Current verdict: `WRITER_AUTHORITY_BLOCKED / NO_TOKEN_GRANTED /
NO_STATE_REPO_CREATED / MODE_C_NOT_PROVEN`.**

No old executable compatibility shims, merges or private repo actions.
