# GADS status - 2026-10-25 - SEC-02 candidate

Canonical public synthetic v0.2.3 draft PR #13 extends #10-#12.
Base `main` has not been merged or mutated. Historic C05-C10 are NOT
maintained as runtime code. The candidate uses canonical H-00 and two
read-only workflows (quality, writer-authority).

SEC-01 historical writers: five workflow IDs 395044779, 395058116,
395072504, 395083466, 395103255 reported `disabled_manually` by owner
CLI; no in-progress runs reported. New ruleset 25822045 is active,
bypass_actors=[], with exact three historical refs; independent live GitHub
GET shows each ref `protected=true`. The historical code remains
preserved solely for audit and is not a backwards-compatibility interface.

SEC-02: replace incompatible second-human GitHub reviewer requirement
with an independent fresh-context AI J-01 evidence policy and separate
human release approval. Model invocation, independent context and trusted
required status are not deployed/proven. Strong negative tests are added.
The current live gate must remain BLOCKED.

Previous exact-head v0.2.3 read-only CI success:
https://github.com/spikkie/gads-mode-c-proof/actions/runs/40192429487
and fail-closed security gate:
https://github.com/spikkie/gads-mode-c-proof/actions/runs/40192425445
These are historical relative to this NEW candidate commit, not evidence
of its final HEAD.

GraphQL beforeOid has mock-backed unit evidence, NOT a live authenticated
mutate/compare test; prior GitHub branch race is not that test.
State-only repo, App token, owner authorization, model budget, outbox,
native recovery, actual independent J-01 and full Mode C remain OPEN.

**WRITER BLOCKED / NO PRIVATE WRITES / NO MAIN MERGE / NOT ADOPTED.**

## v0.2.4 — SEC-02.1 candidate (2026-10-25)
Separate canonical branch `development/gads-trusted-j01-v0.2.4-20261025`
based on v0.2.3 exact SHA `9532d5154005709676f4eeaacff7730c141d30de`.
Adds bounded GET-only GitHub snapshot, fresh Ollama protocol, J-01 report,
and protected-main-only workflow proposal. Feature-branch workflow is not
trusted and no protected-main deployment, real model call or write token
has been authorized. CI evidence will be recorded after final-head runs.

SEC-02.1 security hardening: reject GitHub truncated diff patches by
cross-checking addition/deletion counts and reject duplicate model JSON keys.

## v0.2.5 — SEC-02.2 architecture correction
Static first-party review found HIGH public Actions self-hosted runner
compromise risk and the missing required PR-check event provenance.
New clean development branch removes that workflow, adds pull-only
credentialless local J-01 observations with explicit non-authority.
Final-head CI pending. No real Ollama review, merge or approved runner.

Additional read-only live PR analysis: PR #15 is ~33.9 KB, greater than
previous single-model 24 KB cap. Deterministic complete-file chunking now
supports up to 64 KiB input and <=8 x 16 KiB batches; no model actually
ran during these E1 tests. Final-head revalidation pending.
