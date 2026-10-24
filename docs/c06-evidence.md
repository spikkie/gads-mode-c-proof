# C-06 — synthetic durable Git-ref CAS and restart evidence

**Status:** BOUNDED SYNTHETIC RUNTIME PROOF / CANDIDATE / NOT ADOPTED.
**Repository:** public synthetic-only `spikkie/gads-mode-c-proof`.
**Isolation:** `qualification/c06-h00-live-20261024` contains source, while `qualification/c06-state-20261024` contains the one state record `state/c06.json`. Protected `main` and the existing draft PRs were not modified or merged.

## Live qualification on distinct GitHub-hosted workflow runs

| Gate | Immutable source SHA | Run | Observed result |
| --- | --- | --- | --- |
| Seed then injected crash | `b2bb55a8fddc0f1e29d623a41121aec0b4c971f5` | [#40089451870](https://github.com/spikkie/gads-mode-c-proof/actions/runs/40089451870) | Durable `LEASED`, generation 1, deadline 0 written to a separate Git ref, read back; expected runner failure exit 73. This is intentional failure evidence, **not** PASS for that job. |
| Two contender CAS recovery | `1abcdfe67085add6d7bc8644805b06a843563fc5` | [#40089583773](https://github.com/spikkie/gads-mode-c-proof/actions/runs/40089583773) | Separate `alpha` and `beta` jobs; `alpha` won GitHub non-force ref CAS, `beta` lost the race and performed no duplicate transition; independent verification `COMPLETED` generation 2, two history entries. |
| Independent replay/readback | `8a09bb1636622a95cbf6f2d99f005b26e1a3bf07` | [#40089782206](https://github.com/spikkie/gads-mode-c-proof/actions/runs/40089782206) | Read-only replay job confirmed identical terminal state, generation and Git ref, no additional write. |
| Repository source E1 on replay SHA | `8a09bb1636622a95cbf6f2d99f005b26e1a3bf07` | [#40089782232](https://github.com/spikkie/gads-mode-c-proof/actions/runs/40089782232) | SUCCESS; complete strict SHA256SUMS manifest and repository tests. |

**Independent Git ref state:** `302874960a0afe9b310a2bd71dcda57a154811ca`.
**Result:** `status=COMPLETED`, `generation=2`, `owner=40089451870`, `recovery_owner=40089583773:alpha`; event history exactly `injected-crash:40089451870` and `recovered:40089583773:alpha`.

The test uses GitHub's real `POST /git/commits` and non-forced `PATCH /git/refs`; the competing writer's sibling update cannot fast-forward the ref. No force updates, `main` writes, merge API, production credentials or private repository content are involved.

## Boundaries — not covered by this proof

- The lease expiry is **intentionally injected** as `lease_deadline=0`; this does not prove real wall-clock TTL/deadline scheduling or budget exhaustion.
- Exactly one synthetic workpackage is processed; full H-00 queue scheduling, multi-package concurrency, cost accounting, retry/deadline budgets, takeover fencing under a hostile writer, and cross-repository consumer orchestration are still unproven.
- Repository-scoped GitHub Actions `contents:write` is **not** equivalent to a file/ref-scoped credential. Protected `main` is enforced server-side in this public test repository; production/private authorization requires independent review.
- Human-initiated GitHub commits triggered these separate recovery test runs. Unattended chaining/automatic next-workpackage dispatch is **not** proven.
- C-05 has its own [positive draft publisher proof](https://github.com/spikkie/gads-mode-c-proof/pull/2) and [hosted negative qualification](https://github.com/spikkie/gads-mode-c-proof/pull/3). Neither draft PR is merged. C-05 independent security sign-off remains open.

**Next bounded gate:** review these specific live traces, check stale-writer fencing and real expiring lease/budget semantics before expanding H-00. Keep the synthetic and private workflows separate.


## Real wall-clock TTL, one-attempt budget and independent CAS recovery (2026-10-24)

This is a follow-up to the original injected `deadline=0` proof, not a replacement for that historical evidence.

| Gate | GitHub run / exact source | Evidence |
| --- | --- | --- |
| Future deadline seed and early denial | [#40090945426](https://github.com/spikkie/gads-mode-c-proof/actions/runs/40090945426) / `838e4f2cb05b99a97718ca0a0cb3e036c6916ca2` | Persisted a new separate Git ref with an actual runner wall-clock lease deadline 15 seconds in the future; before-expiry recovery was explicitly rejected. Runner then exited 73 as expected **after** durable readback. |
| Actual expired TTL + bounded recovery | [#40091035825](https://github.com/spikkie/gads-mode-c-proof/actions/runs/40091035825) / `005b56fe36ab93910f062b2a039e307fa0529740` | Two independent jobs observed expiry; beta won the non-force CAS, alpha got `C06_TTL_CAS_LOST_NO_DUPLICATE`. Independent verifier emitted `C06_TTL_REAL_TIME_AND_BUDGET_PASS generation=2 history=2`. |
| Source integrity and regression E1 | [#40091039642](https://github.com/spikkie/gads-mode-c-proof/actions/runs/40091039642) and [#40091035799](https://github.com/spikkie/gads-mode-c-proof/actions/runs/40091035799) / `005b56fe36ab93910f062b2a039e307fa0529740` | SUCCESS with strict pinned `SHA256SUMS`, previous recovery unit tests and new deadline/budget unit tests. |

Persistent TTL-state ref: `qualification/c06-ttl-state-20261024`; terminal ref SHA `3411cf9b588349670f9b8c5edcf0ceb37b8d2b1a`. State schema `gads.c06.ttl.v1`, workpackage `synthetic-ttl-02`, `deadline=1792842148`, `attempts=1`, `max_attempts=1`, `generation=2`, `recovered_by=40091035825:beta`; history exactly `crash:40090945426`, `recovered:40091035825:beta`.

The `scripts.c06_h00.read_state` helper now binds the content read to the **observed commit SHA** instead of a mutable branch name, eliminating a ref/content read-snapshot race in this qualification code. `build_commit` supports an explicitly scoped test-state path; existing historical C-06 ref and state remain unchanged.

**Scope qualification:** this proves a real 15-second clock-based lease expiry, early denial, one allowed state transition, capped state attempt counter, concurrent non-force Git CAS and readback. It does **not** prove provider/model cost accounting, a globally transactional budget, automatic scheduling without human-initiated stage commits, adversarial privilege fencing against a malicious writer with repository-wide token privileges, multi-workpackage queue and downstream consumer handoff. No protected-main or private repo mutation, no merge.
