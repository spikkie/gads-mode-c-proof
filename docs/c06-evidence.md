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
