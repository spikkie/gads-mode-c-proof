# C-06 — automatic synthetic H-00 workpackage chain

**Candidate status:** BOUNDED AUTOMATIC CONTINUATION PASS / FULL MODE C NOT PROVEN.
**Repository:** public synthetic-only `spikkie/gads-mode-c-proof`; source stays on the unmerged `qualification/c06-h00-live-20261024` branch of draft PR #4.

## GitHub-hosted runtime evidence

Source SHA `2c2f043550b00750583e2c35a84f9b47db3179e2`.
Workflow [#40092471386](https://github.com/spikkie/gads-mode-c-proof/actions/runs/40092471386), attempt 1 and independently repeated verification attempt 2: **SUCCESS**.

Six fresh GitHub-hosted jobs ran sequentially on **one automatically orchestrated workflow invocation**:

1. `tests`: strict repository manifest and 12 deterministic synthetic transition/negative tests PASS.
2. `init`: persisted a new 3-workpackage queue to Git ref `qualification/c06-auto-state-40092471386`, synthetic budget 2.
3. `crash`: persisted workpackage 1 as `LEASED`, then **actually exited 73**. The job asserted `steps.injected.outcome == failure` to make the injected fault observable, while permitting H-00 continuation.
4. `recover`: separate job read durable checkpoint, recovered workpackage 1 and recorded first synthetic unit; P1 attempt counter reached its exact limit 2.
5. `next_package`: **without additional manual dispatch/commit**, processed P2 (2nd synthetic budget unit); rejected P3 and persisted `BLOCKED_BUDGET`.
6. `verify`: read-only independently confirmed `STOP_BUDGET`, 2/2 units, P1/P2 `DONE`, P3 `BLOCKED_BUDGET`, exact four transition events.

Immutable terminal ref SHA `2960938bce20a30142fefb520a037c313e67c83f`. Ledger: `generation=4`, `units_used=2`, `units_limit=2`, `p1_attempts=2`, `p1_attempt_limit=2`, `history=[p1-crashed,p1-recovered,p2-completed,p3-denied-budget]`.

The independent verifier was **re-run via GitHub API** (same run, attempt 2); GitHub Actions run PASS again and terminal ref SHA **unchanged** `2960938bce20a30142fefb520a037c313e67c83f`. No extra state transition or accounting.

This new test builds on the earlier [real-time TTL proof](https://github.com/spikkie/gads-mode-c-proof/actions/runs/40091035825) and is separate from the previous crash/recovery across manually initiated workflow runs.

## Security boundaries / exclusions

- The budget is **synthetic integer work units**. It does **not** meter real Copilot premium requests, token consumption, API spend, or reconcile provider billing. Actual external-budget enforcement remains **OPEN**.
- Automatic continuation is across independent jobs **within a single GitHub Actions run**. Fully autonomous restart after a cancelled or terminated *entire workflow run*, time-based wakeup, and independent run-to-run scheduling remain **OPEN**.
- The deliberately crashing worker uses `continue-on-error` on exactly its crash step; it still logs exit code 73 and the following guard requires `failure`. This proves stage-level recovery, not a replacement for actual ungraceful workflow termination.
- GitHub's `GITHUB_TOKEN` with `contents:write` remains repository-scoped in write jobs, even though the publisher code only writes a named synthetic state ref. This is **not** privileged-token hostile-writer fencing.
- No AI model executes in the new automatic chain. The existing C-05 model worker/reviewer runtime evidence is separate.
- GitHub-hosted code, source branches and state refs are PUBLIC. No private source, customer data, merge, protected-main mutation, external deployments, or production AI credentials were used.
- Independent security review, real billable-cost controls, queue fairness/multi-run recovery, and consumer qualification are not claimed.

**Next gate:** enforce real provider-usage budgets/fencing with independent review and demonstrate unattended *cross-run* crash recovery; preserve read-only E1, protected main and human adoption gates.
