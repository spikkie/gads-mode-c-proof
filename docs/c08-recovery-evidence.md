# C-08 — fail-closed unknown-dispatch reconciliation (public synthetic candidate)

This standalone C-08 test **reuses an actually completed cross-run C-07 to C-05 dispatch**, without sending a second request, incurring new AI usage, merging PRs, or deploying anything.

Target: approved `c05-proof.yml` run `40093613654`, created by `github-actions[bot]` on protected main at `43cb1e6924d208288350d70b7b273f7cd3def0c4`.
Prior durable C-07 intent: `qualification/c07-intent-1f4ab08244d22b49b84a`, source run `40093584738`.

The first C-08 workflow run writes `UNKNOWN_ACK` to its **own Git state ref** and terminates with real exit code 73. A separately initiated later run reads this durable state, matches the actual C-05 run within the source-intent creation window, rejects no/multiple/failed matches, and atomically transitions to `CONFIRMED_SUCCESS`. A read-only verifier checks the Git ref and target run again.

**Important limits:** the lost acknowledgement is injected; the C-07 dispatch actually succeeded and was verified. The second C-08 run is started by a separate branch push, **not yet an automatic scheduler**. Code is on an unprotected experimental branch and cannot be treated as a trusted default-branch H-00 controller. No runtime proof is claimed until actual runs complete; no write to main or private repos.

## Live GitHub qualification — 2026-10-24

**Run separation:**
1. [#40095804830](https://github.com/spikkie/gads-mode-c-proof/actions/runs/40095804830) at source commit `05c031e8a95fa725a7b4a0f8d685fe0dd93096e8`: complete workflow **FAILED as deliberately injected**, exit code 73 after persisting and reading back `UNKNOWN_ACK` on state ref `qualification/c08-unknown-dispatch-state-20261024`, initial Git ref `a5dc16a03f4b706245d34e5b7b0607521581253b`. 12 positive/negative unit checks and strict checksum manifest passed before deliberate fault.
2. [#40095926987](https://github.com/spikkie/gads-mode-c-proof/actions/runs/40095926987) at commit `32fecc165214b7cf8e7bf34b6043639de0a72b87`: separate GitHub Actions **SUCCESS**. Its `reconcile` job read original C-07 intent `qualification/c07-intent-1f4ab08244d22b49b84a`, retrieved real GitHub Actions metadata, matched **exactly one** previously completed target event, and committed `CONFIRMED_SUCCESS` generation 2 using non-force Git ref update. The independent read-only `verify` job confirmed matching target run and terminal replay without mutation.
3. The independent `verify` job was rerun (attempt 2, same run #40095926987): **SUCCESS**, state ref SHA unchanged `d09cabb5c384ab376bb52b85541a8118c90785c8`. No extra reconciliation write, target dispatch or PR.

**Grounded target:** existing C-05 [run #40093613654](https://github.com/spikkie/gads-mode-c-proof/actions/runs/40093613654) with `workflow_dispatch`, actor `github-actions[bot]`, `head_sha=43cb1e6924d208288350d70b7b273f7cd3def0c4`, `workflow_id=395007460`, `head_branch=main`, completed success and timestamp within the original C-07 intent's 120-second identification window. Other runs, unmatched actors and SHA mismatches cannot satisfy the reconciler; absent or multiple candidate matches block without dispatch.

**Durable final record:** `status=CONFIRMED_SUCCESS`, `generation=2`, `checks=1`, `matched_run=40093613654`, `history=[injected-lost-ack-after-dispatch,reconciled:40093613654]`, Git state ref SHA `d09cabb5c384ab376bb52b85541a8118c90785c8`.

### Security and scope

- The lost acknowledgement is **simulated** after an earlier real successful C-07 dispatch. We did **not** experience a genuine transport ambiguity and did **not** send a new `workflow_dispatch` from C-08.
- The first C-08 run really failed and ended, and a separate second run really recovered its persisted state. However, the second run was **started by a separately initiated source-branch push**, not an automatically scheduled trusted recovery trigger.
- `reconcile` currently has GitHub Actions `contents:write` to update its isolated state branch and `actions:read` for target-run inspection. GitHub's token is repository-scoped, not intrinsically restricted to the single state ref. It remains an **experimental untrusted branch**; protected-default-branch integration requires independent security approval and privileged-writer threat modelling.
- A wrong match, incomplete GitHub run listing, ambiguous match or failed target **blocks**. There is no automatic retry or duplicate dispatch when outcome is unknown; queue/scheduler for pending reconciliation, crash-safe exactly-once external side effects, provider cost caps and malicious-writer fencing remain **NOT PROVEN**.
- No private repository writes or production credentials; no merge and no change to protected `main`. The existing C-05 draft PR #2 was not duplicated.

**Qualification:** `C08_BOUNDED_CROSS_RUN_RECONCILIATION_PASS / C08_UNATTENDED_TRUSTED_RECOVERY_OPEN / FULL_MODE_C_NOT_PROVEN`.
