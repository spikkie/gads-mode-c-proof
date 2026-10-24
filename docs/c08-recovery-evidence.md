# C-08 — fail-closed unknown-dispatch reconciliation (public synthetic candidate)

This standalone C-08 test **reuses an actually completed cross-run C-07 to C-05 dispatch**, without sending a second request, incurring new AI usage, merging PRs, or deploying anything.

Target: approved `c05-proof.yml` run `40093613654`, created by `github-actions[bot]` on protected main at `43cb1e6924d208288350d70b7b273f7cd3def0c4`.
Prior durable C-07 intent: `qualification/c07-intent-1f4ab08244d22b49b84a`, source run `40093584738`.

The first C-08 workflow run writes `UNKNOWN_ACK` to its **own Git state ref** and terminates with real exit code 73. A separately initiated later run reads this durable state, matches the actual C-05 run within the source-intent creation window, rejects no/multiple/failed matches, and atomically transitions to `CONFIRMED_SUCCESS`. A read-only verifier checks the Git ref and target run again.

**Important limits:** the lost acknowledgement is injected; the C-07 dispatch actually succeeded and was verified. The second C-08 run is started by a separate branch push, **not yet an automatic scheduler**. Code is on an unprotected experimental branch and cannot be treated as a trusted default-branch H-00 controller. No runtime proof is claimed until actual runs complete; no write to main or private repos.
