# C-07 synthetic cross-run dispatcher — qualification scope

A single-use durable intent (created with `contents:write`) authorizes a bounded `workflow_dispatch` of the already reviewed default-branch C-05 proof only. The dispatcher uses `actions:write` **without `contents:write`**. The verifier uses `actions:read`, no writes.

Default-branch restrictions mean experimental H-00 workflow files cannot self-dispatch until reviewed into protected `main`. Therefore this test dispatches only `.github/workflows/c05-proof.yml` at the fixed approved SHA `43cb1e6924d208288350d70b7b273f7cd3def0c4` and expects the idempotent existing draft PR #2. All public synthetic-only; no private repo files or deployments.

A successful test proves separate-run dispatch and target identity, **not** automatic H-00 cross-run recovery. A failed or unknown dispatch does not retry: the durable intent prevents double dispatch but requires later controlled reconciliation.

Owner-approved `GADS_C05_APPROVED_SHA` must still exactly match before the test launches. GitHub's native `workflow_dispatch` exception permits GITHUB_TOKEN-triggered new runs; ordinary GITHUB_TOKEN pushes normally do not.

Runtime evidence and SHA-bound acceptance remain pending until actual GitHub-hosted test completes. No PR merges or updates to protected main.

## Live GitHub-hosted evidence — 2026-10-24

**Approved baseline:** protected main `43cb1e6924d208288350d70b7b273f7cd3def0c4`.
**Dispatcher source (immutable):** `1f4ab08244d22b49b84a0fda3ed8509ed9069adb`.

- [C-07 workflow run #40093584738](https://github.com/spikkie/gads-mode-c-proof/actions/runs/40093584738) **SUCCESS**, four jobs: preflight (contents:read), prepare (contents:write only, durable intent), dispatch (actions:write + contents:read, no contents:write), verify (actions:read + contents:read).
- Durable intent ref `qualification/c07-intent-1f4ab08244d22b49b84a`, status `INTENT_ONLY`, source run ID `40093584738`, target pinned `c05-proof.yml` on baseline SHA. The intent is a replay barrier: if a worker fails between committing intent and dispatch, the system **stops rather than automatically sending another dispatch**, requiring explicit reconciliation.
- [C-05 run #40093613654](https://github.com/spikkie/gads-mode-c-proof/actions/runs/40093613654) was newly created with `event=workflow_dispatch`, actor `github-actions[bot]`, exact approved source SHA. **ALL five target jobs SUCCESS**: worker, independent QA, reviewer, stage and trusted publisher.
- Publisher reused pre-existing **DRAFT PR #2** at the same head and two allowed files, with no duplicate PR. No merge, no protected-main changes, no private repo data or releases.
- The subsequent revision adds negative hosted regression tests for replay attempt 2, duplicate persisted intent, unprotected main and wrong source ref; confirmation requires final-head CI PASS.

### Scope and open security controls

This proof establishes a *real automated cross-workflow-run launch* from a limited GitHub Actions job using the GitHub Free plan and existing approved default-branch C-05 workflow. It is **not** yet fully autonomous recovery of the H-00 workpackage after termination of a complete workflow run: H-00 dispatcher and scheduler must be reviewed into protected main, with independent security approval and robust crash-window reconciliation.

- Initial C-07 launch was initiated by a source-branch push. No further manual triggers were used between the dispatcher and C-05 target run.
- The runner creating the durable intent needed `contents:write` (repository-scoped), but the separate dispatch job did **not** have content-write permission.
- `GITHUB_TOKEN` `actions:write` is not single-workflow-scoped by GitHub permissions; the fixed dispatch URL and source-SHA/owner gate are code-level constraints, not sandbox-enforced workflow-specific capabilities. Hostile script modification on an unprotected source branch remains a security risk.
- This demonstration incurs the ordinary synthetic C-05 AI worker and reviewer calls. It is **not** an actual premium-request spending cap.
- Missing authorization, branch protection, target SHA mismatch and repeated attempt must fail closed. No support for arbitrary target workflows, refs or payloads.

**Qualification status:** `C07_PUBLIC_CROSS_RUN_PASS / C07_INDEPENDENT_SECURITY_REVIEW_OPEN / H00_CROSS_RUN_RECOVERY_NOT_PROVEN`.
