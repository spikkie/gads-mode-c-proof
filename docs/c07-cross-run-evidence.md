# C-07 synthetic cross-run dispatcher — qualification scope

A single-use durable intent (created with `contents:write`) authorizes a bounded `workflow_dispatch` of the already reviewed default-branch C-05 proof only. The dispatcher uses `actions:write` **without `contents:write`**. The verifier uses `actions:read`, no writes.

Default-branch restrictions mean experimental H-00 workflow files cannot self-dispatch until reviewed into protected `main`. Therefore this test dispatches only `.github/workflows/c05-proof.yml` at the fixed approved SHA `43cb1e6924d208288350d70b7b273f7cd3def0c4` and expects the idempotent existing draft PR #2. All public synthetic-only; no private repo files or deployments.

A successful test proves separate-run dispatch and target identity, **not** automatic H-00 cross-run recovery. A failed or unknown dispatch does not retry: the durable intent prevents double dispatch but requires later controlled reconciliation.

Owner-approved `GADS_C05_APPROVED_SHA` must still exactly match before the test launches. GitHub's native `workflow_dispatch` exception permits GITHUB_TOKEN-triggered new runs; ordinary GITHUB_TOKEN pushes normally do not.

Runtime evidence and SHA-bound acceptance remain pending until actual GitHub-hosted test completes. No PR merges or updates to protected main.
