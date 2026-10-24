# C-10 — effective GitHub Actions branch-authority inventory

**Scope:** public synthetic only, candidate, no main merge or private writes.

This gate resolves **each actual GitHub branch HEAD**, reads all tracked workflow
YAML via pinned commit SHA, validates each returned Git blob hash, and looks for
write-capable jobs that can run from unprotected push/PR refs. It does **not**
assume that repairing the workflow files on one stacked draft branch fixes its
ancestor branches. Missing metadata, unknown permission schema and ambiguous
inputs are blockers rather than silently ignored.

The gate has only `contents:read` and never dispatches or writes. It
intentionally reports **BLOCKED** until the historical write-enabled branch
workflows are safely retired, migrated to a trusted default-branch controller,
or isolated by verified branch protection/permissions and independent reviewer
gates. Successful unit tests are not an authorization for privileged work.

Related [SEC-01..06 register](https://github.com/spikkie/gads-mode-c-proof/issues/8).
Historical C06/C07/C08 live GitHub runtime evidence stays immutable by source
SHA, but that does not prove secure execution under hostile branch edits.

**Limit:** this is a named-branch inventory, not full org-wide policy assurance.
Do not claim SEC-01 closed without repository rules, permissions, and
adversarial authorization tests.

## Live GitHub qualification — 2026-10-24

At exact source SHA `3a1c537bcaad208da2947e76035c119e47049308`, [workflow #40127588074](https://github.com/spikkie/gads-mode-c-proof/actions/runs/40127588074) ran **11/11 deterministic positive/negative scanner tests PASS**, then deliberately ended with **`BLOCKED_C10_UNPROTECTED_WRITE_WORKFLOWS`** after reading actual GitHub branch tips and per-commit workflow YAML via read-only API. Required source E1 [#40127588047](https://github.com/spikkie/gads-mode-c-proof/actions/runs/40127588047) SUCCESS on the identical SHA.

Observed 12 write-capable jobs across three real unprotected branch tips:

| Branch | Immutable observed SHA | Write-capable jobs |
| --- | --- | ---: |
| `qualification/c06-h00-live-20261024` | `4ebf5726e97ad8e5c45b4de9b61da04a65743443` | 8 |
| `qualification/c07-trusted-cross-run-20261024` | `73967346385b5db92f20c7804813f2a2da849c23` | 2 |
| `qualification/c08-reconcile-20261024` | `0dab90a61ec035ec1b6be6ac3b7d20a6cab638fa` | 2 |

C-05 negative, C-09 and C-10 branch-specific push/PR workflows did not expose additional write-permission grants in this scan. The `c05-proof.yml` file contains trusted publisher rights but is triggered by `workflow_dispatch` from protected `main`, not by push to these feature branches; it is intentionally classified separately.

**Interpretation:** The remaining unsafe workflows are *historical branch HEADs*, not merely copies inside the newest draft. Neither editing the new branch nor passing its unit tests remediates those actual older branches. This candidate has changed **no historical refs**. Actual closure needs repository/branch rules with independent approval and either quarantining the old branch workflows or moving state authority behind reviewed trusted code; verify effective controls before retiring SEC-01.

**Open:** branch list enumerates known C-05..C-10 proof refs, not arbitrary attacker-created refs, org policy, GitHub environments or third-party Apps. A clean result from this tool alone cannot certify complete authorization security.
