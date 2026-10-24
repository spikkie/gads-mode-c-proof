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
