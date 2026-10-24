# GADS Mode C — Public Synthetic Qualification Harness

**Status: NOT PROVEN / NOT ADOPTED.** Standalone synthetic-only C-05 proof. This repository contains no other project source, internal documents, personal identifiers, customer names or application credentials.

## Purpose

Verify a real five-stage GitHub Actions path: noninteractive AI worker → deterministic independent quality → fresh AI reviewer → tokenless staged candidate → bounded GitHub API publisher that creates **one draft pull request**. CI and negative tests are separate. The generated code implements only a toy `is_even(n)` function and may not be reused as production logic.

This public qualification does **not** authorize autonomous writes to any other repository. It also does **not** establish H-00 crash/recovery, budget exhaustion, second-consumer qualification, or private-repository protection. Those remain explicit future gates.

## Bootstrap

1. Create an **empty public** repository named `gads-mode-c-proof`, owned by your GitHub account. Do not initialize it with a README or license. Upload/push these **synthetic files only**. Use a GitHub *noreply* commit email.
2. Run `python3 -m unittest discover -s tests -v` and `python3 scripts/qualify.py manifest --checkout .` before pushing; both should pass.
3. In Settings → Branches, **protect `main`**. Require a pull request before merging, prohibit force pushes and branch deletion, include administrators in enforcement, disallow bypass where supported. Require the repository's `quality` status check **after its first green run**. Do not require a second human GitHub approver for this synthetic single-owner proof.
4. In Settings → Actions → General, keep default `GITHUB_TOKEN` permissions restricted. Turn on **Allow GitHub Actions to create and approve pull requests**. The workflow itself grants `contents: write` and `pull-requests: write` only to its publisher job; it does not call any approval or merge APIs.
5. Confirm `main` is protected through GitHub's REST branch endpoint. Set repository Actions variable `GADS_C05_APPROVED_SHA` to the **full, reviewed commit SHA of the protected `main` branch** (Settings → Secrets and variables → Actions → Variables). This explicitly opts in a single synthetic workflow revision.
6. Actions → **C-05 synthetic autonomous draft publisher** → Run workflow on `main`. Check all five jobs and the resulting draft PR. A manual dispatch begins the autonomous chain; there are no further human approval steps within the test.
7. Deliberately test denied authorization (unset/wrong SHA), duplicate reruns, tampered artifacts and failed reviewer/CI. Do not bypass any gate to get a green run.

## Security boundaries

- Public from day one: repository contents, commit identities, PRs and workflow logs. Use only synthetic text. Never reference or import a private repository, external project, private submodule, account token or real device.
- No workflow uses `pull_request_target`, force-push, merge API, production deployments or user-supplied shell commands.
- Model worker and reviewer jobs have **read-only source access** and separately request Copilot inference; deterministic QA/stage have read-only source. Only the separate bounded publisher has repository write permissions.
- The publisher fails closed unless the trusted base is the protected `main` branch at the exact GitHub Actions SHA and the exact staged evidence/manifest pair passes preflight.
- Model entitlement, GitHub settings, CI and protected refs must be tested live. Static file presence does not qualify C-05.
- No broad repository PAT; only ephemeral job-scoped `GITHUB_TOKEN`, and never print credentials.

## Acceptance evidence

Record the full source SHA, CI run, proof workflow run, fresh worker/reviewer decisions, exact draft PR number, base/head refs, precisely two changed files, no duplicate PR on rerun, and negative runtime outcomes in `docs/project/status.md`. Until then the result is **CANDIDATE**.
