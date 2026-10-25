# SEC-02.1 - Trusted J-01 runtime candidate

Date: 2026-10-25. GitHub Free, public synthetic source only.
Decision: CODE CANDIDATE / SECURITY DEPLOYMENT BLOCKED.

## Invariants
One human operator controls merge/adoption. W-01 may propose code without
writer rights. J-01 reads a bounded immutable PR diff by GitHub GET and
reviews it in a newly constructed two-message, tool-free Ollama context.
The model can neither modify code nor decide human adoption.

The runner refuses missing/binary/truncated changes (enforce GitHub additions/deletions
and patch-line count equivalence), oversized diffs,
wrong repo identity, SHA changes during snapshot or inference, incomplete
model output, model tool calls, unexpected URLs and GitHub POST. Local
Ollama endpoint is restricted to http://127.0.0.1:11434/api/chat,
stream=false, keep_alive=0, num_predict=384, temperature=0, no retries.
The model is not authenticated as a GitHub writer.

## Workflow proposal
`.github/workflows/j01-trusted-proposed.yml` uses workflow_dispatch,
requires refs/heads/main, fixed operator, pinned checkout SHA and pinned
upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9; requests
only Contents:read and PullRequests:read and assumes a dedicated ephemeral
self-hosted runner label `gads-j01-ephemeral`.

This workflow currently exists ONLY on an experimental candidate branch.
GitHub workflow_dispatch must be present on default branch to execute as
a normal manually triggered workflow. A public-repository self-hosted
runner MUST be independently hardened and barred from untrusted PR jobs.
It is not installed or connected by this release.

## Attestation / future verification
The candidate produces `j01-attestation.json` with exact reviewed head,
base head, canonical diff_sha256, main source SHA, run ID and model ID.
The existing gads/j01_review.py must later verify actual authenticated
run provenance and the uploaded ZIP digest. A future protected trusted
check must be bound to exact PR commit and non-forgeable relative to W-01.

Host E1 uses only injected fake GitHub GET and fake model transport.
These tests do NOT prove live model inference, fresh model process,
runner isolation, artifact production or GitHub required checks.
SEC-02.1 remains unaccepted until these are independently witnessed.

Sources:
- https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows
- https://docs.github.com/en/actions/reference/security/securely-using-pull_request_target
- https://github.com/ollama/ollama/blob/main/docs/api.md
