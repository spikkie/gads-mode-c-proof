# SEC-02.2 trusted J-01 architecture security review

Date: 2026-10-25. GitHub Free, PUBLIC SYNTHETIC test repository.
Verdict: REQUEST_CHANGES for PR #14's public GitHub self-hosted runner.
This is a first-party static review, NOT a separate J-01 AI approval.

## SEC02.2-01 HIGH: unsafe public self-hosted runner
The v0.2.4 candidate proposes a repository-level self-hosted runner:
`runs-on: [self-hosted, linux, x64, gads-j01-ephemeral]`.
Its `github.actor`/protected-main `if` checks protect only that job,
not the runner's global job admission. Other malicious or accidental
public-repository workflows could target the same labels. Compromise
may reveal local Ollama, personal files, Git credentials and future
trusted writer privileges. Official GitHub security guidance states
self-hosted runners should almost never be used for public repositories:
https://docs.github.com/en/actions/reference/security/secure-use

**Mitigation:** remove the proposed workflow from the clean next
candidate. Do not register a local Actions runner to this public repo.
Historical PR #14 remains unmerged and is not accepted as deployment code.

## SEC02.2-02 HIGH: workflow_dispatch cannot satisfy required PR check
GitHub says Actions checks triggered by `workflow_dispatch` do not
automatically satisfy a PR's required status check. Merely adding such
a job to protected main or matching an Actions integration ID is not
an authorized exact-head review status. A separate trusted GitHub App
check publisher/other proven eligible integration must be designed.
https://docs.github.com/en/pull-requests/how-tos/merge-and-close-pull-requests/troubleshooting-required-status-checks

## SEC02.2-03 HIGH: independent J-01 is not yet proven
E1 used fake model transport. The literal `fresh_independent`
and a two-message request are not independent proof of a new
isolated model session, reliable reviews, or freedom from inherited
context. Model APPROVE is advisory and can be wrong or prompt-injected.
We have not performed a genuinely separate model review on a protected
source SHA. No human merge or writer authorization has been granted.

## v0.2.5 candidate mitigation
`gads/j01_pull_only.py` reads only public PR JSON/patches via GitHub GET,
with no GitHub token, then issues at most one loopback Ollama request and
rechecks exact PR/base/diff. It does not execute PR code, invoke AI tools,
publish GitHub checks or register as a runner. It rejects credentialed
or GitHub Actions environments, refuses overwrite and writes a local
0600 observation with schema `gads.j01-local-observation.v1`.
It always sets `writer_authorized=false`,
`required_status_issued=false` and `owner_approval_recorded=false`.
The existing trusted run/ZIP verifier cannot accept it as a real
GitHub J-01 attestation.

Python-level checks are NOT an OS isolation boundary. An operator-run
dry-run MUST use an independently audited, dedicated low-privilege
sandbox/VM/container with no employer data, secret material, Docker socket,
shell tools given to AI, or unrestricted egress. Egress allow only GitHub
public GET and local Ollama, enforced by network policy (not merely Python).

## Remaining qualification and authorization gates
- [ ] External independent fresh-context review of exact final source SHA.
- [ ] Independent sandbox/runner lifecycle and egress policy verification.
- [ ] Operator-approved merge of audited source into protected main.
- [ ] Actual isolated local Ollama run and real PR head evidence.
- [ ] Cryptographically attested provenance and anti-replay/freshness checks.
- [ ] Separate trusted issuer of required J-01 exact-PR-head status.
- [ ] Human-controlled merge/deployment and absence of bypass verified.
- [ ] Later: separately approved state-only GitHub App and live CAS.

No GitHub Pro, no private repo, no trusted GitHub publisher, no real model
execution, no backward-compatible C05-C10 code, no automatic merge.
**SEC-02.2 STATUS: DESIGN MITIGATION ONLY / TRUST NOT PROVEN.**

## Complete-diff budget and model context
Live public PR #15 was read with GitHub GET: 18 changed files, approximately
33,888 serialized characters. The original 24 KB single-prompt limit
correctly denied that review. This candidate now uses an explicit total
64 KiB limit, deterministic complete-file batches <=16 KB and <=8 calls.
Every batch must return a valid decision. Final APPROVE requires all
batches APPROVE; any error blocks, any REQUEST_CHANGES denies. Exact source
SHA/base/diff revalidation follows inference. Digests and batch coverage are
recorded in a non-authoritative local observation.

Batchwise analysis is NOT proof of holistic cross-file understanding;
model context and invocation costs remain to be empirically qualified.
No partial or truncated review can issue a trusted GitHub status.
