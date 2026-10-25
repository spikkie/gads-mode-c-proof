# SEC-02.6 — two-phase macOS-to-offline-guest reviewer

Version: v0.2.9 development candidate, 2026-10-25.
**No guest, Mac or local Ollama was started or probed in this change.**

## Motivation

A Linux guest with default-deny egress should NOT fetch GitHub or reach
the Mac network just to review code. Distinguish the public synthetic
data acquisition phase on the Mac from the untrusted J-01 model phase
running within a separately approved isolated Linux VM.

## Phase 1 — macOS, anonymous read-only GET

Review the code in `gads/sec026_offline.py` before executing it. With a
local copy of the candidate checked out at the approved exact SHA, run:

```sh
python3 -m gads.sec025_macos preflight
python3 -m gads.sec026_offline export \
  --pr 18 \
  --head <EXACT_PR_HEAD_SHA> \
  --output "$HOME/tmp/gads-sec026-public-packet.json"
```

The output location must be an **absolute path that does not exist**.
Export calls ONLY the fixed public GitHub repo GET endpoints for the PR
and changed files, validates source head/base and all supported patches
and computes complete SHA256/batch integrity. No GitHub account token
and no Ollama call in this phase. An export is NOT a signed proof of the
GitHub server, and the operator MUST independently verify the intended
head SHA before calling it.

## Phase 2 — offline Linux VM, local Ollama ONLY

A vetted, user-approved VM must be configured without host-home mounts,
Mac loopback forwarding, GitHub authentication, guest internet egress
or writable source checkout. Make the exported packet available to the
guest as an individually transferred immutable synthetic input, NOT by
mounting the entire Mac home. No automatic VM/guest creation in this
candidate.

After confirming guest-local Ollama model availability and all isolation
controls, execute INSIDE THE GUEST, using a reviewed copy of the runner:

```sh
python3 -m gads.sec026_offline review \
  --pr 18 \
  --head <EXACT_PR_HEAD_SHA> \
  --model gemma4:12b \
  --input /review/input/public-packet.json \
  --output /review/output/j01-observation.json
```

This command needs only `127.0.0.1:11434/api/chat` in the GUEST;
it intentionally performs no GitHub fetch, shell tool call, shared model
conversation or status write. All files/batches must be accounted for.
One malformed, missing or contradictory model answer aborts the run.
Guest-local model installation/resource requirements and true
review-context isolation must be separately qualified.

## Result and trust semantics

Package: `gads.sec026.offline-package.v1`, fixed repository,
PR/head/base/diff digest, all batch digests and complete public snapshot.
Review: `gads.sec026.offline-observation.v1`, exact package SHA, source
SHAs, model name, each decision and file/batch coverage.

**Both are UNTRUSTED.** A checksum proves self-consistency only; an
attacker may replace the package and recompute every hash. A reviewer
may also return a wrong APPROVE. A truly independent verifier must read
fresh authenticated GitHub source, compare the exact PR SHA and full
diff, and separately authenticate the VM/model execution before any
trusted status. An HMAC test fixture from v0.2.7 is NOT that proof.

## Security and human gates

- [ ] Mac preflight actually run and sanitized findings reviewed.
- [ ] Separate independent code and architecture review at final SHA.
- [ ] Explicit owner authorization to provision isolated Linux VM;
      verify actual negative host/egress/mount/credential probes.
- [ ] Real J-01 call in fresh guest model context on complete synthetic diff.
- [ ] Verify package against independently fetched GitHub source.
- [ ] Authenticate reviewer process, preserve model version and receipt,
      design trusted checks:write publisher with short-lived credentials.
- [ ] Owner separately approves protected-main integration.
- [ ] No privileged source/state writes until later security gates.

Never register Mac as a public GitHub Actions self-hosted runner. Do
not bind host Ollama to `0.0.0.0` to reach the VM. For a company-managed
Mac, obtain permission before transferring work data or provisioning
any VM. Use PUBLIC SYNTHETIC data only. No paid model calls.
