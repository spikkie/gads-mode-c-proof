# GADS — canonical H-00 / GitHub Free qualification

**Version: v0.2.10 SEC-02.7 native Mac Ollama CANDIDATE — NOT RELEASED / NOT ADOPTED.**

One canonical deterministic H-00 codebase in `gads/`. Historical C05–C10
experimental workflows/branches remain audit-only; no backward-compatibility
runtime or source-main integration. Public synthetic GitHub Free only.

## Current code
- `gads/h00.py`: deterministic H-00 state machine and synthetic limits.
- `gads/github_gateway.py`: testable GraphQL exact-beforeOid CAS adapter;
  no authenticated trusted live state write has passed.
- `gads/writer_authority.py`: read-only fail-closed authority policy.
- `gads/j01_runtime.py`, `gads/j01_batches.py`: bounded GitHub snapshot
  and model message protocols. No privileged PR code execution.
- `gads/j01_pull_only.py`: credentialless **non-authoritative** local
  observation runner; NOT a GitHub Actions self-hosted runner.
- `gads/j01_sec023.py`: cross-check untrusted observation and immutable
  full PR diff/batch coverage, never upgrade it to trusted.
- `gads/sec024_sandbox.py`: normalize/inspect a proposed local rootless
  Podman offline network/containers, **not** a deployed firewall.
- `gads/sec024_handoff.py`: exact-SHA clean-context J-01 review handoff
  and non-authoritative returned-review consistency policy.
- `gads/sec024_challenge.py`: synthetic-key HMAC nonce/expiry/replay
  **reference test**, NOT a trusted signing key or GitHub check publisher.

## Validate source locally
```bash
python3 -m gads.manifest verify --root .
python3 -m unittest discover -s tests -v
```

GitHub-hosted E1 is read-only; the writer authority workflow MUST remain
BLOCKED until truly isolated reviewed source, independent J-01 execution,
owner adoption, required trusted GitHub status, and separate state-only
writer privileges are proven. No model run occurred in GitHub CI.
No merge to main, private repository writes, real model billing or token
grant is permitted by this candidate.

See `docs/project/`, `docs/security/sec02-4-bundle-v0.2.7.md`.

## SEC-02.5 — Mac developer host
The development host is macOS, not Linux. Use `python3 -m gads.sec025_macos preflight` **only after source review** for non-mutating tool presence and ambient-risk inventory. Podman on Mac requires a Linux VM. Host Ollama at 127.0.0.1 is not the guest model. The strict guest contract never proves OS isolation or writer authority. See `docs/security/sec02-5-macos-v0.2.8.md`.

## v0.2.9 macOS public snapshot -> offline Linux guest
The new `gads/sec026_offline.py` supports separate two-phase operations:
`export` uses anonymous public synthetic GitHub GET from Mac, while
`review` in a future isolated Linux guest uses only guest-local Ollama.
No guest/VM/model has actually run in hosted CI; package and model
observation remain UNTRUSTED, never GitHub check, owner merge or writer.
See `docs/security/sec02-6-offline-v0.2.9.md`.

## SEC-02.7 — Apple Silicon 24 GiB native model test
On the operator Mac, `python3 -m gads.sec027_mac_model probe --model gemma4:12b`
performs only three loopback Ollama GETs. An explicit `smoke` operation
with `--confirm-synthetic-inference` sends ONE hardcoded adversarial
synthetic security change to the chosen local model, then writes an
untrusted, private JSON observation. No GitHub API in either operation.
No Mac/VM runtime was invoked from hosted CI. See
`docs/security/sec02-7-mac-ollama-v0.2.10.md`.
