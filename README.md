# GADS - canonical H-00, GitHub Free synthetic qualification

**v0.2.5 SEC-02.2 development candidate - NOT ADOPTED**

One canonical deterministic H-00 runtime in `gads/`, no backwards
compatibility for C05-C10 experimental runners. Historical run evidence
is preserved separately for audit, but is not part of the product runtime.

- `gads/h00.py`: deterministic workpackage/state and synthetic budget.
- `gads/github_gateway.py`: bounded beforeOid GraphQL state gateway
  candidate; real atomic CAS and writer authority not deployed.
- `gads/j01_review.py`: proposed fresh-context independent AI reviewer
  evidence policy, *not* a live AI model invocation.
- `gads/writer_authority.py`: solo operator, strict required J-01 and
  source provenance rules, disabled historical workflow checks.
- `gads/writer_authority_probe.py`: read-only live GitHub inspection;
  intentionally fail-closed without active approved security controls.
- `gads/manifest.py`: complete Git tracked checkout SHA256 verification.

Local validation:
```bash
python3 -m gads.manifest verify --root .
python3 -m unittest discover -s tests -v
```

E1 and security workflows only use read-only GitHub credentials.
A second human GitHub account is NOT an architectural requirement;
one human authorizes merging, and J-01 independently evaluates exact
immutable changes. The secure J-01 runtime/check status is NOT deployed.

SEC-01 old writers are administratively disabled and historical branches
frozen; read-only SEC-02 review is still BLOCKED. See
`docs/security/solo-operator-j01-sec02.md`, `docs/project/`.
No production write, source main merge, token, paid AI bill, private
repository change or complete Mode C qualification is claimed.

## SEC-02.1 — J-01 executable candidate
Read-only `gads/j01_runtime.py` fetches and bounds an immutable GitHub
PR diff by exact SHA, sends it to loopback-only Ollama in fresh no-tools
context and emits a source-bound J-01 attestation. The proposed
`.github/workflows/j01-trusted-proposed.yml` MUST first be security
reviewed and explicitly adopted into protected main, and use an isolated
ephemeral runner. It is NOT yet deployed; no actual model invocation or
trusted reviewer status is claimed. See `docs/security/j01-runtime-v0.2.4.md`.

## SEC-02.2 public runner correction
The v0.2.4 proposed public GitHub self-hosted Actions workflow is
REMOVED from the clean candidate. Do not register an Actions runner.
`gads/j01_pull_only.py` uses only public GitHub GET and local Ollama
to generate an untrusted, non-authorizing observation; no tokens,
writer rights, required checks or protected main deployment.
See `docs/security/runner-threat-model-v0.2.5.md`.
