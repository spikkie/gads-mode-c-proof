# GADS - canonical H-00, GitHub Free synthetic qualification

**v0.2.3 SEC-02 development candidate - NOT ADOPTED**

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
