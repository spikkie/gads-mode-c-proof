# GitHub Autonomous Development Standard — clean H-00 baseline

**v0.2.2 development candidate · public synthetic only · NOT ADOPTED**

The canonical code in `gads/` is developed without backward compatibility
with C-05..C-10 proof runners. The old evidence and commit SHAs remain linked
in `docs/evidence/historical-index.md`; old branches have not been merged.

## Architecture

- `gads/h00.py`: pure deterministic workpackage and synthetic budget model.
- `gads/github_gateway.py`: bounded injectable GitHub Git-CAS gateway;
  fixed state ref, runner/source authority policy and independent GET of
  target-run metadata.
- `gads/readonly_probe.py`: live GET-only GitHub historical identity smoke.
- `gads/manifest.py`: SHA256 protection for the entire tracked checkout.
- `.github/workflows/quality.yml`: E1, with `contents:read` and
  `actions:read` only. **No privileged gateway invocation.**

## Validation

```bash
python3 -m gads.manifest verify --root .
python3 -m unittest discover -s tests -v
```

Live GitHub provenance smoke executes in Actions with a read-only token.
No Copilot upgrade, private account credential or third-party dependency is
required.

## Security status

A pinned policy permits H-00 gateway use only from approved protected-main
source, against one state ref. **Code-level scoping does not narrow GitHub
token privileges.** Actual live trusted-writer deployment remains blocked by
security issue #8 and independent reviewer/owner approval.

Correlated target attestation is a testable API contract in this candidate,
not live verified end-to-end. Real model costs, durable outbox, multi-run
recovery and full Mode C are **NOT PROVEN**.

0.2.2 requires GraphQL `updateRefs(beforeOid, afterOid)`. REST `force:false` alone is only fast-forward protection. Real write-token installation and GraphQL live proof remain blocked pending independent review.

## Writer authorization (v0.2.3)

The separate read-only writer-authority preflight intentionally reports
BLOCKED pending independent review, protected source branch controls, and a
dedicated synthetic state-only GitHub App installation. No write token is
available to feature-branch CI. See
`docs/security/writer-authorization-v0.2.3.md`.
