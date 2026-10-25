# GitHub Autonomous Development Standard — clean H-00 baseline

**v0.2.0 development candidate · public synthetic only · NOT ADOPTED**

This candidate is based directly on the protected `main` baseline and does not
include the stacked C-06–C-10 temporary implementations. We intentionally
replace the historical C-05 proof runtime in this candidate; original immutable
commits and Actions runs remain indexed in `docs/evidence/historical-index.md`.

## One canonical implementation

- `gads/h00.py`: deterministic, pure H-00 state machine
- `gads/manifest.py`: complete tracked-file SHA256 verification
- `.github/workflows/quality.yml`: read-only GitHub Actions E1
- `tests/`: negative and positive qualification tests

No deprecated adapters, old module imports, or temporary runtime workflows.

The H-00 model reserves **synthetic** budget before external effects. Uncertain
acknowledgements and expired leases enter `UNKNOWN` and cannot blindly retry.
Replay is idempotent only for identical request IDs and payloads. Correlation,
repository/workflow ID, source SHA and outcome must agree before completion.

This is a **pure in-memory model**. A separately approved trusted gateway must
implement durable Git CAS, independent live GitHub attestation, real model
spend accounting, privileged credential isolation and cross-run scheduling.
The caller must NOT treat arbitrary untrusted target metadata as authentication.

## Validate

```bash
python3 -m gads.manifest verify --root .
python3 -m unittest discover -s tests -v
```

No paid AI or third-party Python dependency is needed for E1. GitHub Free is
sufficient for these public read-only tests.

**Security and adoption:** issue #8 remains open. No automatic merge, protected
main writes, private sources, credentials, deployments or customer data.
