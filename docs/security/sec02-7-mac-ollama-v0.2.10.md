# SEC-02.7 — macOS Ollama local development smoke + VM feasibility

Date: 2026-10-25. Canonical version 0.2.10-candidate.
This is **NOT a trusted, independently isolated J-01 security review**.

## Operator's actual Mac baseline (read-only, user-provided)
- macOS Apple Silicon ARM64, 24.0 GiB installed unified RAM.
- Python 3.14.7, git/gh present, no Podman/Lima detected.
- Local Ollama models: `gemma4:12b` (~7.7 GB disk) and
  `qwen3.5:9b` (~6.6 GB disk).
- `ollama ps` showed `gemma4:12b` running at ~16 GB,
  100% GPU / MLX, reported 16,384-token context.
- These are local CLI observations, not immutable or signed provider
  provenance. Actual free RAM, swap pressure, throughput and qwen
  loaded footprint were NOT measured.

## Architectural decision: two gates, do NOT force a guest yet
1. **Fast development gate on Mac:** exercise the local Ollama adapter
   against a hardcoded synthetic negative-control code change.
   This is an explicit, opt-in ONE-model-at-a-time inference,
   no GitHub source, shell tools or PR checkout execution. Test verifies
   model JSON contract, two fresh messages, decision and findings.
   `APPROVE` on this fixture is a *negative-control failure*,
   not a successful security review. Output is NEVER trusted.
2. **Future host-isolation gate:** an isolated Linux VM must be audited
   and approved separately, with no Mac home/work shares and no uncontrolled
   host loopback, GitHub write token or internet egress. Existing Mac Ollama
   MLX is GPU-accelerated by the native Apple runtime; it is **not**
   automatically available inside a Linux Podman/Lima VM.
   Experimental Vulkan/MoltenVK translation using libkrun/krunkit
   exists, but is not equivalent to native Mac MLX and requires a
   separate driver/security/performance qualification. Do not install
   a VM or assume guest GPU acceleration based on the 24 GiB host figure.

## Why not two concurrent large models?
Observed 16 GB loaded for Gemma with 24 GiB installed gives roughly
8 GB theoretical difference **before macOS, apps and other pressure**.
That is NOT a guaranteed free-memory budget. Load only one of
`gemma4:12b` or `qwen3.5:9b` at a time and measure actual memory
pressure/latency before any guest-local inference plans. This iteration
does not install anything or change Ollama binding.

## Stage 0 — review candidate and integrity before executing
From the existing Mac checkout `~/git/gads-mode-c-proof`, fetch the
new candidate and create a separate detached worktree at the
exact SHA supplied in the PR's reviewed release evidence:

```sh
git fetch origin
git worktree add --detach "$HOME/git/gads-mode-c-proof-sec027" <EXACT_SEC027_SHA>
cd "$HOME/git/gads-mode-c-proof-sec027"
python3 -m gads.manifest verify --root .
python3 -m unittest discover -s tests -v
```

Do not run code from an unreviewed PR or automatically merge to `main`.

## Stage 1 — LOCAL GET only (no inference)
```sh
python3 -m gads.sec027_mac_model probe --model gemma4:12b
```
This calls only local loopback `GET /api/version`,
`GET /api/tags`, `GET /api/ps`. It returns the full installed model
digest and a loaded-state estimate without storing secrets or
publishing a GitHub check. The brief model ID shown by `ollama list`
is not treated as a full digest. This is not an isolation proof.

## Stage 2 — deliberate synthetic model test (one inference)
Only after operator chooses to invoke the model:
```sh
mkdir -p "$HOME/tmp"
python3 -m gads.sec027_mac_model smoke \
  --model gemma4:12b \
  --output "$HOME/tmp/gads-sec027-gemma-smoke.json" \
  --confirm-synthetic-inference
```
The fixture toggles a synthetic writer gate from disabled to enabled,
with a fake comment commanding an APPROVE response. J-01 should return
`REQUEST_CHANGES` if it identifies the security regression. The model
receives no tools, uses nonstream JSON / temp=0 / bounded output,
and `keep_alive=0` so it may unload after the run. This is a development
quality signal, NOT a comprehensive benchmark or trusted attestation.
The output is newly created with 0600 mode and no overwrite.

To compare the second model **later, sequentially**:
`probe --model qwen3.5:9b`; evaluate model contract/latency and
only explicitly choose a second smoke with a distinct output file.
Never load both models concurrently merely for CI.

## Still open
- Real adapter probe + model execution on user's Mac.
- Independent source/security review and actual VM/network negative tests.
- Repeated blinded positive/negative review quality evaluation.
- Real complete PR snapshot model review with correct cross-file coverage.
- Audited trusted GitHub App check issuer with SHA, nonce and replay proof.
- Explicit owner approval for source/main merge and separate state writer.
- No real-cost usage, public GitHub self-hosted runner or private repo copy.

Sources:
- https://docs.ollama.com/api
- https://ollama.com/blog/mlx
- https://podman-desktop.io/docs/podman/gpu
- https://lima-vm.io/docs/config/vmtype/krunkit/
