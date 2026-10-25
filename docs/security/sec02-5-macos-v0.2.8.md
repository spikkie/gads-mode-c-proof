# SEC-02.5 — Mac development host and real-runtime prerequisites

**Mac OS is the developer workstation. This document is a security plan, not proof of a deployed sandbox.**

## Architecture and trust
A) macOS operator acquires only *public synthetic* immutable GitHub PR data through read-only GET.
B) Separate Linux guest VM using Podman Machine or Lima, with no Mac home/work mounts, no host socket, no host-loopback route and no external internet egress. The input is independently SHA-pinned data transferred without shared host volumes. Guest-local Ollama is the baseline for trusted isolation; host Ollama is not transparently available at guest 127.0.0.1.
C) Result leaves VM explicitly as an **UNTRUSTED_LOCAL_OBSERVATION**. Only a separate audited owner-approved verifier/issuer can authenticate provenance later. No GitHub write credentials in guest or Mac model context.

## macOS facts
Podman containers on macOS run inside an underlying Linux VM. Lima defaults may expose a read-only host home mount (still data exposure), and Lima user-mode networking may reach Mac host-loopback via host.lima.internal unless controlled. Podman virtualized environments may resolve host.containers.internal. Inspect and negatively test all paths: configuration alone is insufficient. Ollama typically binds Mac 127.0.0.1:11434, which is not VM loopback. **Never change host Ollama to 0.0.0.0 as a shortcut.**

## Read-only inventory
After reviewing this candidate source on the Mac, run:
```sh
python3 -m gads.sec025_macos preflight
```
It uses Python platform APIs and shutil.which ONLY. It executes no external tools, produces no token values or host identifiers and never marks itself security-approved. Presence of Podman/Lima is not evidence a VM exists, runs or is isolated. An inventory can report BLOCKED even though source E1 tests pass. The Mac can optionally run the existing pull-only local reviewer with host Ollama and public synthetic PR content, but that experiment is **not** trusted and cannot satisfy J-01 DoD.

Independent manual read-only diagnostics, if tools are installed:
```sh
sw_vers
uname -m
command -v podman
command -v limactl
command -v ollama
podman machine list --format json
ollama list
```
Do not paste unredacted company/user machine mounts, paths, tokens, host IDs or network details into public PRs. Run only tools that exist and only where employer policy permits.

## Open acceptance gate
- [ ] Mac preflight actually executed and operator evaluated.
- [ ] Independently audited offline VM creation/runner code; explicit operator approval before installation.
- [ ] VM host-mount absence, host loopback denied, internet egress denied, model guest local, secrets absent: *actual* negative probes.
- [ ] Truly separate fresh-context independent J-01 code review on exact source SHA and real Ollama results.
- [ ] Separate authenticated status issuer, challenge anti-replay, exact PR SHA, human-only main merge.
- [ ] Writer authorization remains BLOCKED until all mandatory controls are satisfied.

Sources:
https://docs.podman.io/en/latest/markdown/podman-machine.1.html
https://lima-vm.io/docs/usage/
https://lima-vm.io/docs/config/network/user/
https://github.com/ollama/ollama/blob/main/docs/faq.mdx
