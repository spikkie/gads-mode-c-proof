# SEC-02.8 v0.2.11.1 — Approval output contract repair

Date 2026-10-26. Candidate only. All test data public and synthetic.

## Root cause observed
Operator invoked the five-case Gemma batch on native macOS.
S01 (owner validation) and S02 (cost ceiling tightening) had expected
APPROVE but returned `CONFLICTING_APPROVAL`. The strict J-01 parser
only produces this diagnostic when a model sends `decision=APPROVE`
with nonempty `findings`. The actual raw model findings for these
two responses were NOT retained, and cannot be reconstructed.
The report faithfully retained both as ERROR. U01/A01/U02 were
correct REQUEST_CHANGES with technically relevant findings.
Historical score stays 3 decision-correct, 2 errors, zero FP/FN
in the schema-valid subset.

## Bounded repair (evaluation only)
- Do not modify canonical `gads/j01_runtime.py` or its strict validation.
- Additional instructions are appended only to the benchmark's system
  message: APPROVE must have `findings=[]`, no rationale in findings;
  REQUEST_CHANGES must cite concrete factual security issues.
- No second turn, retry, hidden repair prompt, JSON coercion, or
  reinterpretation of original model answers is permitted.
- A report uses v2 schema with `prompt_contract_sha256`; matching v2
  scorer recomputes fingerprint and rejects v1/mismatched reports.
- Per-model `error_codes` makes contract failures visible rather than
  silently reducing them to a 'model accuracy' decision.
- Dataset `benchmarks/sec028_cases.json` remains byte-for-byte unchanged,
  so this is a protocol repair, not a revised expected-label oracle.
- Source model-identity checks, 0600 new output, one model/one batch,
  explicit consent and no token/tool privilege constraints remain.

## Operator workflow
In a new detached Git worktree on the exact E1-qualified SHA:

```sh
python3 -m gads.manifest verify --root .
python3 -m gads.sec028_benchmark plan
python3 -m gads.sec028_benchmark run \
  --model gemma4:12b --batch 1 --repeats 1 \
  --output "$HOME/tmp/gads-sec028-gemma-b1-v2.json" \
  --confirm-synthetic-inference
python3 -m gads.sec028_benchmark score \
  --inputs "$HOME/tmp/gads-sec028-gemma-b1-v2.json" \
  --output "$HOME/tmp/gads-sec028-gemma-b1-v2-score.json"
python3 -m json.tool "$HOME/tmp/gads-sec028-gemma-b1-v2-score.json"
```

These are **five actual new local Ollama inference calls** at operator's
discretion, not an automated continuous job. If the model still supplies
conflicting responses, classify as model contract unreliability and
investigate further; do not automatically retry. Avoid simultaneous
models on the 24 GiB Mac.

## Remaining non-goals
- No claim of independent semantic benchmark truth.
- No replay/identity evidence trusted beyond local untrusted JSON.
- No local/guest OS-isolated AI process proven.
- No trusted GitHub status, signing key, source merge or state writer.
- This repair does NOT transform a local model into trusted J-01.
