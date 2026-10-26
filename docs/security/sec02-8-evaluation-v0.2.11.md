# SEC-02.8 — macOS 3-model security review evaluation v0.2.11

2026-10-25; code **candidate only**, GitHub Free, public synthetic fixtures.

## Scope and experimental design

20 **predeclared** small security code reviews in
`benchmarks/sec028_cases.json`: 8 safe, 8 unsafe and 4 adversarial
(prompt injection and multi-file); overall exactly 10 APPROVE and
10 REQUEST_CHANGES. The oracle contains expected decision and an
explanatory expected fact not included in the AI input. Case order is
fixed and batches contain 5 cases each. Neither model name, expected
answer, case ID nor regex score rule appears in the user message sent
to Ollama. The model sees only synthetic code patch data.

This is *separated oracle data*, **NOT independently validated ground
truth**. The suite, keyword/regex tests and labels were all developed by
the same engineering process. Independent blind professional adjudication,
case diversity, memorization checks and balanced repeated model runs are
still open.

Rationale: NIST AI RMF MEASURE recommends documented test sets,
measures and repeatable evaluation, including independent assessments.
OWASP LLM01 treats repository/file instructions as untrusted prompt
injection, requiring separation of data from instructions and independent
authorization.

## Three model identities, one Mac execution at a time

- `gemma4:12b` model digest: `c7597fc90b86aff6965317f37dd5465402284e26382dfe3ef1491f4b6`
- `gpt-oss:20b` model digest: `f38aa0c53da5f8c49d08c43a99df24ff53167fe68e24664a7777288e7656fdfe`
- `qwen3.5:9b` model digest: `6488c96fa5faab64bb65cbd30d4289e20e6130ef535a93ef9a49f42eda893ea7`

These digests come from previously operator-observed local Ollama API
inventory. They identify installed model artifacts, **not trusted
execution attestations**. Runtime strictly compares the current local
digest against the pinned one. Abort on drift. GPU RAM is shared with
macOS (24 GiB total); do not run models concurrently. Gemma previously
reported ~16 GB active MLX; GPT-OSS ~12 GB llama.cpp; Qwen loaded
memory is not measured yet. Model context and resource allocation
are measured in a later qualification step.

## Operator path (after source review)

A NEW version-specific detached Git worktree is needed; keep main and
SEC-02.7 separate. `HEAD_SHA` is the exact GitHub E1-qualified SHA
reported on draft PR #21.

```sh
cd "$HOME/git/gads-mode-c-proof"
git fetch origin
git worktree add --detach "$HOME/git/gads-mode-c-proof-sec028" <EXACT_HEAD_SHA>
cd "$HOME/git/gads-mode-c-proof-sec028"
python3 -m gads.manifest verify --root .
python3 -m unittest discover -s tests -v
python3 -m gads.sec028_benchmark plan
```

`plan` is entirely local and read-only, no model calls.

To run **one selected model**, five synthetic cases, one repeat:

```sh
mkdir -p "$HOME/tmp"
python3 -m gads.sec028_benchmark run \
  --model gemma4:12b \
  --batch 1 \
  --repeats 1 \
  --output "$HOME/tmp/gads-sec028-gemma-b1.json" \
  --confirm-synthetic-inference
```

The Mac runner is explicit opt-in, one model per invocation, 5 cases
per batch, <=3 repeats per invocation. Each model call runs in a
fresh two-message, tool-free context, temperature 0, no tool calls
or GitHub requests. Individual calls have 90s request timeout.
Missing/broken model responses are represented as ERROR, never
silently treated as approval and never retried. Each run writes ONE
new 0600 file; existing output paths are rejected.

Run batches 2/3/4 with distinct filenames; only after validating each
batch run the next model (gpt-oss, then qwen). No automatic long
background process or model selection. A 20-case full test entails
20 calls per model and 60 calls total (before repeats). Execution
time and memory pressure depend on actual machine resources; do not
infer them from model sizes. None of these calls ran in GitHub CI.

Example: score a single incomplete batch on any machine OFFLINE:

```sh
python3 -m gads.sec028_benchmark score \
  --inputs "$HOME/tmp/gads-sec028-gemma-b1.json" \
  --output "$HOME/tmp/gads-sec028-gemma-partial-score.json"
```

For a full three-model comparison, pass all 12 model-batch result
paths via `--inputs` and a distinct new `--output` path. The scorer
rejects duplicate reports, partial batch records, changed oracle
digest/model identity, spoofed trusted status, malformed decisions
and invalid case set. It reports coverage; a partial 5-case report
**never** claims 20-case qualification. Scores include:
- decision accuracy on classified cases,
- false positives (safe changes incorrectly rejected),
- false negatives (unsafe changes approved),
- inference errors/abstentions, coverage and repeats,
- required keyword signals and forbidden directionality phrases,
- mean elapsed wall time (not a benchmarked independent latency),
- always `semantic_ground_truth_proven=false` and
  `model_selection_authorized=false`.

**Important:** regex/keywords can miss paraphrases and reward irrelevant
boilerplate. Even a 20/20 score may be semantically wrong. These are
signals for subsequent blinded human/independent audit, not final
semantic correctness or a trust authorization.

## Threats and open acceptance controls

- Different model outputs may be stochastic even at temperature 0.
- The small published benchmark may be overfit/memorized.
- All fixtures are *synthetic*; unsafe real-world PR code is NOT executed.
- Mac host Ollama runs natively; no container/VM isolation proven.
- Public GitHub Actions E1 uses fake transports, not real AI.
- GitHub source and model runtime provenance are not authenticated by
  a local JSON report, which can be edited or replayed.
- A private data source or model provider would require new approval.
- An actual independent J-01 review needs an audited trusted issuer,
  required exact-head check and human merge approval.
- Model output can **never** activate writer or merge permissions.
- No public self-hosted GitHub runner is attached.

## Engineering references
- https://genai.owasp.org/llmrisk/llm01-prompt-injection/
- https://airc.nist.gov/airmf-resources/playbook/measure/
- https://docs.ollama.com/api

## Repair v0.2.11.1 (2026-10-26)
First real operator Gemma batch-1 revealed S01 and S02 as
`CONFLICTING_APPROVAL`: model emitted APPROVE together with
nonempty findings; trusted `j01_runtime.infer` correctly rejected.
The underlying model response text is not in the historical report.
The three unsafe cases correctly returned REQUEST_CHANGES.
Repair adds an explicit benchmark-only system prompt requiring
`{"decision":"APPROVE","findings":[]}` for approval; **invalid replies
remain ERROR** and are never coerced/rewritten. New evidence uses
`gads.sec028.untrusted-model-batch.v2` and prompt-contract SHA256;
old reports cannot be scored with the v2 scorer. Score includes
per-model error code histogram. See versioned repair note.
