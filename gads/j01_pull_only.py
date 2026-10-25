"""SEC-02.2: pull-only local J-01 review OBSERVATION, never authorization.

Public synthetic source only. No GitHub Actions runner registration or secrets.
No credentialed GitHub calls or GitHub writes. A local observation is deliberately
NOT a trusted GitHub workflow attestation or owner approval.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
from gads import j01_runtime as runtime
from gads import j01_batches as batching

SCHEMA = "gads.j01-local-observation.v1"
UNSAFE_ENV = (
    "GITHUB_TOKEN", "GH_TOKEN", "GITHUB_APP_TOKEN", "GH_ENTERPRISE_TOKEN",
    "GADS_WRITER_TOKEN", "GADS_APP_PRIVATE_KEY",
)


def check_environment(environ):
    if any(environ.get(name) for name in UNSAFE_ENV):
        raise runtime.ReviewBlocked("CREDENTIALS_PRESENT_IN_REVIEWER_ENV")
    if environ.get("GITHUB_ACTIONS"):
        raise runtime.ReviewBlocked("GITHUB_ACTIONS_RUNNER_NOT_ALLOWED")
    return True


def observe(get, model_call, *, pr, expected_head, model):
    """One model invocation, GitHub GET only, no trust-emitting side effect."""
    before, digest = runtime.snapshot(get, pr, expected_head,
                                      max_bytes=batching.MAX_TOTAL_BYTES)
    batches = batching.partition(before)
    decisions = []
    for batch in batches:
        verdict = runtime.infer(model_call, model, batch)
        decisions.append({
            "batch_index": batch["batch_index"],
            "sha256": batching.batch_digest(batch),
            "decision": verdict["decision"],
            "findings": verdict["findings"]
        })
    after, after_digest = runtime.snapshot(get, pr, expected_head,
                                          max_bytes=batching.MAX_TOTAL_BYTES)
    if before != after or digest != after_digest:
        raise runtime.ReviewBlocked("PR_CHANGED_DURING_LOCAL_INFERENCE")
    if len(decisions) != len(batches):
        raise runtime.ReviewBlocked("INCOMPLETE_MODEL_COVERAGE")
    approved = all(x["decision"] == "APPROVE" for x in decisions)
    aggregated = [
        f"batch {x['batch_index']}/{len(decisions)}: {finding}"
        for x in decisions for finding in x["findings"]
    ]
    return {
        "schema": SCHEMA,
        "reviewer": "J-01",
        "trust_level": "UNTRUSTED_LOCAL_OBSERVATION",
        "decision": "APPROVE" if approved else "REQUEST_CHANGES",
        "findings": aggregated,
        "review_batches": decisions,
        "reviewed_file_count": len(before["files"]),
        "review_batch_count": len(batches),
        "pr_number": pr,
        "reviewed_head": expected_head,
        "base_head": before["base_head"],
        "diff_sha256": digest,
        "model": model,
        "writer_authorized": False,
        "required_status_issued": False,
        "owner_approval_recorded": False
    }


def parse_cli(argv=None):
    cli = argparse.ArgumentParser(description="Synthetic J-01 observation, no writer authority")
    cli.add_argument("--pr", type=int, required=True)
    cli.add_argument("--head", required=True)
    cli.add_argument("--model", default="gemma4:12b")
    cli.add_argument("--output", default="j01-local-observation.json")
    return cli.parse_args(argv)


def main(argv=None, environ=None):
    env = os.environ if environ is None else environ
    check_environment(env)
    args = parse_cli(argv)

    def get(path):
        return runtime.request_json("https://api.github.com/repos/" + runtime.REPO + path)

    def model_call(payload):
        return runtime.request_json(runtime.OLLAMA_URL, data=payload, timeout=90)

    # Do not create or overwrite a file unless the entire GET and model
    # verification completes, and never write into the repository automatically.
    report = observe(get, model_call, pr=args.pr, expected_head=args.head, model=args.model)
    dest = Path(args.output)
    if not dest.is_absolute() or dest.suffix != ".json" or dest.is_symlink():
        raise runtime.ReviewBlocked("OUTPUT_MUST_BE_NEW_ABSOLUTE_JSON_FILE")
    if len(runtime.canonical(report)) > 8192:
        raise runtime.ReviewBlocked("OBSERVATION_SIZE_LIMIT")
    payload = runtime.canonical(report) + b"\n"
    fd = os.open(dest, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        with os.fdopen(fd, "wb") as result:
            result.write(payload)
    except BaseException:
        try:
            dest.unlink()
        except OSError:
            pass
        raise
    print("LOCAL_OBSERVATION_ONLY head=" + args.head +
          " decision=" + report["decision"] + " path=" + str(dest))


if __name__ == "__main__":
    main()
