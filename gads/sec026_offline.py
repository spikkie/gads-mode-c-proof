"""SEC-02.6: bounded public-GitHub -> offline Linux-guest J-01 handoff.

A package is UNTRUSTED even with consistent hashes: hashes are not
signatures and anonymous public GET cannot prove an authorized issuer.
EXPORT: read-only public GitHub GET on Mac, no model access.
REVIEW: local Ollama inside isolated guest, NO GitHub network access.
Neither phase issues checks, tokens, writer rights or adoption.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
from gads import j01_runtime as rt
from gads import j01_batches as batches
from gads import j01_pull_only as pull

PACKAGE_SCHEMA = "gads.sec026.offline-package.v1"
RESULT_SCHEMA = "gads.sec026.offline-observation.v1"
MAX_PACKAGE_BYTES = 100000
MAX_RESULT_BYTES = 16000


def digest(obj):
    return hashlib.sha256(rt.canonical(obj)).hexdigest()


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise rt.ReviewBlocked("DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def prepare(get, pr, head):
    snapshot, sha = rt.snapshot(get, pr, head,
                                max_bytes=batches.MAX_TOTAL_BYTES)
    parts = batches.partition(snapshot)
    return {
        "schema": PACKAGE_SCHEMA, "class": "UNTRUSTED_SYNTHETIC_INPUT",
        "repository": rt.REPO, "pr": pr, "reviewed_head": head,
        "base_head": snapshot["base_head"], "diff_sha256": sha,
        "batch_digests": [batches.batch_digest(x) for x in parts],
        "snapshot": snapshot, "github_provenance_authenticated": False,
        "trusted_reviewer": False, "writer_authorized": False,
    }


def verify_package(package, *, pr, head):
    if type(pr) is not int or pr <= 0 or not isinstance(head, str) or not rt.SHA.fullmatch(head):
        raise rt.ReviewBlocked("INVALID_EXPECTED_PR_OR_SHA")
    if not isinstance(package, dict) or len(rt.canonical(package)) > MAX_PACKAGE_BYTES:
        raise rt.ReviewBlocked("INVALID_PACKAGE_SIZE_OR_TYPE")
    if set(package) != {
            "schema", "class", "repository", "pr", "reviewed_head",
            "base_head", "diff_sha256", "batch_digests", "snapshot",
            "github_provenance_authenticated", "trusted_reviewer",
            "writer_authorized"}:
        raise rt.ReviewBlocked("UNKNOWN_PACKAGE_FIELDS")
    if (package["schema"] != PACKAGE_SCHEMA or
            package["class"] != "UNTRUSTED_SYNTHETIC_INPUT" or
            package["repository"] != rt.REPO or
            package["pr"] != pr or type(package["pr"]) is not int or
            package["reviewed_head"] != head or
            not isinstance(package["base_head"], str) or
            not rt.SHA.fullmatch(package["base_head"])):
        raise rt.ReviewBlocked("PACKAGE_IDENTITY_MISMATCH")
    if any(package[k] is not False for k in
           ("github_provenance_authenticated", "trusted_reviewer", "writer_authorized")):
        raise rt.ReviewBlocked("FORGED_PACKAGE_TRUST")
    snap = package["snapshot"]
    if not isinstance(snap, dict) or set(snap) != {
            "schema", "repository", "pr_number", "base_head",
            "reviewed_head", "files"}:
        raise rt.ReviewBlocked("INVALID_SNAPSHOT_SCHEMA")
    if (snap["schema"] != "gads.j01-diff.v1" or
            snap["repository"] != rt.REPO or
            snap["pr_number"] != pr or type(snap["pr_number"]) is not int or
            snap["reviewed_head"] != head or
            snap["base_head"] != package["base_head"]):
        raise rt.ReviewBlocked("SNAPSHOT_IDENTITY_MISMATCH")
    files = snap["files"]
    if not isinstance(files, list) or len(files) > rt.MAX_FILES or not files:
        raise rt.ReviewBlocked("INVALID_FILESET")
    seen = set()
    for f in files:
        if not isinstance(f, dict) or set(f) != {
                "path", "status", "patch", "additions", "deletions"}:
            raise rt.ReviewBlocked("INVALID_FILE_RECORD")
        path, patch = f["path"], f["patch"]
        if (not isinstance(path, str) or not path or len(path) > 200 or
                path.startswith("/") or ".." in path.split("/") or path in seen or
                f["status"] not in ("added", "modified", "removed") or
                not isinstance(patch, str) or not patch.startswith("@@ ")):
            raise rt.ReviewBlocked("UNSAFE_OR_INCOMPLETE_PATCH")
        seen.add(path)
        added, removed = f["additions"], f["deletions"]
        if (type(added) is not int or type(removed) is not int or
                added < 0 or removed < 0):
            raise rt.ReviewBlocked("INVALID_PATCH_COUNTS")
        lines = patch.splitlines()
        actual_adds = sum(s.startswith("+") and not s.startswith("+++") for s in lines)
        actual_dels = sum(s.startswith("-") and not s.startswith("---") for s in lines)
        if (actual_adds, actual_dels) != (added, removed):
            raise rt.ReviewBlocked("TRUNCATED_OFFLINE_PATCH")
    if [f["path"] for f in files] != sorted(seen):
        raise rt.ReviewBlocked("NON_CANONICAL_FILE_ORDER")
    if len(rt.canonical(snap)) > batches.MAX_TOTAL_BYTES:
        raise rt.ReviewBlocked("TOTAL_DIFF_BUDGET")
    if package["diff_sha256"] != digest(snap):
        raise rt.ReviewBlocked("DIFF_DIGEST_MISMATCH")
    parts = batches.partition(snap)
    if package["batch_digests"] != [
            batches.batch_digest(p) for p in parts]:
        raise rt.ReviewBlocked("BATCH_DIGEST_MISMATCH")
    return parts


def offline_review(package, model_call, *, pr, head, model):
    parts = verify_package(package, pr=pr, head=head)
    results = []
    for p in parts:
        verdict = rt.infer(model_call, model, p)
        results.append({
            "index": p["batch_index"],
            "batch_sha256": batches.batch_digest(p),
            "decision": verdict["decision"],
            "findings": verdict["findings"]})
    if len(results) != len(parts):
        raise rt.ReviewBlocked("INCOMPLETE_MODEL_COVERAGE")
    return {
        "schema": RESULT_SCHEMA, "class": "UNTRUSTED_LOCAL_OBSERVATION",
        "repository": rt.REPO, "pr": pr, "reviewed_head": head,
        "base_head": package["base_head"],
        "diff_sha256": package["diff_sha256"],
        "package_sha256": digest(package),
        "model": model, "model_batches": results,
        "decision": ("APPROVE" if all(
            v["decision"] == "APPROVE" for v in results) else "REQUEST_CHANGES"),
        "covered_files": len(package["snapshot"]["files"]),
        "covered_batches": len(results),
        "independent_review_proven": False, "trusted_status_issued": False,
        "owner_approval": False, "writer_authorized": False,
    }


def _absolute_path(value):
    path = Path(value)
    if not path.is_absolute() or path.is_symlink():
        raise rt.ReviewBlocked("INVALID_ABSOLUTE_PATH")
    return path


def _write_new(target, document, limit):
    path = _absolute_path(target)
    raw = rt.canonical(document) + b"\n"
    if len(raw) > limit:
        raise rt.ReviewBlocked("OUTPUT_SIZE_LIMIT")
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(str(path), flags, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(raw)


def _read_package(source):
    path = _absolute_path(source)
    fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as f:
        data = f.read(MAX_PACKAGE_BYTES + 2)
    if len(data) > MAX_PACKAGE_BYTES + 1:
        raise rt.ReviewBlocked("PACKAGE_FILE_TOO_LARGE")
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=_pairs)
    except (ValueError, UnicodeError) as exc:
        raise rt.ReviewBlocked("INVALID_PACKAGE_JSON") from exc


def main(argv=None, environ=None):
    parser = argparse.ArgumentParser(description="Public synthetic offline J-01 handoff only")
    sub = parser.add_subparsers(dest="stage", required=True)
    for stage in ("export", "review"):
        p = sub.add_parser(stage)
        p.add_argument("--pr", type=int, required=True)
        p.add_argument("--head", required=True)
        p.add_argument("--output", required=True)
        if stage == "review":
            p.add_argument("--input", required=True)
            p.add_argument("--model", required=True)
    args = parser.parse_args(argv)
    env = os.environ if environ is None else environ
    pull.check_environment(env)
    if args.stage == "export":
        def github_get(path):
            return rt.request_json("https://api.github.com/repos/" + rt.REPO + path)
        package = prepare(github_get, args.pr, args.head)
        verify_package(package, pr=args.pr, head=args.head)
        _write_new(args.output, package, MAX_PACKAGE_BYTES)
        print("UNTRUSTED_OFFLINE_PACKAGE_EXPORTED sha256=" + digest(package))
    else:
        package = _read_package(args.input)
        # No GitHub GET/POST in guest evaluation stage; model loopback only.
        def model_call(payload):
            return rt.request_json(rt.OLLAMA_URL, data=payload, timeout=90)
        result = offline_review(package, model_call, pr=args.pr,
                                head=args.head, model=args.model)
        _write_new(args.output, result, MAX_RESULT_BYTES)
        print("UNTRUSTED_OFFLINE_MODEL_OBSERVATION decision=" + result["decision"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
