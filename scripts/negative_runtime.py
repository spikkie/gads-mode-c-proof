#!/usr/bin/env python3
"""Hosted C-05 fail-closed probes. Read-only network; no publisher mutation."""
import json
import tempfile
import urllib.request
from pathlib import Path

from scripts.qualify import SOURCE, PROOF, Rejected, digest, stage, preflight
from scripts.publish import API, run

ROOT = Path.cwd()
SOURCE_SHA = "43cb1e6924d208288350d70b7b273f7cd3def0c4"
REPO = "spikkie/gads-mode-c-proof"
COUNT = 0


def blocked(label, expected, action):
    global COUNT
    try:
        action()
    except Rejected as error:
        if str(error) != expected:
            raise AssertionError(f"{label}: wrong rejection {error} (expected {expected})") from error
        COUNT += 1
        print(f"NEGATIVE_PASS {label} {expected}")
        return
    raise AssertionError(f"{label}: unexpectedly accepted")


def read_public(path):
    req = urllib.request.Request(
        "https://api.github.com/repos/" + REPO + path,
        headers={"Accept": "application/vnd.github+json", "User-Agent": "gads-c05-read-only-qualification"})
    with urllib.request.urlopen(req, timeout=20) as response:
        return json.load(response)


class NoWrites:
    def __init__(self, protected=True, stale=False):
        self.protected = protected
        self.stale = stale
        self.calls = []

    def call(self, method, path, body=None):
        self.calls.append((method, path))
        if method != "GET":
            raise AssertionError("UNEXPECTED_WRITE_CALL")
        if path == "":
            return {"private": False}
        if path == "/branches/main":
            return {"protected": self.protected}
        if path == "/git/ref/heads/main":
            return {"object": {"sha": "0" * 40 if self.stale else SOURCE_SHA}}
        raise AssertionError("unexpected GET: " + path)


def main():
    main_branch = read_public("/branches/main")
    if main_branch["protected"] is not True or main_branch["commit"]["sha"] != SOURCE_SHA:
        raise AssertionError("LIVE_MAIN_PROTECTION_OR_SHA")
    rules = read_public("/rulesets")
    if not any(r["name"] == "protect-main" and r["enforcement"] == "active" for r in rules):
        raise AssertionError("LIVE_RULESET_ABSENT")
    pr = read_public("/pulls/2")
    if pr["draft"] is not True or pr["merged"] is not False or pr["base"]["ref"] != "main":
        raise AssertionError("LIVE_DRAFT_METADATA")
    files = read_public("/pulls/2/files?per_page=100")
    if {f["filename"] for f in files} != {PROOF, "SHA256SUMS"}:
        raise AssertionError("LIVE_PR_FILESET")
    print("LIVE_READONLY_PASS protected_main active_ruleset draft_pr_2 two_files")

    with tempfile.TemporaryDirectory(prefix="c05-negative-") as tempdir:
        tmp = Path(tempdir)
        worker, e1, reviewer, out = (
            tmp / "worker.py", tmp / "qa.sha", tmp / "review.txt", tmp / "staged")
        worker.write_bytes(SOURCE)
        sha = digest(SOURCE)
        e1.write_text(sha + "  worker.py\n", encoding="ascii")
        reviewer.write_text("GADS_J01_APPROVE_" + sha + "\n", encoding="ascii")
        stage(ROOT, worker, e1, reviewer, SOURCE_SHA, out)
        preflight(ROOT, out, SOURCE_SHA)
        print("POSITIVE_FIXTURE_PASS sha_bound_preflight")

        original = (out / PROOF).read_bytes()
        (out / PROOF).write_bytes(original + b"TAMPER")
        blocked("tampered_proof", "PROOF_HASH",
                lambda: preflight(ROOT, out, SOURCE_SHA))
        (out / PROOF).write_bytes(original)

        original = (out / "evidence.json").read_bytes()
        report = json.loads(original)
        report["allowed_files"].append("forbidden.txt")
        (out / "evidence.json").write_text(json.dumps(report), encoding="utf-8")
        blocked("tampered_evidence", "EVIDENCE_REPORT",
                lambda: preflight(ROOT, out, SOURCE_SHA))
        (out / "evidence.json").write_bytes(original)

        (out / "unapproved.txt").write_text("synthetic", encoding="ascii")
        blocked("extra_staged_file", "STAGE_FILESET",
                lambda: preflight(ROOT, out, SOURCE_SHA))
        (out / "unapproved.txt").unlink()

        blocked("wrong_proof_source_sha", "PROOF_UNBOUND",
                lambda: preflight(ROOT, out, "0" * 40))

        badreview = tmp / "reject.txt"
        badreview.write_text("GADS_J01_REJECT\n", encoding="ascii")
        blocked("reviewer_rejection", "J01_REJECT_OR_UNBOUND",
                lambda: stage(ROOT, worker, e1, badreview, SOURCE_SHA, tmp / "badreview-out"))

        bade1 = tmp / "wrongqa.sha"
        bade1.write_text("0" * 64 + "  worker.py\n", encoding="ascii")
        blocked("invalid_e1", "E1_NOT_BOUND",
                lambda: stage(ROOT, worker, bade1, reviewer, SOURCE_SHA, tmp / "bade1-out"))

        badworker = tmp / "malformed.py"
        badworker.write_text("def is_even(n):\n    return True\n", encoding="ascii")
        blocked("worker_defect", "WORKER_OUTPUT_NOT_QUALIFIED",
                lambda: stage(ROOT, badworker, e1, reviewer, SOURCE_SHA, tmp / "badworker-out"))

        blocked("wrong_repository", "WRONG_SYNTHETIC_REPOSITORY",
                lambda: run(NoWrites(), ROOT, out, SOURCE_SHA, "refs/heads/main", "example/other"))
        blocked("wrong_ref", "UNTRUSTED_BASE_REF",
                lambda: run(NoWrites(), ROOT, out, SOURCE_SHA, "refs/heads/untrusted", REPO))

        no_protection = NoWrites(protected=False)
        blocked("unprotected_main", "MAIN_NOT_PROTECTED",
                lambda: run(no_protection, ROOT, out, SOURCE_SHA, "refs/heads/main", REPO))
        if any(m != "GET" for m, _ in no_protection.calls):
            raise AssertionError("UNPROTECTED_REF_WRITE_ATTEMPT")

        stale = NoWrites(stale=True)
        blocked("stale_main", "BASE_MOVED",
                lambda: run(stale, ROOT, out, SOURCE_SHA, "refs/heads/main", REPO))
        if any(m != "GET" for m, _ in stale.calls):
            raise AssertionError("STALE_BASE_WRITE_ATTEMPT")
        blocked("missing_token", "NO_TOKEN", lambda: API(REPO, None))
        preflight(ROOT, out, SOURCE_SHA)

    if COUNT != 12:
        raise AssertionError(f"EXPECTED_12_NEGATIVES_GOT_{COUNT}")
    print(f"NEGATIVE_RUNTIME_PASS count={COUNT} runner=github_hosted network=GET_only publisher_writes=0")


if __name__ == "__main__":
    main()
