#!/usr/bin/env python3
"""C-09 trusted workflow_run *admission-only* security candidate.

No mutations, dispatches, artifact downloads, untrusted checkouts, or token writes.
Only a historically verified public synthetic failure may be admitted.
"""
import json
import os
import sys
from scripts import c06_h00 as core
from scripts import c08_recovery as c08

REPO = "spikkie/gads-mode-c-proof"
REPO_ID = 1432047514
WORKFLOW_ID = 395103255
WORKFLOW_NAME = "C-08 fail-closed terminated-run dispatch reconciliation"
SOURCE_REF = "qualification/c08-reconcile-20261024"
SOURCE_SHA = "05c031e8a95fa725a7b4a0f8d685fe0dd93096e8"
FAILED_RUN_ID = 40095804830
EXPECTED_ACTOR = "spikkie"
TARGET_RUN_ID = "40093613654"
TERMINAL_STATE_SHA = "d09cabb5c384ab376bb52b85541a8118c90785c8"
VALIDATION_BRANCH = "qualification/c09-trusted-trigger-20261024"


def require(condition, reason):
    if not condition:
        raise core.Blocked("C09_" + reason)


def admitted_run(run):
    """Validate a source-run snapshot with no trust in event-supplied metadata."""
    require(isinstance(run, dict), "RUN_TYPE")
    checks = (
        (type(run.get("id")) is int and run["id"] == FAILED_RUN_ID, "RUN_ID"),
        (type(run.get("workflow_id")) is int and run["workflow_id"] == WORKFLOW_ID, "WORKFLOW_ID"),
        (run.get("name") == WORKFLOW_NAME, "WORKFLOW_NAME"),
        (run.get("event") == "push", "SOURCE_EVENT"),
        (run.get("head_branch") == SOURCE_REF, "SOURCE_BRANCH"),
        (run.get("head_sha") == SOURCE_SHA, "SOURCE_SHA"),
        (run.get("status") == "completed", "NOT_COMPLETE"),
        (run.get("conclusion") == "failure", "NOT_FAILURE"),
        (type(run.get("run_attempt")) is int and run["run_attempt"] == 1, "RERUN_DENIED"),
        (isinstance(run.get("actor"), dict)
            and run["actor"].get("login") == EXPECTED_ACTOR, "ACTOR"),
        (isinstance(run.get("repository"), dict)
            and run["repository"].get("id") == REPO_ID
            and run["repository"].get("full_name") == REPO, "REPOSITORY"),
        (isinstance(run.get("head_repository"), dict)
            and run["head_repository"].get("id") == REPO_ID
            and run["head_repository"].get("full_name") == REPO, "HEAD_REPOSITORY"),
    )
    for ok, message in checks:
        require(ok, message)
    return FAILED_RUN_ID


def verify_event(event, actual):
    require(isinstance(event, dict) and event.get("action") == "completed", "EVENT_ACTION")
    require(isinstance(event.get("workflow_run"), dict), "EVENT_SHAPE")
    admitted_run(event["workflow_run"])
    admitted_run(actual)
    # A webhook is merely a hint; re-query GitHub for the authoritative live outcome.
    for field in ("id", "workflow_id", "head_sha", "run_attempt", "conclusion"):
        require(event["workflow_run"].get(field) == actual.get(field), "EVENT_API_MISMATCH")
    return FAILED_RUN_ID


def context(api, live):
    require(os.environ.get("GITHUB_REPOSITORY") == REPO, "CONTEXT_REPO")
    if live:
        require(os.environ.get("GITHUB_EVENT_NAME") == "workflow_run", "CONTEXT_EVENT")
        require(os.environ.get("GITHUB_REF") == "refs/heads/main", "CONTEXT_DEFAULT_BRANCH")
    else:
        require(os.environ.get("GITHUB_EVENT_NAME") == "push", "SMOKE_EVENT")
        require(os.environ.get("GITHUB_REF") == "refs/heads/" + VALIDATION_BRANCH, "SMOKE_BRANCH")
    meta = api.call("GET", "")
    require(meta.get("private") is False and meta.get("id") == REPO_ID, "PUBLIC_REPO_ID")
    main = api.call("GET", "/branches/main")
    require(main.get("protected") is True, "PROTECTED_MAIN")
    if live:
        require(main.get("commit", {}).get("sha") == os.environ.get("GITHUB_SHA"),
                "DEFAULT_BRANCH_SHA")
    return True


def target_reconciled(api):
    observed = c08.read_state(api)
    require(observed is not None, "STATE_MISSING")
    sha, state = observed
    require(sha == TERMINAL_STATE_SHA, "STATE_CHANGED")
    require(state["status"] == "CONFIRMED_SUCCESS" and
            state["generation"] == 2 and state["checks"] == 1 and
            state["matched_run"] == TARGET_RUN_ID, "STATE_INCOMPLETE")
    # Reuse the C-08 invariant checks for the durable terminal record.
    c08.validate(state)
    target = api.call("GET", "/actions/runs/" + TARGET_RUN_ID)
    shadow = dict(state, status="UNKNOWN_ACK", generation=1,
                  checks=0, matched_run=None,
                  history=["injected-lost-ack-after-dispatch"])
    require(c08.matches(shadow, [target]) == TARGET_RUN_ID, "ORIGINAL_DISPATCH_MISMATCH")
    return sha


def run(live):
    api = core.Github(os.environ.get("GITHUB_TOKEN"))
    context(api, live)
    actual = api.call("GET", "/actions/runs/" + str(FAILED_RUN_ID))
    if live:
        path = os.environ.get("GITHUB_EVENT_PATH", "")
        require(bool(path), "EVENT_PATH")
        with open(path, "r", encoding="utf-8") as handle:
            event = json.load(handle)
    else:
        # Smoke fixture from the independently retrieved, real GitHub run only.
        event = {"action": "completed", "workflow_run": actual}
    verify_event(event, actual)
    final_sha = target_reconciled(api)
    print("C09_READ_ONLY_GATE_PASS source_run=" + str(FAILED_RUN_ID) +
          " target_run=" + TARGET_RUN_ID + " final_state_sha=" + final_sha, flush=True)
    print("C09_NO_WRITE_NO_DISPATCH_REPLAY_SAFE", flush=True)


if __name__ == "__main__":
    try:
        if len(sys.argv) != 2 or sys.argv[1] not in ("event", "smoke"):
            raise core.Blocked("C09_MODE")
        run(sys.argv[1] == "event")
    except (core.Blocked, KeyError, ValueError, OSError, json.JSONDecodeError) as exc:
        raise SystemExit("BLOCKED: " + str(exc)) from None
