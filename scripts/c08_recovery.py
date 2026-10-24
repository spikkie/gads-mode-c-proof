#!/usr/bin/env python3
"""C-08 fail-closed dispatch-ack reconciliation across terminated GitHub runs.

Public synthetic proof only. Never dispatches, deploys or merges.
"""
import os
import re
import sys
from datetime import datetime, timezone

from scripts import c06_h00 as core
from scripts import c07_dispatch as c07

REPO = "spikkie/gads-mode-c-proof"
BRANCH = "qualification/c08-reconcile-20261024"
STATE_REF = "qualification/c08-unknown-dispatch-state-20261024"
STATE_PATH = "state/c08-recovery.json"
ORIGINAL_DISPATCH_SHA = "1f4ab08244d22b49b84a0fda3ed8509ed9069adb"
EXPECTED_C07_RUN = "40093584738"
TARGET_WORKFLOW = "c05-proof.yml"
TARGET_WORKFLOW_ID = 395007460
WINDOW_SECONDS = 120
HEX40 = re.compile(r"^[0-9a-f]{40}$")
DECIMAL = re.compile(r"^[0-9]{6,15}$")


def check_origin(api):
    if os.environ.get("GITHUB_REPOSITORY") != REPO:
        raise core.Blocked("C08_WRONG_REPO")
    if os.environ.get("GITHUB_REF") != "refs/heads/" + BRANCH:
        raise core.Blocked("C08_WRONG_BRANCH")
    src = os.environ.get("GITHUB_SHA", "")
    if not HEX40.fullmatch(src):
        raise core.Blocked("C08_SOURCE_SHA_INVALID")
    main = api.call("GET", "/branches/main")
    if (main.get("protected") is not True or
            main.get("commit", {}).get("sha") != c07.TARGET_SHA):
        raise core.Blocked("C08_TRUSTED_MAIN_DRIFT")
    metadata = api.call("GET", "")
    if metadata.get("private") is not False:
        raise core.Blocked("C08_PUBLIC_ONLY")
    return src


def get_original_intent(api):
    observed = c07.read_intent(api, ORIGINAL_DISPATCH_SHA)
    if observed is None:
        raise core.Blocked("C08_ORIGINAL_INTENT_MISSING")
    intent = observed[1]
    if (intent["source_run"] != EXPECTED_C07_RUN or
            intent["source_sha"] != ORIGINAL_DISPATCH_SHA or
            intent["target_sha"] != c07.TARGET_SHA or
            intent["target_workflow"] != TARGET_WORKFLOW):
        raise core.Blocked("C08_ORIGINAL_INTENT_NOT_TRUSTED")
    return intent


def initial(intent, seed_sha):
    if not HEX40.fullmatch(seed_sha):
        raise core.Blocked("C08_BAD_SEED_SHA")
    if not isinstance(intent, dict):
        raise core.Blocked("C08_BAD_INTENT")
    if intent["source_run"] != EXPECTED_C07_RUN:
        raise core.Blocked("C08_INTENT_RUN_MISMATCH")
    return dict(schema="gads.c08.unknown-dispatch.v1",
                original_source_sha=ORIGINAL_DISPATCH_SHA,
                original_run=EXPECTED_C07_RUN,
                intent_epoch=intent["created_epoch"],
                target_sha=c07.TARGET_SHA,
                target_workflow=TARGET_WORKFLOW,
                seed_sha=seed_sha, status="UNKNOWN_ACK",
                generation=1, checks=0, matched_run=None,
                history=["injected-lost-ack-after-dispatch"])


def validate(state):
    if not isinstance(state, dict) or set(state) != {
            "schema", "original_source_sha", "original_run", "intent_epoch",
            "target_sha", "target_workflow", "seed_sha", "status", "generation",
            "checks", "matched_run", "history"}:
        raise core.Blocked("C08_STATE_SCHEMA")
    if (state["schema"] != "gads.c08.unknown-dispatch.v1" or
            state["original_source_sha"] != ORIGINAL_DISPATCH_SHA or
            state["original_run"] != EXPECTED_C07_RUN or
            state["target_sha"] != c07.TARGET_SHA or
            state["target_workflow"] != TARGET_WORKFLOW or
            not isinstance(state["seed_sha"], str) or
            not HEX40.fullmatch(state["seed_sha"]) or
            type(state["intent_epoch"]) is not int or
            state["intent_epoch"] <= 0):
        raise core.Blocked("C08_STATE_IDENTITY")
    if state["status"] == "UNKNOWN_ACK":
        if (state["generation"] != 1 or state["checks"] != 0 or
                state["matched_run"] is not None or
                state["history"] != ["injected-lost-ack-after-dispatch"]):
            raise core.Blocked("C08_UNKNOWN_INVARIANT")
    elif state["status"] == "CONFIRMED_SUCCESS":
        run_id = state["matched_run"]
        if (state["generation"] != 2 or state["checks"] != 1 or
                not isinstance(run_id, str) or not DECIMAL.fullmatch(run_id) or
                state["history"] != ["injected-lost-ack-after-dispatch",
                                     "reconciled:" + run_id]):
            raise core.Blocked("C08_TERMINAL_INVARIANT")
    else:
        raise core.Blocked("C08_STATUS")
    return state


def parse_epoch(value):
    try:
        return int(datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp())
    except (AttributeError, TypeError, ValueError) as exc:
        raise core.Blocked("C08_BAD_TIMESTAMP") from exc


def matches(state, candidates):
    validate(state)
    found = []
    for run in candidates:
        if (run.get("event") != "workflow_dispatch" or
                run.get("workflow_id") != TARGET_WORKFLOW_ID or
                run.get("head_sha") != c07.TARGET_SHA or
                run.get("head_branch") != "main" or
                (run.get("actor") or {}).get("login") != "github-actions[bot]"):
            continue
        ts = parse_epoch(run.get("created_at"))
        if state["intent_epoch"] <= ts <= state["intent_epoch"] + WINDOW_SECONDS:
            if run.get("status") != "completed" or run.get("conclusion") != "success":
                raise core.Blocked("C08_MATCH_NOT_SUCCESSFUL")
            rid = run.get("id")
            if type(rid) is not int or not DECIMAL.fullmatch(str(rid)):
                raise core.Blocked("C08_MATCH_RUN_ID")
            found.append(str(rid))
    if len(found) > 1:
        raise core.Blocked("C08_AMBIGUOUS_MATCH")
    if not found:
        raise core.Blocked("C08_NOT_FOUND_INCONCLUSIVE_NO_REDISPATCH")
    return found[0]


def confirm(state, target_run):
    validate(state)
    if state["status"] == "CONFIRMED_SUCCESS":
        return None
    if not isinstance(target_run, str) or not DECIMAL.fullmatch(target_run):
        raise core.Blocked("C08_INVALID_MATCH")
    finished = dict(state, status="CONFIRMED_SUCCESS", generation=2,
                    checks=1, matched_run=target_run,
                    history=state["history"] + ["reconciled:" + target_run])
    return validate(finished)


def read_state(api):
    return core.read_state(api, ref=STATE_REF, path=STATE_PATH, validation=validate)


def seed(api):
    sha = check_origin(api)
    if read_state(api) is not None:
        raise core.Blocked("C08_SEED_ALREADY_EXISTS")
    intent = get_original_intent(api)
    state = initial(intent, sha)
    commit = core.build_commit(api, sha, core.encode_state(state),
                               "test(c08): unknown ack after complete dispatch",
                               path=STATE_PATH)
    api.call("POST", "/git/refs", {"ref": "refs/heads/" + STATE_REF,
                                  "sha": commit})
    loaded = read_state(api)
    if loaded is None or loaded[1] != state:
        raise core.Blocked("C08_SEED_READBACK")
    print("C08_UNKNOWN_ACK_DURABLE " + commit, flush=True)
    print("C08_INJECTED_LOST_ACK_TERMINATE_WHOLE_RUN", flush=True)
    sys.exit(73)


def reconcile(api):
    check_origin(api)
    before = read_state(api)
    if before is None:
        raise core.Blocked("C08_NO_DURABLE_UNKNOWN_ACK")
    tip, state = before
    if state["status"] == "CONFIRMED_SUCCESS":
        print("C08_REPLAY_NO_MUTATION matched_run=" + state["matched_run"], flush=True)
        return
    original = get_original_intent(api)
    if original["created_epoch"] != state["intent_epoch"]:
        raise core.Blocked("C08_ORIGINAL_INTENT_CHANGED")
    # The queried collection is bounded; never treat an incomplete page as proof of absence.
    query = "/actions/workflows/" + TARGET_WORKFLOW + "/runs?event=workflow_dispatch&per_page=100"
    result = api.call("GET", query)
    runs = result.get("workflow_runs")
    if not isinstance(runs, list) or len(runs) >= 100:
        raise core.Blocked("C08_UNBOUNDED_QUERY_UNCERTAIN")
    observed = matches(state, runs)
    changed = confirm(state, observed)
    commit = core.build_commit(api, tip, core.encode_state(changed),
                               "test(c08): reconcile original dispatch by real GitHub run",
                               path=STATE_PATH)
    try:
        api.call("PATCH", "/git/refs/heads/" + STATE_REF,
                 {"sha": commit, "force": False})
    except core.HttpFailure as exc:
        if exc.status not in (409, 422):
            raise
        latest = read_state(api)
        if latest and latest[1]["status"] == "CONFIRMED_SUCCESS" and latest[1]["matched_run"] == observed:
            print("C08_CAS_RACE_RECONCILED_WITHOUT_DUPLICATE", flush=True)
            return
        raise core.Blocked("C08_CAS_CONFLICT_NO_RETRY") from None
    latest = read_state(api)
    if latest is None or latest[1] != changed:
        raise core.Blocked("C08_COMMIT_MISMATCH")
    print("C08_RECONCILED_NO_DISPATCH target_run=" + observed + " sha=" + latest[0], flush=True)


def verify(api):
    check_origin(api)
    state = read_state(api)
    if state is None or state[1]["status"] != "CONFIRMED_SUCCESS":
        raise core.Blocked("C08_NOT_CONFIRMED")
    j = state[1]
    run = api.call("GET", "/actions/runs/" + j["matched_run"])
    if matches(dict(j, status="UNKNOWN_ACK", generation=1,
                    checks=0, matched_run=None,
                    history=["injected-lost-ack-after-dispatch"]), [run]) != j["matched_run"]:
        raise core.Blocked("C08_TARGET_RUN_MISMATCH")
    if confirm(j, j["matched_run"]) is not None:
        raise core.Blocked("C08_REPLAY_NOT_IDEMPOTENT")
    print("C08_CROSS_RUN_RECOVERY_PASS generation=2 target_run=" +
          j["matched_run"] + " ref_sha=" + state[0], flush=True)


if __name__ == "__main__":
    try:
        api = core.Github(os.environ.get("GITHUB_TOKEN"))
        command = sys.argv[1] if len(sys.argv) == 2 else ""
        if command == "seed":
            seed(api)
        elif command == "reconcile":
            reconcile(api)
        elif command == "verify":
            verify(api)
        else:
            raise core.Blocked("C08_MODE")
    except (core.Blocked, KeyError, ValueError, OSError) as exc:
        raise SystemExit("BLOCKED: " + str(exc)) from None
