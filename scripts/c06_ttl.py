#!/usr/bin/env python3
"""C-06 live TTL: scoped synthetic state, wall-clock deadline, CAS, attempt budget."""
import os
import sys
import time
from scripts import c06_h00 as core

REF = "qualification/c06-ttl-state-20261024"
PATH = "state/c06-ttl.json"
TTL = 15
MAX_ATTEMPTS = 1
SCHEMA = "gads.c06.ttl.v1"


def new_state(owner, origin, now):
    if not owner.isdigit() or not core.HEX40.fullmatch(origin) or type(now) is not int:
        raise core.Blocked("TTL_IDENTITY")
    return dict(schema=SCHEMA, package="synthetic-ttl-02", owner=owner,
                origin=origin, deadline=now + TTL, generation=1, status="LEASED",
                attempts=0, max_attempts=MAX_ATTEMPTS, recovered_by=None,
                history=["crash:" + owner])


def valid(s):
    if not isinstance(s, dict) or set(s) != set(new_state("1", "a"*40, 1)):
        raise core.Blocked("TTL_SCHEMA")
    if s["schema"] != SCHEMA or s["package"] != "synthetic-ttl-02":
        raise core.Blocked("TTL_SCHEMA")
    if not isinstance(s["owner"], str) or not s["owner"].isdigit() or not core.HEX40.fullmatch(s["origin"]):
        raise core.Blocked("TTL_IDENTITY")
    if type(s["deadline"]) is not int or s["max_attempts"] != MAX_ATTEMPTS:
        raise core.Blocked("TTL_BUDGET_OR_DEADLINE")
    if s["status"] == "LEASED":
        if s["generation"] != 1 or s["attempts"] != 0 or s["recovered_by"] is not None or s["history"] != ["crash:" + s["owner"]]:
            raise core.Blocked("TTL_BAD_LEASE")
    elif s["status"] == "COMPLETED":
        if s["generation"] != 2 or s["attempts"] != 1 or not isinstance(s["recovered_by"], str) or s["history"] != ["crash:" + s["owner"], "recovered:" + s["recovered_by"]]:
            raise core.Blocked("TTL_BAD_COMPLETION")
    else:
        raise core.Blocked("TTL_STATUS")
    return s


def transition(s, now, actor):
    valid(s)
    if s["status"] == "COMPLETED":
        return None
    if type(now) is not int or now < s["deadline"]:
        raise core.Blocked("TTL_LEASE_ACTIVE")
    if s["attempts"] >= s["max_attempts"]:
        raise core.Blocked("TTL_BUDGET_EXHAUSTED")
    if not isinstance(actor, str) or ":" not in actor:
        raise core.Blocked("TTL_ACTOR")
    n = dict(s, status="COMPLETED", generation=2, attempts=s["attempts"]+1,
             recovered_by=actor, history=s["history"] + ["recovered:" + actor])
    return valid(n)


def load(api):
    return core.read_state(api, ref=REF, path=PATH, validation=valid)


def run_seed(api):
    origin = core.check_source(api)
    if load(api) is not None:
        raise core.Blocked("TTL_ALREADY_SEEDED")
    state = new_state(os.environ["GITHUB_RUN_ID"], origin, int(time.time()))
    commit = core.build_commit(api, origin, core.encode_state(state), "test(c06): live future TTL lease", path=PATH)
    api.call("POST", "/git/refs", {"ref": "refs/heads/" + REF, "sha": commit})
    observed = load(api)
    if not observed or observed[1] != state:
        raise core.Blocked("TTL_SEED_NOT_DURABLE")
    try:
        transition(state, int(time.time()), state["owner"] + ":premature")
    except core.Blocked as e:
        if str(e) != "TTL_LEASE_ACTIVE":
            raise
    else:
        raise core.Blocked("TTL_EARLY_RECOVERY")
    print("C06_TTL_PRE_EXPIRY_REJECTED deadline=" + str(state["deadline"]), flush=True)
    print("C06_TTL_DURABLE_SEED " + commit, flush=True)
    sys.exit(73)  # real interrupted workflow; persisted state survives


def run_recover(api, contender):
    core.check_source(api)
    if contender not in ("alpha", "beta"):
        raise core.Blocked("TTL_CONTENDER")
    for attempt in range(2):  # bounded retry, not unbounded spin
        observed = load(api)
        if not observed:
            raise core.Blocked("TTL_MISSING_REF")
        tip, state = observed
        new = transition(state, int(time.time()), os.environ["GITHUB_RUN_ID"] + ":" + contender)
        if new is None:
            print("C06_TTL_TERMINAL_NO_DUPLICATE", flush=True)
            return
        commit = core.build_commit(api, tip, core.encode_state(new), "test(c06): TTL CAS complete", path=PATH)
        try:
            api.call("PATCH", "/git/refs/heads/" + REF, {"sha": commit, "force": False})
        except core.HttpFailure as e:
            if e.status not in (409, 422):
                raise
            current = load(api)
            if current and current[1]["status"] == "COMPLETED":
                print("C06_TTL_CAS_LOST_NO_DUPLICATE", flush=True)
                return
            if attempt == 1:
                raise core.Blocked("TTL_CAS_RETRIES_EXHAUSTED")
            continue
        current = load(api)
        if not current or current[1] != new:
            raise core.Blocked("TTL_CAS_READBACK")
        print("C06_TTL_CAS_WON attempts=1 budget=1 actor=" + contender, flush=True)
        return


def run_verify(api):
    core.check_source(api)
    state_pair = load(api)
    if not state_pair:
        raise core.Blocked("TTL_NO_STATE")
    tip, state = state_pair
    if state["status"] != "COMPLETED" or state["attempts"] != 1 or int(time.time()) < state["deadline"]:
        raise core.Blocked("TTL_NOT_TERMINAL")
    print("C06_TTL_REAL_TIME_AND_BUDGET_PASS generation=2 history=2 ref_sha=" + tip, flush=True)


if __name__ == "__main__":
    try:
        api = core.Github(os.environ.get("GITHUB_TOKEN"))
        cmd = sys.argv[1] if len(sys.argv) > 1 else ""
        if cmd == "seed" and len(sys.argv) == 2:
            run_seed(api)
        elif cmd == "recover" and len(sys.argv) == 3:
            run_recover(api, sys.argv[2])
        elif cmd == "verify" and len(sys.argv) == 2:
            run_verify(api)
        else:
            raise core.Blocked("TTL_MODE")
    except (core.Blocked, KeyError, ValueError, OSError) as e:
        raise SystemExit("BLOCKED: " + str(e)) from None
