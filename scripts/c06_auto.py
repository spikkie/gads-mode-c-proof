#!/usr/bin/env python3
"""C-06 bounded synthetic H-00 job chain. Durable Git ref, no actual AI charges."""
import os
import re
import sys
import time
from scripts import c06_h00 as core

SCHEMA = "gads.c06.auto.v1"
PATH = "state/c06-auto.json"
REF_PREFIX = "qualification/c06-auto-state-"
LIMIT = 2
RETRY_LIMIT = 2


def state_ref(run_id):
    if not isinstance(run_id, str) or not re.fullmatch(r"[0-9]{6,15}", run_id):
        raise core.Blocked("AUTO_RUN_ID")
    return REF_PREFIX + run_id


def initial(run_id, source):
    state_ref(run_id)
    if not isinstance(source, str) or not core.HEX40.fullmatch(source):
        raise core.Blocked("AUTO_SOURCE_SHA")
    return dict(schema=SCHEMA, run_id=run_id, source=source, generation=0,
                stage="READY", units_limit=LIMIT, units_used=0,
                p1_attempt_limit=RETRY_LIMIT, p1_attempts=0,
                p1="PENDING", p2="PENDING", p3="PENDING", deadline=0, history=[])


def validate(s):
    if not isinstance(s, dict) or set(s) != set(initial("123456", "a"*40)):
        raise core.Blocked("AUTO_SCHEMA")
    initial(s["run_id"], s["source"])
    if s["schema"] != SCHEMA or s["units_limit"] != LIMIT or s["p1_attempt_limit"] != RETRY_LIMIT:
        raise core.Blocked("AUTO_BUDGET_CONFIG")
    if type(s["generation"]) is not int or s["generation"] not in range(5):
        raise core.Blocked("AUTO_GENERATION")
    if any(type(s[x]) is not int for x in ("units_used", "p1_attempts", "deadline")):
        raise core.Blocked("AUTO_COUNTER")
    if s["units_used"] < 0 or s["units_used"] > LIMIT or s["p1_attempts"] > RETRY_LIMIT:
        raise core.Blocked("AUTO_BUDGET_EXCEEDED")
    expected=[
       ("READY",0,0,0,"PENDING","PENDING","PENDING",[]),
       ("LEASED",1,0,1,"LEASED","PENDING","PENDING",["p1-crashed"]),
       ("P1_DONE",2,1,2,"DONE","PENDING","PENDING",["p1-crashed","p1-recovered"]),
       ("P2_DONE",3,2,2,"DONE","DONE","PENDING",["p1-crashed","p1-recovered","p2-completed"]),
       ("STOP_BUDGET",4,2,2,"DONE","DONE","BLOCKED_BUDGET",["p1-crashed","p1-recovered","p2-completed","p3-denied-budget"]),
    ][s["generation"]]
    actual=(s["stage"],s["generation"],s["units_used"],s["p1_attempts"],
            s["p1"],s["p2"],s["p3"],s["history"])
    if actual!=expected:
        raise core.Blocked("AUTO_BAD_TRANSITION")
    if s["generation"]==0 and s["deadline"]!=0:
        raise core.Blocked("AUTO_UNEXPECTED_DEADLINE")
    if s["generation"]>0 and s["deadline"]<=0:
        raise core.Blocked("AUTO_MISSING_DEADLINE")
    return s


def step(s, action, now):
    validate(s)
    if type(now) is not int:
        raise core.Blocked("AUTO_CLOCK")
    if s["stage"]=="STOP_BUDGET":
        return None
    nxt=dict(s)
    nxt["history"]=list(s["history"])
    if action=="crash" and s["stage"]=="READY":
        nxt.update(stage="LEASED",generation=1,p1="LEASED",p1_attempts=1,deadline=now-1)
        nxt["history"].append("p1-crashed")
    elif action=="recover" and s["stage"]=="LEASED":
        if now<s["deadline"]:
            raise core.Blocked("AUTO_LEASE_ACTIVE")
        if s["p1_attempts"]>=s["p1_attempt_limit"] or s["units_used"]>=s["units_limit"]:
            raise core.Blocked("AUTO_RECOVERY_BUDGET")
        nxt.update(stage="P1_DONE",generation=2,p1="DONE",p1_attempts=2,units_used=1)
        nxt["history"].append("p1-recovered")
    elif action=="next" and s["stage"]=="P1_DONE":
        if s["units_used"]+1>s["units_limit"]:
            raise core.Blocked("AUTO_NEXT_BUDGET")
        nxt.update(stage="P2_DONE",generation=3,p2="DONE",units_used=2)
        nxt["history"].append("p2-completed")
    elif action=="deny" and s["stage"]=="P2_DONE":
        if s["units_used"]<s["units_limit"]:
            raise core.Blocked("AUTO_P3_WRONG_BUDGET")
        nxt.update(stage="STOP_BUDGET",generation=4,p3="BLOCKED_BUDGET")
        nxt["history"].append("p3-denied-budget")
    else:
        raise core.Blocked("AUTO_ILLEGAL_STEP")
    return validate(nxt)


def read(api, run_id):
    return core.read_state(api,ref=state_ref(run_id),path=PATH,validation=validate)


def put(api, run_id, base_tip, state):
    commit=core.build_commit(api,base_tip,core.encode_state(state),
                             "test(c06): auto gen"+str(state["generation"]),path=PATH)
    api.call("PATCH","/git/refs/heads/"+state_ref(run_id),
             {"sha":commit,"force":False})
    latest=read(api,run_id)
    if latest is None or latest[1]!=state:
        raise core.Blocked("AUTO_CAS_READBACK")


def apply(api, run_id, action):
    previous=read(api,run_id)
    if previous is None:
        raise core.Blocked("AUTO_NO_DURABLE_CHECKPOINT")
    tip,state=previous
    if state["source"]!=os.environ.get("GITHUB_SHA") or state["run_id"]!=run_id:
        raise core.Blocked("AUTO_WORKPACKAGE_BINDING")
    after=step(state,action,int(time.time()))
    if after is not None:
        put(api,run_id,tip,after)
    return after


def run(mode):
    api=core.Github(os.environ.get("GITHUB_TOKEN"))
    sha=core.check_source(api)
    run_id=os.environ.get("GITHUB_RUN_ID","")
    state_ref(run_id)
    if mode=="init":
        if read(api,run_id) is not None:
            raise core.Blocked("AUTO_ALREADY_INITIALIZED")
        s=initial(run_id,sha)
        commit=core.build_commit(api,sha,core.encode_state(s),
                  "test(c06): initial durable queue",path=PATH)
        api.call("POST","/git/refs",{"ref":"refs/heads/"+state_ref(run_id),"sha":commit})
        if read(api,run_id)[1]!=s:
            raise core.Blocked("AUTO_INITIAL_READBACK")
        print("AUTO_STATE_PERSISTED generation=0 packages=3 budget=2",flush=True)
    elif mode=="crash":
        s=apply(api,run_id,"crash")
        if s is None or s["stage"]!="LEASED":
            raise core.Blocked("AUTO_CRASH_STATE")
        print("AUTO_INJECTED_WORKER_CRASH_AFTER_STATE_COMMIT",flush=True)
        sys.exit(73)
    elif mode=="recover":
        s=apply(api,run_id,"recover")
        print("AUTO_P1_RECOVERED attempts="+str(s["p1_attempts"])+" credits="+str(s["units_used"]),flush=True)
    elif mode=="next":
        s=apply(api,run_id,"next")
        print("AUTO_P2_STARTED_AUTOMATICALLY credits="+str(s["units_used"]),flush=True)
        s=apply(api,run_id,"deny")
        print("AUTO_P3_DENIED_BUDGET used=2 max=2",flush=True)
    elif mode=="verify":
        state=read(api,run_id)
        if state is None or state[1]["stage"]!="STOP_BUDGET":
            raise core.Blocked("AUTO_TERMINAL_MISSING")
        if state[1]["history"]!=["p1-crashed","p1-recovered","p2-completed","p3-denied-budget"]:
            raise core.Blocked("AUTO_HISTORY")
        if step(state[1],"next",int(time.time())) is not None:
            raise core.Blocked("AUTO_REPLAY_WRITE")
        print("AUTO_H00_CHAIN_PASS generation=4 p1=DONE p2=DONE p3=BLOCKED_BUDGET "+
              "units=2/2 ref_sha="+state[0],flush=True)
    else:
        raise core.Blocked("AUTO_MODE")


if __name__=="__main__":
    try:
        if len(sys.argv)!=2 or sys.argv[1] not in ("init","crash","recover","next","verify"):
            raise core.Blocked("AUTO_ARGUMENTS")
        run(sys.argv[1])
    except (core.Blocked,KeyError,ValueError,OSError) as exc:
        raise SystemExit("BLOCKED: "+str(exc)) from None
