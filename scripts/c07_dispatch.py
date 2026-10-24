#!/usr/bin/env python3
"""C-07 single-use GitHub Actions cross-run dispatch, public synthetic-only.

A durable source-SHA-bound intent ref is created first; the trigger job has no
repository contents-write privilege and can dispatch only the already approved
C-05 workflow on protected main. No dynamic commands or user input.
"""
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

from scripts import c06_h00 as core

REPO = "spikkie/gads-mode-c-proof"
SOURCE_BRANCH = "qualification/c07-trusted-cross-run-20261024"
TARGET_WORKFLOW = "c05-proof.yml"
TARGET_SHA = "43cb1e6924d208288350d70b7b273f7cd3def0c4"
INTENT_PREFIX = "qualification/c07-intent-"
INTENT_PATH = "state/c07-intent.json"
RUN_ID = re.compile(r"^[0-9]{6,15}$")


def intent_ref(source_sha):
    if not isinstance(source_sha, str) or not core.HEX40.fullmatch(source_sha):
        raise core.Blocked("C07_SOURCE_SHA")
    return INTENT_PREFIX + source_sha[:20]


def make_intent(source_sha, run_id, created_at):
    if not RUN_ID.fullmatch(run_id) or type(created_at) is not int or created_at <= 0:
        raise core.Blocked("C07_RUN_ID_OR_CLOCK")
    return dict(schema="gads.c07.dispatch.v1", source_sha=source_sha,
                source_run=run_id, target_sha=TARGET_SHA,
                target_workflow=TARGET_WORKFLOW, created_epoch=created_at,
                status="INTENT_ONLY")


def validate(intent):
    if not isinstance(intent, dict) or set(intent) != set(
            make_intent("a" * 40, "123456", 1)):
        raise core.Blocked("C07_SCHEMA")
    original=make_intent(intent["source_sha"], intent["source_run"],
                         intent["created_epoch"])
    if intent!=original:
        raise core.Blocked("C07_INTENT_TAMPER")
    return intent


def preflight(api):
    if os.environ.get("GITHUB_REPOSITORY")!=REPO:
        raise core.Blocked("C07_WRONG_REPOSITORY")
    if os.environ.get("GITHUB_REF")!="refs/heads/"+SOURCE_BRANCH:
        raise core.Blocked("C07_WRONG_SOURCE_BRANCH")
    source=os.environ.get("GITHUB_SHA", "")
    if not core.HEX40.fullmatch(source):
        raise core.Blocked("C07_UNBOUND_SHA")
    branch=api.call("GET", "/branches/main")
    if branch.get("protected") is not True or branch.get("commit",{}).get("sha")!=TARGET_SHA:
        raise core.Blocked("C07_MAIN_PROTECTION_OR_SOURCE_CHANGED")
    info=api.call("GET", "")
    if info.get("private") is not False:
        raise core.Blocked("C07_PUBLIC_ONLY")
    return source


def read_intent(api, source):
    return core.read_state(api, ref=intent_ref(source), path=INTENT_PATH,
                           validation=validate)


def prepare(api):
    source=preflight(api)
    run=os.environ.get("GITHUB_RUN_ID", "")
    intent=make_intent(source,run,int(time.time()))
    if read_intent(api,source) is not None:
        raise core.Blocked("C07_EXISTING_INTENT_DENY_DUPLICATE")
    commit=core.build_commit(api,source,core.encode_state(intent),
         "test(c07): immutable single-dispatch intent",path=INTENT_PATH)
    try:
        api.call("POST","/git/refs",
                 {"ref":"refs/heads/"+intent_ref(source),"sha":commit})
    except core.HttpFailure as exc:
        if exc.status in (409,422):
            raise core.Blocked("C07_INTENT_CONCURRENT_DUPLICATE") from None
        raise
    state=read_intent(api,source)
    if state is None or state[1]!=intent:
        raise core.Blocked("C07_INTENT_READBACK")
    print("C07_INTENT_DURABLE source="+source+" ref_sha="+state[0],flush=True)


def load_bound(api):
    source=preflight(api)
    state=read_intent(api,source)
    if state is None:
        raise core.Blocked("C07_INTENT_MISSING")
    intent=state[1]
    if intent["source_run"]!=os.environ.get("GITHUB_RUN_ID"):
        raise core.Blocked("C07_RUN_BINDING")
    return intent


def dispatch(api):
    if os.environ.get("GITHUB_RUN_ATTEMPT")!="1":
        raise core.Blocked("C07_DISPATCH_REPLAY_DENIED")
    intent=load_bound(api)
    wf=api.call("GET","/actions/workflows/"+TARGET_WORKFLOW)
    if wf.get("path")!=".github/workflows/"+TARGET_WORKFLOW or wf.get("state")!="active":
        raise core.Blocked("C07_TRUSTED_WORKFLOW_MISSING")
    token=os.environ.get("GITHUB_TOKEN")
    if not token:
        raise core.Blocked("C07_DISPATCH_TOKEN_MISSING")
    url=api.url+"/actions/workflows/"+TARGET_WORKFLOW+"/dispatches"
    body=json.dumps({"ref":"main"},separators=(",",":")).encode("ascii")
    req=urllib.request.Request(url,method="POST",data=body,headers={
        "Authorization":"Bearer "+token,
        "Accept":"application/vnd.github+json",
        "X-GitHub-Api-Version":"2022-11-28",
        "Content-Type":"application/json",
        "User-Agent":"gads-c07-public-synthetic"})
    try:
        with urllib.request.urlopen(req,timeout=20) as response:
            if response.status!=204:
                raise core.Blocked("C07_BAD_DISPATCH_STATUS")
    except urllib.error.HTTPError as exc:
        raise core.Blocked("C07_DISPATCH_HTTP_"+str(exc.code)) from None
    print("C07_CROSS_RUN_DISPATCH_ACCEPTED target="+TARGET_WORKFLOW+
          " target_sha="+intent["target_sha"]+" event=workflow_dispatch",flush=True)


def verify(api):
    intent=load_bound(api)
    for attempt in range(15):
        info=api.call("GET","/actions/workflows/"+TARGET_WORKFLOW+
                      "/runs?event=workflow_dispatch&per_page=50")
        matching=[]
        for run in info.get("workflow_runs",[]):
            date=run.get("created_at","")
            try:
                created=int(datetime.fromisoformat(date.replace("Z","+00:00")).timestamp())
            except (ValueError,TypeError):
                continue
            actor=run.get("actor") or {}
            if (created>=intent["created_epoch"] and run.get("head_sha")==TARGET_SHA
                    and actor.get("login")=="github-actions[bot]"
                    and run.get("event")=="workflow_dispatch"):
                matching.append(run)
        if len(matching)>1:
            raise core.Blocked("C07_AMBIGUOUS_DISPATCH")
        if len(matching)==1:
            run=matching[0]
            if run.get("status") not in ("queued","in_progress","completed"):
                raise core.Blocked("C07_BAD_TARGET_STATUS")
            print("C07_CROSS_RUN_CONFIRMED originating_run="+intent["source_run"]+
                  " target_run="+str(run["id"])+" sha="+run["head_sha"],flush=True)
            return
        time.sleep(2)
    raise core.Blocked("C07_CROSS_RUN_NOT_OBSERVED")


if __name__=="__main__":
    try:
        mode=sys.argv[1] if len(sys.argv)==2 else ""
        api=core.Github(os.environ.get("GITHUB_TOKEN"))
        if mode=="prepare":
            prepare(api)
        elif mode=="dispatch":
            dispatch(api)
        elif mode=="verify":
            verify(api)
        else:
            raise core.Blocked("C07_MODE")
    except (core.Blocked,KeyError,ValueError,OSError) as exc:
        raise SystemExit("BLOCKED: "+str(exc)) from None
