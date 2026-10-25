"""Deterministic H-00 state model. No GitHub credentials, storage or network."""
from copy import deepcopy
from hashlib import sha256
import json
import re

SCHEMA = "gads.h00.v1"
NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
FIELDS = {"schema","work_id","source_sha","repo_id","workflow_id","stage",
          "revision","max_attempts","attempts","units_limit","units_reserved",
          "owner","fence","deadline","correlation","target_run","history"}
EVENTS = {"claim","unknown","expire","confirm","block"}
LEASE_SECONDS = 30

class Blocked(ValueError):
    pass

def check(value, reason):
    if not value:
        raise Blocked(reason)

def name(v):
    return isinstance(v,str) and bool(NAME.fullmatch(v))

def number(v,minval=0):
    return type(v) is int and v >= minval

def fingerprint(value):
    raw=json.dumps(value,sort_keys=True,separators=(",",":"),allow_nan=False)
    return sha256(raw.encode("ascii")).hexdigest()

def new(work_id,source_sha,repo_id,workflow_id,max_attempts=1,units_limit=1):
    check(name(work_id) and isinstance(source_sha,str) and HEX40.fullmatch(source_sha),
          "WORK_ID_OR_SOURCE")
    check(number(repo_id,1) and number(workflow_id,1),"GITHUB_IDENTITY")
    check(number(max_attempts,1) and number(units_limit,1)
          and max_attempts <= units_limit <= 100,"BUDGET_CONFIG")
    return dict(schema=SCHEMA,work_id=work_id,source_sha=source_sha,
                repo_id=repo_id,workflow_id=workflow_id,stage="QUEUED",
                revision=0,max_attempts=max_attempts,attempts=0,
                units_limit=units_limit,units_reserved=0,owner=None,fence=None,
                deadline=0,correlation=None,target_run=None,history=[])

def validate(s):
    check(isinstance(s,dict) and set(s)==FIELDS and s["schema"]==SCHEMA,
          "STATE_SCHEMA")
    check(name(s["work_id"]) and isinstance(s["source_sha"],str)
          and HEX40.fullmatch(s["source_sha"])
          and number(s["repo_id"],1) and number(s["workflow_id"],1),
          "STATE_IDENTITY")
    check(all(number(s[k]) for k in ("revision","attempts","units_reserved","deadline"))
          and number(s["max_attempts"],1) and number(s["units_limit"],1)
          and s["attempts"]==s["units_reserved"]
          and s["attempts"] <= s["max_attempts"] <= s["units_limit"] <= 100,
          "STATE_BUDGET")
    stage=s["stage"]
    check(stage in ("QUEUED","LEASED","UNKNOWN","COMPLETED","BLOCKED"),"STATE_STAGE")
    if s["attempts"]==0:
        check(s["owner"] is None and s["fence"] is None and s["deadline"]==0
              and s["correlation"] is None and stage in ("QUEUED","BLOCKED"),
              "UNCLAIMED_STATE")
    else:
        check(name(s["owner"]) and name(s["fence"]) and s["deadline"]>0
              and isinstance(s["correlation"],str)
              and HEX64.fullmatch(s["correlation"]) and stage!="QUEUED",
              "LEASE_STATE")
    check((number(s["target_run"],1) if stage=="COMPLETED"
           else s["target_run"] is None),"STATE_TARGET")
    history=s["history"]
    check(isinstance(history,list) and len(history)==s["revision"]
          and len(history)<=102,"HISTORY_LENGTH")
    seen=set()
    for i,item in enumerate(history,1):
        check(isinstance(item,dict) and set(item)=={"id","fingerprint","stage","revision"}
              and name(item["id"]) and item["id"] not in seen
              and isinstance(item["fingerprint"],str)
              and HEX64.fullmatch(item["fingerprint"])
              and item["revision"]==i and item["stage"] in
              ("QUEUED","LEASED","UNKNOWN","COMPLETED","BLOCKED"),"HISTORY_ORDER")
        seen.add(item["id"])
    check(history[-1]["stage"]==stage if history else stage=="QUEUED",
          "HISTORY_LAST_STAGE")
    return s

def attested(s, evidence):
    # Only a trusted gateway may supply this, following independent GitHub API readback.
    check(isinstance(evidence,dict) and set(evidence)=={
          "id","repo_id","workflow_id","source_sha","correlation","event",
          "actor","status","conclusion"},"ATTESTATION_SCHEMA")
    check(number(evidence["id"],1) and evidence["repo_id"]==s["repo_id"]
          and evidence["workflow_id"]==s["workflow_id"]
          and evidence["source_sha"]==s["source_sha"]
          and evidence["correlation"]==s["correlation"]
          and evidence["event"]=="workflow_dispatch"
          and evidence["actor"]=="github-actions[bot]"
          and evidence["status"]=="completed"
          and evidence["conclusion"]=="success","ATTESTATION_MISMATCH")
    return evidence["id"]

def transition(s,event,now):
    """Pure transition. Durable CAS and authenticated evidence are gateway duties."""
    validate(s)
    check(isinstance(event,dict) and set(event).issubset(
        {"id","kind","owner","fence","target"}) and name(event.get("id"))
        and event.get("kind") in EVENTS,"EVENT_SCHEMA")
    check(number(now,1),"CLOCK")
    digest=fingerprint(event)
    for item in s["history"]:
        if item["id"]==event["id"]:
            check(item["fingerprint"]==digest,"REPLAY_COLLISION")
            return deepcopy(s)
    check(s["stage"] not in ("COMPLETED","BLOCKED"),"TERMINAL")
    nxt=deepcopy(s)
    action=event["kind"]
    if action=="claim":
        check(s["stage"]=="QUEUED" and name(event.get("owner")),"CLAIM_DENIED")
        check(s["attempts"]<s["max_attempts"] and s["units_reserved"]<s["units_limit"],
              "BUDGET_EXHAUSTED")
        nxt["attempts"]+=1
        nxt["units_reserved"]+=1
        nxt["owner"]=event["owner"]
        nxt["fence"]="f"+str(s["revision"]+1)
        nxt["deadline"]=now+LEASE_SECONDS
        nxt["correlation"]=fingerprint({"work_id":s["work_id"],
            "source_sha":s["source_sha"],"attempts":nxt["attempts"],
            "owner":nxt["owner"]})
        nxt["stage"]="LEASED"
    elif action in ("unknown","expire"):
        check(s["stage"]=="LEASED","NOT_LEASED")
        if action=="unknown":
            check(event.get("owner")==s["owner"] and event.get("fence")==s["fence"],
                  "FENCE_DENIED")
        else:
            check(now>=s["deadline"],"LEASE_ACTIVE")
        nxt["stage"]="UNKNOWN"
    elif action=="confirm":
        check(s["stage"] in ("LEASED","UNKNOWN"),"CONFIRM_DENIED")
        nxt["target_run"]=attested(s,event.get("target"))
        nxt["stage"]="COMPLETED"
    elif action=="block":
        nxt["stage"]="BLOCKED"
    nxt["revision"]+=1
    nxt["history"].append({"id":event["id"],"fingerprint":digest,
                           "stage":nxt["stage"],"revision":nxt["revision"]})
    return validate(nxt)
