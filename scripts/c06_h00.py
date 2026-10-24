#!/usr/bin/env python3
"""C-06 public synthetic proof: persistent Git-ref state and non-force CAS.

No production data, external workers, deployments or writes to protected main.
"""
import base64
import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

REPO = "spikkie/gads-mode-c-proof"
CODE_BRANCH = "qualification/c06-h00-live-20261024"
STATE_BRANCH = "qualification/c06-state-20261024"
STATE_FILE = "state/c06.json"
PACKAGE = "synthetic-c06-workpackage-01"
HEX40 = re.compile(r"^[0-9a-f]{40}$")


class Blocked(Exception):
    pass


class HttpFailure(Blocked):
    def __init__(self, status, method, path):
        self.status = status
        super().__init__(f"GITHUB_HTTP_{status}:{method}:{path.split('?')[0]}")


def encode_state(state):
    return (json.dumps(state, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")


def digest_blob(data):
    return hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()


def seed_state(run_id, source_sha):
    if not HEX40.fullmatch(source_sha):
        raise Blocked("SOURCE_SHA_INVALID")
    if not run_id.isdigit():
        raise Blocked("RUN_ID_INVALID")
    return {"schema": "gads.c06.gitcas.v1", "package": PACKAGE, "generation": 1,
            "status": "LEASED", "lease_deadline": 0, "origin_sha": source_sha,
            "owner": run_id, "recovery_owner": None,
            "history": ["injected-crash:" + run_id]}


def validate(state):
    if not isinstance(state, dict) or set(state) != {
        "schema", "package", "generation", "status", "lease_deadline",
        "origin_sha", "owner", "recovery_owner", "history"}:
        raise Blocked("STATE_SCHEMA")
    if state["schema"] != "gads.c06.gitcas.v1" or state["package"] != PACKAGE:
        raise Blocked("STATE_IDENTITY")
    if not isinstance(state["origin_sha"], str) or not HEX40.fullmatch(state["origin_sha"]):
        raise Blocked("STATE_SOURCE_SHA")
    if not isinstance(state["owner"], str) or not state["owner"].isdigit():
        raise Blocked("STATE_OWNER")
    if state["status"] == "LEASED":
        if (state["generation"] != 1 or state["lease_deadline"] != 0
                or state["recovery_owner"] is not None
                or state["history"] != ["injected-crash:" + state["owner"]]):
            raise Blocked("INVALID_LEASE")
    elif state["status"] == "COMPLETED":
        who = state["recovery_owner"]
        if (state["generation"] != 2 or state["lease_deadline"] != 0
                or not isinstance(who, str) or not re.fullmatch(r"[0-9]+:(alpha|beta)", who)
                or state["history"] != [
                    "injected-crash:" + state["owner"], "recovered:" + who]):
            raise Blocked("INVALID_COMPLETION")
    else:
        raise Blocked("STATE_STATUS")
    return state


def recover_state(state, run_id, contender):
    validate(state)
    if state["status"] == "COMPLETED":
        return None
    if not run_id.isdigit() or contender not in ("alpha", "beta"):
        raise Blocked("RECOVERY_IDENTITY")
    result = dict(state)
    result["status"] = "COMPLETED"
    result["generation"] = 2
    result["recovery_owner"] = run_id + ":" + contender
    result["history"] = state["history"] + ["recovered:" + result["recovery_owner"]]
    validate(result)
    return result


class Github:
    def __init__(self, token):
        self.url = "https://api.github.com/repos/" + REPO
        self.token = token

    def call(self, method, path, body=None):
        if method not in ("GET", "POST", "PATCH"):
            raise Blocked("METHOD_NOT_ALLOWED")
        if method != "GET" and not self.token:
            raise Blocked("NO_WRITE_TOKEN")
        headers = {"Accept": "application/vnd.github+json",
                   "User-Agent": "gads-synthetic-h00-proof",
                   "X-GitHub-Api-Version": "2022-11-28"}
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        if body is not None:
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(self.url + path,
             data=json.dumps(body).encode("ascii") if body is not None else None,
             method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=20) as response:
                return json.load(response)
        except urllib.error.HTTPError as err:
            raise HttpFailure(err.code, method, path) from None


def check_source(api):
    if os.environ.get("GITHUB_REPOSITORY") != REPO:
        raise Blocked("REPO_SCOPE")
    if os.environ.get("GITHUB_REF") != "refs/heads/" + CODE_BRANCH:
        raise Blocked("BRANCH_SCOPE")
    sha = os.environ.get("GITHUB_SHA", "")
    if not HEX40.fullmatch(sha):
        raise Blocked("SOURCE_SHA_INVALID")
    meta = api.call("GET", "")
    if meta.get("private") is not False:
        raise Blocked("NOT_PUBLIC_PROOF")
    main = api.call("GET", "/branches/main")
    if main.get("protected") is not True:
        raise Blocked("UNPROTECTED_MAIN")
    return sha


def read_state(api):
    try:
        ref = api.call("GET", "/git/ref/heads/" + STATE_BRANCH)
    except HttpFailure as err:
        if err.status == 404:
            return None
        raise
    tip = ref.get("object", {}).get("sha", "")
    if not HEX40.fullmatch(tip):
        raise Blocked("STATE_REF_IDENTITY")
    path = "/contents/" + STATE_FILE + "?ref=" + urllib.parse.quote(STATE_BRANCH, safe="")
    entry = api.call("GET", path)
    if entry.get("path") != STATE_FILE or entry.get("type") != "file":
        raise Blocked("STATE_BLOB_PATH")
    raw = base64.b64decode(entry["content"], validate=False)
    if digest_blob(raw) != entry.get("sha"):
        raise Blocked("STATE_BLOB_HASH")
    if raw != encode_state(json.loads(raw)):
        raise Blocked("STATE_NOT_CANONICAL")
    return tip, validate(json.loads(raw))


def build_commit(api, parent, data, msg):
    obj = api.call("GET", "/git/commits/" + parent)
    blob = api.call("POST", "/git/blobs", {
        "content": base64.b64encode(data).decode("ascii"), "encoding": "base64"})
    if blob.get("sha") != digest_blob(data):
        raise Blocked("CREATED_BLOB_HASH")
    tree = api.call("POST", "/git/trees", {
        "base_tree": obj["tree"]["sha"],
        "tree": [{"path": STATE_FILE, "mode": "100644", "type": "blob", "sha": blob["sha"]}]})
    commit = api.call("POST", "/git/commits", {
        "message": msg, "tree": tree["sha"], "parents": [parent]})
    if not HEX40.fullmatch(commit.get("sha", "")):
        raise Blocked("COMMIT_SHA")
    return commit["sha"]


def initial(api):
    sha = check_source(api)
    if read_state(api) is not None:
        raise Blocked("SEED_ALREADY_EXISTS")
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    state = seed_state(run_id, sha)
    commit = build_commit(api, sha, encode_state(state), "test(c06): seeded expired lease")
    try:
        api.call("POST", "/git/refs", {
            "ref": "refs/heads/" + STATE_BRANCH, "sha": commit})
    except HttpFailure:
        raise Blocked("SEED_REF_CONCURRENT_OR_FORBIDDEN") from None
    current = read_state(api)
    if current is None or current[1] != state:
        raise Blocked("SEED_READBACK")
    print("C06_SEEDED_EXPIRED_LEASE generation=1 ref=" + STATE_BRANCH, flush=True)
    print("C06_INJECTED_CRASH_AFTER_DURABLE_WRITE", flush=True)
    sys.exit(73)


def recovery(api, contender):
    check_source(api)
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    for attempt in range(1, 4):
        current = read_state(api)
        if current is None:
            raise Blocked("MISSING_DURABLE_LEASE")
        tip, state = current
        changed = recover_state(state, run_id, contender)
        if changed is None:
            print("C06_TERMINAL_REPLAY_NO_WRITE generation=2", flush=True)
            return
        commit = build_commit(api, tip, encode_state(changed),
                              "test(c06): CAS recovery generation 2 " + contender)
        try:
            # force=false ensures a concurrent sibling commit cannot replace the winner.
            api.call("PATCH", "/git/refs/heads/" + STATE_BRANCH,
                     {"sha": commit, "force": False})
        except HttpFailure as err:
            if err.status not in (409, 422):
                raise
            latest = read_state(api)
            if latest and latest[1]["status"] == "COMPLETED":
                print("C06_CAS_LOST_RACE_NO_DUPLICATE", flush=True)
                return
            if attempt == 3:
                raise Blocked("CAS_RETRIES_EXHAUSTED")
            continue
        latest = read_state(api)
        if latest is None or latest[1] != changed:
            raise Blocked("CAS_READBACK_MISMATCH")
        print("C06_CAS_RECOVERY_WON generation=2 contender=" + contender, flush=True)
        return
    raise Blocked("CAS_RETRIES_EXHAUSTED")


def verify(api):
    check_source(api)
    current = read_state(api)
    if current is None:
        raise Blocked("STATE_MISSING")
    tip, state = current
    if state["status"] != "COMPLETED" or state["generation"] != 2:
        raise Blocked("STATE_NOT_COMPLETED")
    validate(state)
    print("C06_DURABLE_RESTART_PASS generation=2 history=2 owner="
          + state["recovery_owner"] + " sha=" + tip, flush=True)


if __name__ == "__main__":
    try:
        mode = sys.argv[1] if len(sys.argv) > 1 else ""
        api = Github(os.environ.get("GITHUB_TOKEN"))
        if mode == "seed":
            initial(api)
        elif mode == "recover" and len(sys.argv) == 3:
            recovery(api, sys.argv[2])
        elif mode == "verify":
            verify(api)
        else:
            raise Blocked("MODE")
    except (Blocked, KeyError, ValueError, OSError) as err:
        raise SystemExit("BLOCKED: " + str(err)) from None
