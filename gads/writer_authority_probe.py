"""GET-only live GitHub authority evidence. Never authorizes a write token."""
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from gads import writer_authority as a

MAX_BYTES = 350000


class ProbeBlocked(ValueError):
    pass


def fetch(path, token):
    request=urllib.request.Request(
        "https://api.github.com/repos/" + a.SOURCE_REPO + path,
        headers={"Accept":"application/vnd.github+json",
                 "Authorization":"Bearer "+token,
                 "X-GitHub-Api-Version":"2022-11-28",
                 "User-Agent":"gads-writer-authority-readonly"},
        method="GET")
    try:
        with urllib.request.urlopen(request,timeout=12) as response:
            if response.status != 200:
                raise ProbeBlocked("HTTP_UNEXPECTED_STATUS")
            raw=response.read(MAX_BYTES+1)
    except urllib.error.HTTPError as exc:
        raise ProbeBlocked("API_HTTP_"+str(exc.code)) from None
    except (OSError, TimeoutError) as exc:
        raise ProbeBlocked("API_TRANSPORT_UNAVAILABLE") from exc
    if len(raw) > MAX_BYTES:
        raise ProbeBlocked("API_RESPONSE_TOO_LARGE")
    try:
        return json.loads(raw)
    except (ValueError, UnicodeError):
        raise ProbeBlocked("API_INVALID_JSON") from None


def probe(token):
    repo=fetch("",token)
    if repo.get("id") != a.SOURCE_REPO_ID or repo.get("full_name") != a.SOURCE_REPO:
        raise ProbeBlocked("SOURCE_REPOSITORY_MISMATCH")
    if repo.get("private") is not False or repo.get("default_branch") != "main":
        raise ProbeBlocked("SOURCE_SCOPE_MISMATCH")
    main=fetch("/branches/main",token)
    if main.get("protected") is not True:
        raise ProbeBlocked("SOURCE_MAIN_NOT_PROTECTED")

    ruleset=fetch("/rulesets/"+str(a.SOURCE_RULESET_ID),token)
    pulls={}
    reviews={}
    for number in a.PR_STACK:
        pulls[number]=fetch("/pulls/"+str(number),token)
        reviews[number]=fetch("/pulls/"+str(number)+"/reviews?per_page=100",token)
        if not isinstance(reviews[number],list) or len(reviews[number])>=100:
            raise ProbeBlocked("INCOMPLETE_REVIEW_PAGINATION")
    branches={}
    for ref in a.LEGACY_REFS:
        branches[ref]=fetch("/branches/"+urllib.parse.quote(ref,safe=""),token)

    # The state-only repo and App token have not been provisioned / audited.
    # No source code is deployed on protected main. All remain hard blockers.
    findings=a.live_readiness(ruleset,pulls,reviews,branches)
    return {
        "schema":"gads.writer-authority-evidence.v1",
        "source_repo":a.SOURCE_REPO,
        "source_main_sha":(main.get("commit") or {}).get("sha"),
        "pr_stack":list(a.PR_STACK),
        "decision":"BLOCKED" if findings else "READY_FOR_EXTERNAL_APPROVAL",
        "findings":[{"code":f.code,"detail":f.detail} for f in findings],
        "writer_token_activated":False,
        "actual_state_write_performed":False
    }


def main():
    if os.environ.get("GITHUB_REPOSITORY") != a.SOURCE_REPO:
        raise SystemExit("BLOCKED: WRONG_ACTIONS_REPOSITORY")
    token=os.environ.get("GITHUB_TOKEN")
    if not token:
        raise SystemExit("BLOCKED: NO_READONLY_TOKEN")
    try:
        data=probe(token)
    except ProbeBlocked as exc:
        data={"schema":"gads.writer-authority-evidence.v1",
              "decision":"BLOCKED",
              "findings":[{"code":"READONLY_METADATA_UNAVAILABLE",
                           "detail":str(exc)}],
              "writer_token_activated":False,
              "actual_state_write_performed":False}
    print(json.dumps(data,sort_keys=True),flush=True)
    if data["decision"]!="READY_FOR_EXTERNAL_APPROVAL":
        raise SystemExit("BLOCKED_WRITER_AUTHORIZATION_NOT_GRANTED")


if __name__=="__main__":
    main()
