"""Read-only live GitHub provenance smoke for the clean gateway candidate.

Runs with read permissions only. This is a historical API consistency probe,
NOT proof that future target run-name correlation is configured or trustworthy.
"""
import json
import os
import urllib.error
import urllib.request
from gads.github_gateway import Blocked, Policy, require

TARGET_RUN = 40093613654


def verify_snapshot(repo, main, run):
    p = Policy()
    require(repo.get("full_name") == p.repository
            and repo.get("id") == p.repository_id
            and repo.get("private") is False
            and repo.get("default_branch") == "main", "PROBE_REPOSITORY")
    require(main.get("protected") is True
            and (main.get("commit") or {}).get("sha") == p.trusted_main_sha,
            "PROBE_MAIN_DRIFT")
    require(run.get("id") == TARGET_RUN
            and run.get("workflow_id") == p.workflow_id
            and run.get("head_sha") == p.trusted_main_sha
            and run.get("head_branch") == "main"
            and run.get("event") == "workflow_dispatch"
            and run.get("status") == "completed"
            and run.get("conclusion") == "success"
            and (run.get("actor") or {}).get("login") == "github-actions[bot]"
            and (run.get("repository") or {}).get("id") == p.repository_id
            and (run.get("head_repository") or {}).get("id") == p.repository_id,
            "PROBE_HISTORICAL_RUN")
    return True


def fetch(path, token):
    p = Policy()
    url = "https://api.github.com/repos/" + p.repository + path
    request = urllib.request.Request(url, headers={
        "Accept": "application/vnd.github+json",
        "Authorization": "Bearer " + token,
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "gads-readonly-e1-candidate"
    }, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            if response.status != 200:
                raise Blocked("PROBE_HTTP_STATUS")
            body = response.read(300001)
    except urllib.error.HTTPError as exc:
        raise Blocked("PROBE_API_" + str(exc.code)) from None
    require(len(body) <= 300000, "PROBE_RESPONSE_TOO_LARGE")
    result=json.loads(body)
    require(isinstance(result, dict), "PROBE_RESPONSE_SHAPE")
    return result


def main():
    p=Policy()
    require(os.environ.get("GITHUB_REPOSITORY") == p.repository, "PROBE_CONTEXT")
    token=os.environ.get("GITHUB_TOKEN")
    require(isinstance(token,str) and bool(token), "PROBE_TOKEN_ABSENT")
    repo=fetch("",token)
    main=fetch("/branches/main",token)
    run=fetch("/actions/runs/" + str(TARGET_RUN), token)
    verify_snapshot(repo,main,run)
    print("GADS_GATEWAY_LIVE_READONLY_PASS main_sha=" +
          p.trusted_main_sha + " prior_target=" + str(TARGET_RUN))


if __name__=="__main__":
    try:
        main()
    except (Blocked, KeyError, TypeError, ValueError) as exc:
        raise SystemExit("BLOCKED: " + str(exc)) from None
