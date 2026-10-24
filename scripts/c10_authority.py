"""C-10 read-only *live* inventory of active write-enabled unprotected-branch workflows.

This is a security diagnostic, not permission to remove branch protections.
Neither GitHub state nor any workflows are mutated.
"""
import base64
import fnmatch
import json
import os
import urllib.parse
import yaml
from scripts import c06_h00 as core

BRANCHES = (
    "qualification/c05-negative-runtime-20261024",
    "qualification/c06-h00-live-20261024",
    "qualification/c07-trusted-cross-run-20261024",
    "qualification/c08-reconcile-20261024",
    "qualification/c09-trusted-trigger-20261024",
    "qualification/c10-least-privilege-20261024",
)
RISK_EVENTS = ("push", "pull_request", "pull_request_target")
WRITE_PERMS = ("write", "write-all")
ROOT = "/contents/.github/workflows"


def triggered(doc, branch):
    if not isinstance(doc, dict) or "on" not in doc:
        raise core.Blocked("C10_TRIGGER_UNREADABLE")
    ev = doc["on"]
    if isinstance(ev, str):
        ev = {ev: None}
    if isinstance(ev, list):
        ev = dict.fromkeys(ev)
    if not isinstance(ev, dict):
        raise core.Blocked("C10_TRIGGER_SCHEMA")
    if "pull_request" in ev or "pull_request_target" in ev:
        return True
    if "push" not in ev:
        return False
    options = ev["push"]
    if options is None or options == "":
        return True
    if not isinstance(options, dict):
        raise core.Blocked("C10_PUSH_SCHEMA")
    allow = options.get("branches")
    exclude = options.get("branches-ignore")
    if allow is not None and exclude is not None:
        raise core.Blocked("C10_CONFLICTING_BRANCH_FILTERS")
    if allow is not None:
        patterns = allow if isinstance(allow, list) else [allow]
        if not patterns or not all(isinstance(x, str) for x in patterns):
            raise core.Blocked("C10_BAD_BRANCH_GLOBS")
        return any(fnmatch.fnmatchcase(branch, x) for x in patterns)
    if exclude is not None:
        patterns = exclude if isinstance(exclude, list) else [exclude]
        if not patterns or not all(isinstance(x, str) for x in patterns):
            raise core.Blocked("C10_BAD_IGNORE_GLOBS")
        return not any(fnmatch.fnmatchcase(branch, x) for x in patterns)
    return True


def write_permissions(value):
    if value is None:
        return False
    if isinstance(value, str):
        if value in WRITE_PERMS:
            return True
        if value in ("read-all", "none"):
            return False
        raise core.Blocked("C10_UNKNOWN_GLOBAL_PERMISSIONS")
    if not isinstance(value, dict):
        raise core.Blocked("C10_BAD_PERMISSIONS")
    return any(str(v) == "write" for v in value.values())


def risky_workflow(text, branch):
    try:
        data = yaml.load(text, Loader=yaml.BaseLoader)
    except yaml.YAMLError:
        raise core.Blocked("C10_INVALID_WORKFLOW_YAML") from None
    if not triggered(data, branch):
        return []
    problems = []
    if write_permissions(data.get("permissions")):
        problems.append("workflow-level-write")
    jobs = data.get("jobs")
    if not isinstance(jobs, dict) or not jobs:
        raise core.Blocked("C10_JOBS_SCHEMA")
    for name, details in sorted(jobs.items()):
        if not isinstance(details, dict):
            raise core.Blocked("C10_JOB_SCHEMA")
        if write_permissions(details.get("permissions")):
            problems.append("job:"+name+":write")
    return problems


def live(api):
    result = []
    for name in BRANCHES:
        branch = api.call("GET", "/branches/" + urllib.parse.quote(name, safe=""))
        sha = branch.get("commit", {}).get("sha")
        if not isinstance(sha, str) or not core.HEX40.fullmatch(sha):
            raise core.Blocked("C10_BRANCH_SHA_INVALID")
        protected = branch.get("protected")
        if type(protected) is not bool:
            raise core.Blocked("C10_BRANCH_PROTECTION_UNKNOWN")
        ref = urllib.parse.quote(sha, safe="")
        directory = api.call("GET", ROOT + "?ref=" + ref)
        if not isinstance(directory, list) or not directory or len(directory) >= 1000:
            raise core.Blocked("C10_WORKFLOW_LIST_INCOMPLETE")
        for entry in directory:
            path = entry.get("path")
            if entry.get("type") != "file" or not isinstance(path, str) or not path.startswith(".github/workflows/"):
                raise core.Blocked("C10_WORKFLOW_ENTRY_UNEXPECTED")
            item = api.call("GET", "/contents/" + path + "?ref=" + ref)
            encoded = item.get("content")
            if not isinstance(encoded, str) or item.get("encoding") != "base64":
                raise core.Blocked("C10_WORKFLOW_CONTENT_NOT_BASE64")
            try:
                raw = base64.b64decode(encoded, validate=False)
                if item.get("sha") != core.digest_blob(raw):
                    raise core.Blocked("C10_WORKFLOW_BLOB_MISMATCH")
                workflow = raw.decode("utf-8")
            except (ValueError, UnicodeError):
                raise core.Blocked("C10_WORKFLOW_CONTENT_INVALID") from None
            findings = risky_workflow(workflow, name)
            for finding in findings:
                if not protected:
                    result.append({"branch": name, "sha": sha, "workflow": path,
                                   "finding": finding, "protected": False})
    return result


def main():
    api = core.Github(os.environ.get("GITHUB_TOKEN"))
    repo = api.call("GET", "")
    if repo.get("full_name") != core.REPO or repo.get("private") is not False:
        raise core.Blocked("C10_WRONG_PUBLIC_REPOSITORY")
    issues = live(api)
    print(json.dumps({"schema": "gads.c10.branch-authority.v1",
                      "verdict": "BLOCKED" if issues else "NO_EXPOSED_BRANCH_WRITE_GRANTS",
                      "findings": issues}, sort_keys=True), flush=True)
    if issues:
        raise SystemExit("BLOCKED_C10_UNPROTECTED_WRITE_WORKFLOWS")
    print("C10_BRANCH_AUTHORITY_INVENTORY_CLEAN_NOT_SECURITY_APPROVAL", flush=True)


if __name__ == "__main__":
    try:
        main()
    except (core.Blocked, OSError, ValueError, KeyError) as exc:
        raise SystemExit("BLOCKED: " + str(exc)) from None
