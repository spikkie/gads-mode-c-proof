"""Read-only fail-closed security posture gate for the public GADS proof."""
import json, os
from pathlib import Path
from scripts import c06_h00 as core

RULESET=25778767
ROOT=Path(__file__).resolve().parents[1]
WRITERS=(
".github/workflows/c06-h00-runtime.yml",
".github/workflows/c06-ttl-runtime.yml",
".github/workflows/c06-auto-runtime.yml",
".github/workflows/c07-cross-run.yml",
".github/workflows/c08-recovery.yml",
)
LISTENER=".github/workflows/c09-trusted-recovery.yml"

def assess(ruleset, files):
    findings=[]
    if ruleset.get("enforcement")!="active" or ruleset.get("bypass_actors")!=[]:
        findings.append("SEC-UNSAFE-RULESET")
    rules={r["type"]:(r.get("parameters") or {}) for r in ruleset.get("rules",[]) if isinstance(r,dict) and "type" in r}
    if not {"deletion","non_fast_forward","pull_request","required_status_checks"}.issubset(rules):
        findings.append("SEC-INCOMPLETE-BRANCH-PROTECTION")
    pr=rules.get("pull_request",{})
    if type(pr.get("required_approving_review_count")) is not int or pr["required_approving_review_count"]<1:
        findings.append("SEC-NO-HUMAN-APPROVAL")
    if pr.get("dismiss_stale_reviews_on_push") is not True:
        findings.append("SEC-STALE-APPROVALS")
    if pr.get("require_last_push_approval") is not True:
        findings.append("SEC-LAST-PUSH-NOT-APPROVED")
    checks=rules.get("required_status_checks",{})
    if checks.get("strict_required_status_checks_policy") is not True:
        findings.append("SEC-LOOSE-CHECKS")
    if not any(isinstance(x,dict) and x.get("context")=="quality" and type(x.get("integration_id")) is int
               for x in (checks.get("required_status_checks") or [])):
        findings.append("SEC-UNBOUND-QUALITY-CHECK")
    for path in WRITERS:
        body=files.get(path)
        if not isinstance(body,str):
            findings.append("SEC-MISSING:"+path)
        elif "on:\n  push:" in body and "qualification/" in body and (
              "      contents: write" in body or "      actions: write" in body):
            findings.append("SEC-UNPROTECTED-WRITER:"+path)
    listener=files.get(LISTENER)
    if not isinstance(listener,str) or "on:\n  workflow_run:" not in listener or (
        "contents: write" in listener or "actions: write" in listener):
        findings.append("SEC-PRIVILEGED-LISTENER")
    return sorted(set(findings))

def main():
    api=core.Github(os.environ.get("GITHUB_TOKEN"))
    repo=api.call("GET","")
    if repo.get("full_name")!=core.REPO or repo.get("private") is not False:
        raise core.Blocked("WRONG_REPOSITORY")
    rule=api.call("GET","/rulesets/"+str(RULESET))
    if rule.get("name")!="protect-main":
        raise core.Blocked("UNEXPECTED_RULESET")
    files={p:(ROOT/p).read_text() for p in (*WRITERS,LISTENER)}
    findings=assess(rule,files)
    print(json.dumps({"verdict":"BLOCKED" if findings else "PASS","findings":findings,
                      "ruleset_id":RULESET,"repository":core.REPO},sort_keys=True),flush=True)
    if findings:
        raise SystemExit("BLOCKED_SECURITY_POSTURE")
    print("GADS_SECURITY_POSTURE_PASS",flush=True)

if __name__=="__main__":
    main()
