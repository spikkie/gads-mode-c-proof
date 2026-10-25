"""Bounded, injectable GitHub REST gateway for one canonical H-00 state ref.

SECURITY: executable design candidate only. Never run source from an unprotected
ref with contents:write; future privileged deployment needs review and approval.
This module neither obtains a token nor schedules/dispatched workflows.
"""
import base64
from dataclasses import dataclass
from hashlib import sha1
import json
from urllib.parse import quote

from gads import h00


class ApiError(Exception):
    """Transport must raise this with the original GitHub HTTP status."""
    def __init__(self, status):
        self.status = status
        super().__init__("GITHUB_HTTP_" + str(status))


class Blocked(h00.Blocked):
    """Fail-closed state, provenance or CAS failure."""


STATE_REF = "refs/heads/qualification/gads-h00-state-v1"
STATE_FILE = "state/h00.json"
MAX_STATE_BYTES = 16384
GRAPHQL_CAS_MUTATION = '''mutation GadsCAS($input: UpdateRefsInput!) { updateRefs(input: $input) { clientMutationId } }'''


@dataclass(frozen=True)
class Policy:
    repository: str = "spikkie/gads-mode-c-proof"
    repository_id: int = 1432047514
    trusted_main_sha: str = "43cb1e6924d208288350d70b7b273f7cd3def0c4"
    work_id: str = "synthetic-gateway-p1"
    workflow_id: int = 395007460
    trusted_owner: str = "h00-controller"


def require(ok, code):
    if not ok:
        raise Blocked(code)


def canonical(state):
    h00.validate(state)
    raw = json.dumps(state, sort_keys=True, separators=(",", ":"),
                     ensure_ascii=True, allow_nan=False).encode("ascii") + b"\n"
    require(len(raw) <= MAX_STATE_BYTES, "STATE_TOO_LARGE")
    return raw


def blob_hash(raw):
    return sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()


class Gateway:
    """API adapter requires call(method, path, payload=None); no built-in token.

    The policy is supplied by separately reviewed trusted code, NEVER from
    an untrusted workflow event, PR branch or repository artifact.
    """
    def __init__(self, api, policy, runner_ref, runner_sha):
        self.api = api
        self.policy = policy
        self.runner_ref = runner_ref
        self.runner_sha = runner_sha
        self.prefix = "/repos/" + policy.repository

    def _get(self, path):
        return self.api.call("GET", self.prefix + path)

    def _post(self, path, payload):
        return self.api.call("POST", self.prefix + path, payload)

    def _atomic_cas(self, before, after):
        """Atomic compare-and-swap via GitHub GraphQL updateRefs.beforeOid.

        Unknown transport/acknowledgement outcome must not be retried blindly.
        """
        metadata = self._get("")
        require(metadata.get("id") == self.policy.repository_id and
                metadata.get("full_name") == self.policy.repository and
                isinstance(metadata.get("node_id"), str) and
                bool(metadata["node_id"]), "CAS_REPOSITORY_NODE_ID")
        nonce = "gads-cas-" + before[:12] + "-" + after[:12]
        values = {"input": {
            "repositoryId": metadata["node_id"],
            "clientMutationId": nonce,
            "refUpdates": [{
                "name": STATE_REF,
                "beforeOid": before,
                "afterOid": after,
                "force": False
            }]
        }}
        try:
            reply = self.api.graphql(GRAPHQL_CAS_MUTATION, values)
        except (ApiError, OSError, TimeoutError) as exc:
            raise Blocked("CAS_OUTCOME_UNKNOWN_NO_RETRY") from exc
        if not isinstance(reply, dict):
            raise Blocked("CAS_OUTCOME_UNKNOWN_NO_RETRY")
        if reply.get("errors"):
            raise Blocked("CAS_REJECTED_NO_RETRY")
        data = reply.get("data")
        result = data.get("updateRefs") if isinstance(data, dict) else None
        if not isinstance(result, dict) or result.get("clientMutationId") != nonce:
            raise Blocked("CAS_OUTCOME_UNKNOWN_NO_RETRY")

    def authorize(self):
        p = self.policy
        require(p.repository == "spikkie/gads-mode-c-proof" and
                p.repository_id == 1432047514 and
                p.workflow_id == 395007460 and
                p.work_id == "synthetic-gateway-p1" and
                p.trusted_owner == "h00-controller" and
                p.trusted_main_sha == "43cb1e6924d208288350d70b7b273f7cd3def0c4",
                "POLICY_NOT_REVIEWED")
        require(self.runner_ref == "refs/heads/main" and
                self.runner_sha == p.trusted_main_sha, "UNTRUSTED_RUNNER_ORIGIN")
        repo = self._get("")
        require(repo.get("id") == p.repository_id and
                repo.get("full_name") == p.repository and
                repo.get("private") is False and
                repo.get("default_branch") == "main", "REPOSITORY_MISMATCH")
        main = self._get("/branches/main")
        require(main.get("protected") is True and
                (main.get("commit") or {}).get("sha") == p.trusted_main_sha,
                "TRUSTED_MAIN_CHANGED")

    def read(self):
        """Return (immutable ref SHA, validated state). Missing ref is not seeded."""
        self.authorize()
        ref = self._get("/git/ref/" + STATE_REF[5:])
        obj = ref.get("object") or {}
        tip = obj.get("sha")
        require(ref.get("ref") == STATE_REF and obj.get("type") == "commit"
                and isinstance(tip, str) and h00.HEX40.fullmatch(tip),
                "STATE_REF_NOT_TRUSTED")
        entry = self._get("/contents/" + STATE_FILE + "?ref=" + quote(tip, safe=""))
        require(entry.get("path") == STATE_FILE
                and entry.get("type") == "file"
                and entry.get("encoding") == "base64"
                and isinstance(entry.get("content"), str)
                and type(entry.get("size")) is int
                and entry["size"] <= MAX_STATE_BYTES,
                "STATE_CONTENT_METADATA")
        try:
            raw = base64.b64decode(entry["content"], validate=False)
            require(len(raw) == entry["size"] and
                    entry.get("sha") == blob_hash(raw), "STATE_BLOB_MISMATCH")
            state = json.loads(raw.decode("ascii"))
        except Blocked:
            raise
        except (ValueError, UnicodeError, TypeError, KeyError) as exc:
            raise Blocked("STATE_DECODING") from exc
        try:
            require(raw == canonical(state), "STATE_NOT_CANONICAL")
        except (h00.Blocked, ValueError, TypeError) as exc:
            raise Blocked("STATE_INVALID") from exc
        p = self.policy
        require(state["work_id"] == p.work_id and
                state["repo_id"] == p.repository_id and
                state["workflow_id"] == p.workflow_id and
                state["source_sha"] == p.trusted_main_sha,
                "STATE_SCOPE")
        return tip, state

    def attest(self, state, target_run):
        """Query GitHub, never trust claims in a caller-provided target object.

        Exact correlation needs a REVIEWED default-branch target workflow with:
          run-name: GADS-H00-${{ inputs.correlation }}
        GitHub's display_title API mapping must be LIVE verified before adoption.
        """
        require(h00.number(target_run, 1), "INVALID_TARGET_RUN")
        run = self._get("/actions/runs/" + str(target_run))
        actor = run.get("actor") or {}
        repository = run.get("repository") or {}
        head_repo = run.get("head_repository") or {}
        require(run.get("id") == target_run and
                run.get("workflow_id") == state["workflow_id"] and
                run.get("head_sha") == state["source_sha"] and
                run.get("head_branch") == "main" and
                run.get("event") == "workflow_dispatch" and
                run.get("status") == "completed" and
                run.get("conclusion") == "success" and
                actor.get("login") == "github-actions[bot]" and
                repository.get("id") == state["repo_id"] and
                head_repo.get("id") == state["repo_id"] and
                run.get("display_title") == "GADS-H00-" + state["correlation"],
                "TARGET_NOT_ATTESTED")
        return dict(id=target_run, repo_id=state["repo_id"],
                    workflow_id=state["workflow_id"],
                    source_sha=state["source_sha"],
                    correlation=state["correlation"],
                    event="workflow_dispatch", actor="github-actions[bot]",
                    status="completed", conclusion="success")

    def transition(self, event, now):
        """Single CAS attempt. No automatic retry, force update or side effects.

        This may CREATE unreachable Git objects before the atomic beforeOid
        validation. Unknown or rejected outcomes are fail-closed, no retries.
        """
        tip, current = self.read()
        require(isinstance(event, dict), "EVENT_TYPE")
        command = dict(event)
        if command.get("kind") == "claim":
            require(command.get("owner") == self.policy.trusted_owner,
                    "CLAIM_OWNER_DENIED")
        if command.get("kind") in ("unknown", "confirm"):
            require(command.get("owner") == current["owner"]
                    and command.get("fence") == current["fence"]
                    and current["owner"] == self.policy.trusted_owner,
                    "STALE_OWNER_OR_FENCE")
        if command.get("kind") == "block" and current["attempts"] > 0:
            require(command.get("owner") == current["owner"]
                    and command.get("fence") == current["fence"],
                    "BLOCK_OWNER_DENIED")
        if command.get("kind") == "confirm":
            require(type(command.get("target")) is int, "TARGET_ID_ONLY")
            command["target"] = self.attest(current, command["target"])
        after = h00.transition(current, command, now)
        if after == current:
            return {"changed": False, "ref_sha": tip, "state": after}
        raw = canonical(after)
        old = self._get("/git/commits/" + tip)
        tree = (old.get("tree") or {}).get("sha")
        require(isinstance(tree, str) and h00.HEX40.fullmatch(tree),
                "PARENT_TREE_UNVERIFIED")
        blob = self._post("/git/blobs", {"content": raw.decode("ascii"),
                                        "encoding": "utf-8"})
        require(blob.get("sha") == blob_hash(raw), "CREATED_BLOB_NOT_VERIFIED")
        newtree = self._post("/git/trees", {
            "base_tree": tree,
            "tree": [{"path": STATE_FILE, "mode": "100644",
                      "type": "blob", "sha": blob["sha"]}]})
        new_tree_sha = newtree.get("sha")
        require(isinstance(new_tree_sha, str) and
                h00.HEX40.fullmatch(new_tree_sha), "TREE_UNVERIFIED")
        commit = self._post("/git/commits", {
            "message": "gads(h00): durable transition " + after["stage"],
            "tree": new_tree_sha, "parents": [tip]})
        sha = commit.get("sha")
        require(isinstance(sha, str) and h00.HEX40.fullmatch(sha),
                "COMMIT_UNVERIFIED")
        self._atomic_cas(tip, sha)
        observed_tip, observed_state = self.read()
        require(observed_tip == sha and observed_state == after,
                "CAS_READBACK_MISMATCH")
        return {"changed": True, "ref_sha": sha, "state": after}
