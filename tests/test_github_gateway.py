"""Trusted gateway CAS, replay, identity and adversarial transport tests."""
import base64
from copy import deepcopy
import hashlib
import json
import unittest

from gads import h00
from gads.github_gateway import (
    ApiError, Blocked, Gateway, Policy, STATE_REF, STATE_FILE,
    MAX_STATE_BYTES, blob_hash, canonical,
)


class FakeGitHub:
    """Fake API server including immutable Git objects and competing ref CAS."""
    def __init__(self):
        self.policy = Policy()
        self.tip = "a" * 40
        self.tree = "b" * 40
        self.current = h00.new(self.policy.work_id, self.policy.trusted_main_sha,
                               self.policy.repository_id, self.policy.workflow_id,
                               max_attempts=1, units_limit=2)
        self.raw = canonical(self.current)
        self.created_blobs = {}
        self.commits = {}
        self.posts = []
        self.cas_calls = []
        self.uncertain_after_commit = False
        self.reject_patch = None
        self.bad_readback = False
        self.mutate_blob = False
        self.unsafe_main = False
        self.wrong_repo = False
        self.target_override = {}
        self.last_target = None

    def graphql(self, query, variables):
        self.cas_calls.append((query, deepcopy(variables)))
        assert "updateRefs" in query and "UpdateRefsInput!" in query
        op = variables["input"]
        assert op["repositoryId"] == "R_kgDO-public-synthetic-cas"
        assert len(op["refUpdates"]) == 1
        update = op["refUpdates"][0]
        assert update["name"] == STATE_REF and update["force"] is False
        if self.reject_patch in (409,422):
            return {"errors":[{"message":"beforeOid mismatch"}]}
        if update["beforeOid"] != self.tip:
            return {"errors":[{"message":"beforeOid mismatch"}]}
        assert update["afterOid"] == self.pending_sha
        self.tip = self.pending_sha
        self.tree = self.new_tree
        self.raw = self.created_blobs[self.pending_blob]
        self.current = json.loads(self.raw)
        if self.bad_readback:
            self.tip = "e" * 40
        if self.uncertain_after_commit:
            raise ApiError(504)
        return {"data":{"updateRefs":{"clientMutationId":op["clientMutationId"]}}}

    def call(self, method, path, payload=None):
        prefix = "/repos/" + self.policy.repository
        assert path.startswith(prefix), path
        route = path[len(prefix):]
        if method == "GET":
            if route == "":
                return {"id": self.policy.repository_id + int(self.wrong_repo),
                        "full_name": self.policy.repository,
                        "node_id": "R_kgDO-public-synthetic-cas",
                        "private": False, "default_branch": "main"}
            if route == "/branches/main":
                return {"protected": not self.unsafe_main,
                        "commit":{"sha": self.policy.trusted_main_sha}}
            if route == "/git/ref/" + STATE_REF[5:]:
                return {"ref": STATE_REF, "object":{"type":"commit", "sha":self.tip}}
            if route == "/contents/" + STATE_FILE + "?ref=" + self.tip:
                raw = self.raw + (b"x" if self.mutate_blob else b"")
                return {"path":STATE_FILE,"type":"file","size":len(raw),
                        "sha":blob_hash(self.raw), "encoding":"base64",
                        "content":base64.b64encode(raw).decode("ascii")}
            if route == "/git/commits/" + self.tip:
                return {"sha":self.tip, "tree":{"sha":self.tree}}
            if route.startswith("/actions/runs/"):
                identifier=int(route.rsplit("/",1)[-1])
                self.last_target=identifier
                s=self.current
                result={
                    "id":identifier, "workflow_id":s["workflow_id"],
                    "head_sha":s["source_sha"], "head_branch":"main",
                    "event":"workflow_dispatch", "status":"completed",
                    "conclusion":"success","actor":{"login":"github-actions[bot]"},
                    "repository":{"id":s["repo_id"]},
                    "head_repository":{"id":s["repo_id"]},
                    "display_title":"GADS-H00-"+s["correlation"]}
                return result | self.target_override
            raise AssertionError("unexpected GET: "+route)
        if method == "POST":
            self.posts.append((route, deepcopy(payload)))
            if route == "/git/blobs":
                raw=payload["content"].encode("ascii")
                sha=blob_hash(raw)
                self.created_blobs[sha]=raw
                return {"sha":sha}
            if route == "/git/trees":
                assert payload["base_tree"]==self.tree
                entry=payload["tree"][0]
                assert entry["path"]==STATE_FILE and entry["mode"]=="100644"
                assert entry["type"]=="blob"
                self.new_tree="c"*40
                self.pending_blob=entry["sha"]
                return {"sha":self.new_tree}
            if route == "/git/commits":
                assert payload["parents"]==[self.tip]
                assert payload["tree"]==self.new_tree
                self.pending_sha="d"*40
                self.commits[self.pending_sha]=payload
                return {"sha":self.pending_sha}
            raise AssertionError("unexpected POST: "+route)
        raise AssertionError("unexpected method: "+method)


class GatewayTests(unittest.TestCase):
    def setUp(self):
        self.api=FakeGitHub()
        self.p=self.api.policy
        self.g=Gateway(self.api,self.p, "refs/heads/main",self.p.trusted_main_sha)

    def command(self,kind="claim",id="evt-1",**rest):
        return {"id":id,"kind":kind,**rest}

    def claim(self):
        return self.g.transition(self.command(owner="h00-controller"),100)

    def test_identity_and_initial_load(self):
        tip,state=self.g.read()
        self.assertEqual(tip,"a"*40)
        self.assertEqual(state["stage"],"QUEUED")

    def test_claim_is_durable_cas(self):
        receipt=self.claim()
        self.assertTrue(receipt["changed"])
        self.assertEqual(receipt["ref_sha"],"d"*40)
        self.assertEqual(receipt["state"]["stage"],"LEASED")
        self.assertEqual(receipt["state"]["units_reserved"],1)
        self.assertEqual(len(self.api.cas_calls),1)
        self.assertFalse(self.api.cas_calls[0][1]["input"]["refUpdates"][0]["force"])

    def test_duplicate_exact_event_no_mutation(self):
        self.claim()
        start=len(self.api.posts)
        replay=self.g.transition(self.command(owner="h00-controller"),101)
        self.assertEqual(replay["changed"],False)
        self.assertEqual(len(self.api.posts),start)
        self.assertEqual(len(self.api.cas_calls),1)

    def test_replay_id_collision_denied(self):
        self.claim()
        with self.assertRaisesRegex(h00.Blocked,"REPLAY_COLLISION"):
            self.g.transition(self.command(owner="h00-controller",id="evt-1",
                                           fence="f999"),102)
        self.assertEqual(len(self.api.cas_calls),1)

    def test_stale_owner_denied(self):
        with self.assertRaisesRegex(Blocked,"CLAIM_OWNER_DENIED"):
            self.g.transition(self.command(owner="attacker"),100)

    def test_untrusted_runner_ref_denied_before_write(self):
        g=Gateway(self.api,self.p,"refs/heads/development/gads-gateway",
                  self.p.trusted_main_sha)
        with self.assertRaisesRegex(Blocked,"UNTRUSTED_RUNNER_ORIGIN"):
            g.transition(self.command(owner="h00-controller"),100)
        self.assertEqual(len(self.api.posts),0)

    def test_untrusted_runner_sha_denied(self):
        g=Gateway(self.api,self.p,"refs/heads/main","f"*40)
        with self.assertRaisesRegex(Blocked,"UNTRUSTED_RUNNER_ORIGIN"):
            g.read()

    def test_changed_main_is_denied(self):
        self.api.unsafe_main=True
        with self.assertRaisesRegex(Blocked,"TRUSTED_MAIN_CHANGED"):
            self.g.read()

    def test_repository_mismatch_denied(self):
        self.api.wrong_repo=True
        with self.assertRaisesRegex(Blocked,"REPOSITORY_MISMATCH"):
            self.g.read()

    def test_repository_policy_tamper_denied(self):
        from dataclasses import replace
        p=replace(self.p, trusted_owner="mallory")
        g=Gateway(self.api,p,"refs/heads/main",p.trusted_main_sha)
        with self.assertRaisesRegex(Blocked,"POLICY_NOT_REVIEWED"):
            g.read()

    def test_blob_tampering_denied(self):
        self.api.mutate_blob=True
        with self.assertRaisesRegex(Blocked,"STATE_BLOB_MISMATCH"):
            self.g.read()

    def test_state_identity_tamper_denied(self):
        self.api.current["work_id"]="elsewhere"
        self.api.raw=canonical(self.api.current)
        with self.assertRaisesRegex(Blocked,"STATE_SCOPE"):
            self.g.read()

    def test_conflict_409_never_retry(self):
        self.api.reject_patch=409
        with self.assertRaisesRegex(Blocked,"CAS_REJECTED_NO_RETRY"):
            self.claim()
        self.assertEqual(len(self.api.cas_calls),1)
        self.assertEqual(self.api.tip,"a"*40)

    def test_conflict_422_never_retry(self):
        self.api.reject_patch=422
        with self.assertRaisesRegex(Blocked,"CAS_REJECTED_NO_RETRY"):
            self.claim()
        self.assertEqual(len(self.api.cas_calls),1)

    def test_post_commit_readback_mismatch_blocks(self):
        self.api.bad_readback=True
        with self.assertRaisesRegex(Blocked,"CAS_READBACK_MISMATCH"):
            self.claim()
        self.assertEqual(len(self.api.cas_calls),1)

    def test_missing_ref_denied(self):
        original=self.api.call
        def missing(method,path,payload=None):
            if "/git/ref/heads/" in path:
                raise ApiError(404)
            return original(method,path,payload)
        self.api.call=missing
        with self.assertRaises(ApiError) as exc:
            self.g.read()
        self.assertEqual(exc.exception.status,404)

    def test_unauthorized_target_object_denied(self):
        self.claim()
        with self.assertRaisesRegex(Blocked,"TARGET_ID_ONLY"):
            self.g.transition(self.command("confirm","evt-2", owner="h00-controller",
                                            fence="f1",target={"id":40093613654}),101)

    def test_confirm_with_independent_lookup(self):
        self.claim()
        receipt=self.g.transition(self.command("confirm","evt-2",
                              owner="h00-controller",fence="f1",target=40093613654),101)
        self.assertEqual(receipt["state"]["stage"],"COMPLETED")
        self.assertEqual(receipt["state"]["target_run"],40093613654)
        self.assertEqual(self.api.last_target,40093613654)

    def test_missing_correlation_blocks_before_state_write(self):
        self.claim()
        self.api.target_override["display_title"]="ambiguous"
        with self.assertRaisesRegex(Blocked,"TARGET_NOT_ATTESTED"):
            self.g.transition(self.command("confirm","evt-2",owner="h00-controller",
                                            fence="f1",target=40093613654),101)
        self.assertEqual(len(self.api.cas_calls),1)

    def test_wrong_target_workflow_denied(self):
        self.claim()
        self.api.target_override["workflow_id"]=0
        with self.assertRaisesRegex(Blocked,"TARGET_NOT_ATTESTED"):
            self.g.transition(self.command("confirm","evt-2",owner="h00-controller",
                                            fence="f1",target=40093613654),101)

    def test_wrong_actor_denied(self):
        self.claim()
        self.api.target_override["actor"]={"login":"bad-actor"}
        with self.assertRaisesRegex(Blocked,"TARGET_NOT_ATTESTED"):
            self.g.transition(self.command("confirm","evt-2",owner="h00-controller",
                                            fence="f1",target=40093613654),101)

    def test_wrong_repository_and_head_repo_denied(self):
        self.claim()
        self.api.target_override["head_repository"]={"id":123}
        with self.assertRaisesRegex(Blocked,"TARGET_NOT_ATTESTED"):
            self.g.transition(self.command("confirm","evt-2",owner="h00-controller",
                                            fence="f1",target=40093613654),101)

    def test_failed_external_run_not_confirmed(self):
        self.claim()
        self.api.target_override["conclusion"]="failure"
        with self.assertRaisesRegex(Blocked,"TARGET_NOT_ATTESTED"):
            self.g.transition(self.command("confirm","evt-2",owner="h00-controller",
                                            fence="f1",target=40093613654),101)

    def test_unknown_effect_disallows_reclaim(self):
        self.claim()
        u=self.g.transition(self.command("unknown","evt-2",
                             owner="h00-controller",fence="f1"),105)
        self.assertEqual(u["state"]["stage"],"UNKNOWN")
        with self.assertRaisesRegex(h00.Blocked,"CLAIM_DENIED"):
            self.g.transition(self.command("claim","evt-3",
                              owner="h00-controller"),200)

    def test_no_force_no_arbitrary_state_file(self):
        self.claim()
        requested=[x[1]["input"]["refUpdates"][0] for x in self.api.cas_calls]
        self.assertEqual(len(requested),1)
        self.assertEqual(requested[0]["name"], STATE_REF)
        self.assertEqual(requested[0]["beforeOid"],"a"*40)
        self.assertEqual(requested[0]["afterOid"],"d"*40)
        self.assertIs(requested[0]["force"],False)
        writes=[x for x in self.api.posts if x[0]=="/git/trees"]
        self.assertEqual(len(writes),1)
        self.assertEqual(writes[0][1]["tree"][0]["path"],"state/h00.json")



    def test_graphql_server_side_before_oid_required(self):
        self.claim()
        body=self.api.cas_calls[0][1]["input"]
        self.assertEqual(body["repositoryId"],"R_kgDO-public-synthetic-cas")
        self.assertEqual(body["refUpdates"][0]["beforeOid"],"a"*40)
        self.assertEqual(body["refUpdates"][0]["afterOid"],"d"*40)

    def test_unknown_ack_after_committed_state_is_not_retried(self):
        self.api.uncertain_after_commit=True
        with self.assertRaisesRegex(Blocked,"CAS_OUTCOME_UNKNOWN_NO_RETRY"):
            self.claim()
        self.assertEqual(len(self.api.cas_calls),1)
        self.assertEqual(self.api.current["stage"],"LEASED")
        self.assertEqual(self.api.tip,"d"*40)
        self.api.uncertain_after_commit=False
        read_tip,state=self.g.read()
        self.assertEqual(read_tip,"d"*40)
        self.assertEqual(state["units_reserved"],1)

    def test_same_old_ref_cannot_overwrite_advanced_tip(self):
        self.claim()
        # second writer already knew old head but cannot update after it moved
        answer=self.api.graphql("mutation UpdateRefs($input: UpdateRefsInput!) { updateRefs(input:$input) { clientMutationId } }",
          {"input":{"repositoryId":"R_kgDO-public-synthetic-cas",
                    "clientMutationId":"second-writer",
                    "refUpdates":[{"name":STATE_REF,"beforeOid":"a"*40,
                                   "afterOid":"d"*40,"force":False}]}})
        self.assertTrue(answer.get("errors"))
        self.assertEqual(self.api.tip,"d"*40)

    def test_missing_mutation_ack_denied_no_retry(self):
        original=self.api.graphql
        def missing_ack(query,vars):
            original(query,vars)
            return {"data":{"updateRefs":None}}
        self.api.graphql=missing_ack
        with self.assertRaisesRegex(Blocked,"CAS_OUTCOME_UNKNOWN_NO_RETRY"):
            self.claim()
        self.assertEqual(len(self.api.cas_calls),1)

    def test_repo_graphql_node_id_is_required(self):
        original=self.api.call
        def without_node_id(method,path,payload=None):
            result=original(method,path,payload)
            if method=="GET" and path.endswith("/gads-mode-c-proof"):
                result.pop("node_id",None)
            return result
        self.api.call=without_node_id
        with self.assertRaisesRegex(Blocked,"CAS_REPOSITORY_NODE_ID"):
            self.claim()
        self.assertEqual(len(self.api.cas_calls),0)

    def test_blob_digest_known(self):
        self.assertEqual(blob_hash(b"hello\n"),
                         hashlib.sha1(b"blob 6\0hello\n").hexdigest())
