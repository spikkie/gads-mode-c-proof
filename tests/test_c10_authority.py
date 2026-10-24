"""C10 branch-authority adversarial fixtures."""
import unittest
from scripts import c10_authority as a
from scripts.c06_h00 import Blocked

def yaml_for(on, permissions, jobs=None):
    return "name: synthetic\non:\n"+on+"\npermissions:\n"+permissions+"\njobs:\n"+(jobs or
       "  unit:\n    runs-on: ubuntu-24.04\n    permissions:\n      contents: read\n")

class AuthorityTests(unittest.TestCase):
    def test_unprotected_push_job_writer_flagged(self):
        code=yaml_for("  push:\n    branches: [qualification/c06-h00-live-20261024]",
                      "  contents: read",
                      "  writer:\n    runs-on: ubuntu-24.04\n    permissions:\n      contents: write\n")
        self.assertEqual(a.risky_workflow(code,"qualification/c06-h00-live-20261024"),
                         ["job:writer:write"])

    def test_actions_write_detected(self):
        code=yaml_for("  push:","  contents: read",
                      "  dispatch:\n    runs-on: ubuntu-24.04\n    permissions:\n      actions: write\n")
        self.assertEqual(a.risky_workflow(code,"qualification/c07-trusted-cross-run-20261024"),
                         ["job:dispatch:write"])

    def test_default_branch_workflow_dispatch_not_branch_push(self):
        code="name: safe\non:\n  workflow_dispatch:\npermissions: {}\njobs:\n  job:\n    runs-on: ubuntu-24.04\n    permissions:\n      contents: write\n"
        self.assertEqual(a.risky_workflow(code,"qualification/c06-h00-live-20261024"),[])

    def test_branch_filters_honored(self):
        code=yaml_for("  push:\n    branches: [qualification/c08-reconcile-20261024]",
                       "  contents: write")
        self.assertEqual(a.risky_workflow(code,"qualification/c07-trusted-cross-run-20261024"),[])

    def test_pr_writer_is_flagged(self):
        code=yaml_for("  pull_request:","  contents: write")
        self.assertEqual(a.risky_workflow(code,"qualification/c08-reconcile-20261024"),
                         ["workflow-level-write"])

    def test_read_only_is_safe(self):
        code=yaml_for("  push:","  contents: read")
        self.assertEqual(a.risky_workflow(code,"qualification/c06-h00-live-20261024"),[])

    def test_yaml_11_on_keyword_is_resolved_correctly(self):
        code="name: safe\non:\n  push:\npermissions: {}\njobs:\n  t:\n    runs-on: ubuntu-24.04\n    permissions:\n      contents: write\n"
        self.assertEqual(len(a.risky_workflow(code,"qualification/c09-trusted-trigger-20261024")),1)

    def test_missing_trigger_blocks(self):
        with self.assertRaisesRegex(Blocked,"C10_TRIGGER_UNREADABLE"):
            a.risky_workflow("name: missing\njobs:\n  task:\n    runs-on: ubuntu-24.04\n",
                             "qualification/c06-h00-live-20261024")

    def test_unknown_permissions_block(self):
        with self.assertRaisesRegex(Blocked,"C10_UNKNOWN_GLOBAL_PERMISSIONS"):
            a.write_permissions("inherit")

    def test_write_all_blocks(self):
        self.assertTrue(a.write_permissions("write-all"))

    def test_read_only_allows(self):
        self.assertFalse(a.write_permissions("read-all"))
