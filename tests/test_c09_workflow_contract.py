"""Static read-only privilege and provenance contract for C-09 native listener."""
from pathlib import Path
import unittest
ROOT=Path(__file__).resolve().parents[1]

class WorkflowContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source=(ROOT/".github/workflows/c09-trusted-recovery.yml").read_text()
        cls.validation=(ROOT/".github/workflows/c09-validation.yml").read_text()

    def test_native_completed_trigger_only(self):
        self.assertIn("on:\n  workflow_run:\n",self.source)
        self.assertIn("types: [completed]",self.source)
        self.assertNotIn("pull_request_target",self.source)
        self.assertNotIn("workflow_dispatch:",self.source)

    def test_token_is_read_only(self):
        self.assertIn("permissions: {}\n",self.source)
        self.assertIn("      contents: read\n      actions: read\n",self.source)
        self.assertNotIn("contents: write",self.source)
        self.assertNotIn("actions: write",self.source)
        self.assertNotIn("secrets.",self.source)

    def test_no_untrusted_checkout(self):
        self.assertIn("ref: ${{ github.sha }}",self.source)
        self.assertIn("persist-credentials: false",self.source)
        self.assertNotIn("ref: ${{ github.event.workflow_run.head_sha }}",self.source)
        self.assertNotIn("ref: ${{ github.event.workflow_run.head_branch }}",self.source)

    def test_allowlist_and_timeout(self):
        self.assertIn("qualification/c08-reconcile-20261024",self.source)
        self.assertIn("github.event.workflow_run.conclusion == 'failure'",self.source)
        self.assertIn("timeout-minutes: 5",self.source)

    def test_no_download_or_script_injection(self):
        self.assertNotIn("download-artifact",self.source)
        self.assertNotIn("git checkout ${{ github.event",self.source)
        self.assertNotIn("curl |",self.source)

    def test_validation_never_writes(self):
        self.assertIn("      contents: read\n      actions: read\n",self.validation)
        self.assertNotIn("contents: write",self.validation)
        self.assertNotIn("actions: write",self.validation)
