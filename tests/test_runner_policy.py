"""SEC-02.2: never register public GitHub Actions as the local J-01 runner."""
import unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]

class RunnerPolicyTests(unittest.TestCase):
    def test_no_public_self_hosted_workflow(self):
        workflow_dir = ROOT / ".github" / "workflows"
        self.assertFalse((workflow_dir / "j01-trusted-proposed.yml").exists())
        for path in workflow_dir.glob("*.yml"):
            body = path.read_text(encoding="utf-8").lower()
            self.assertNotIn("self-hosted", body, str(path))
            self.assertNotIn("gads-j01-ephemeral", body, str(path))

    def test_no_writer_grants_in_ci(self):
        for path in (ROOT / ".github" / "workflows").glob("*.yml"):
            body = path.read_text(encoding="utf-8").lower()
            for forbidden in ("contents: write", "actions: write",
                              "pull-requests: write"):
                self.assertNotIn(forbidden, body, str(path))
