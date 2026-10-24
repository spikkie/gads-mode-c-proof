"""Structural CI security controls: duplicate keys and escalating job scopes fail."""
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


class UniqueLoader(yaml.BaseLoader):
    def construct_mapping(self, node, deep=False):
        result = {}
        for key, value in node.value:
            k = self.construct_object(key, deep=deep)
            if k in result:
                raise ValueError('DUPLICATE_YAML_KEY:' + str(k))
            result[k] = self.construct_object(value, deep=deep)
        return result


def load_safely(text):
    return yaml.load(text, Loader=UniqueLoader)


class SecurityContractTests(unittest.TestCase):
    def test_duplicate_yaml_keys_rejected(self):
        with self.assertRaisesRegex(ValueError, 'DUPLICATE_YAML_KEY'):
            load_safely('permissions:\n  contents: read\n  contents: write\n')

    def test_scoped_permissions_events_and_owner_sha_gate(self):
        flow = load_safely((ROOT / '.github/workflows/c05-proof.yml').read_text())
        self.assertEqual(list(flow['on']), ['workflow_dispatch'])
        self.assertEqual(flow['permissions'], {})
        jobs = flow['jobs']
        self.assertEqual(set(jobs), {'worker', 'quality', 'reviewer', 'stage', 'trusted_publisher'})
        self.assertEqual(jobs['worker']['permissions'],
                         {'contents': 'read', 'copilot-requests': 'write'})
        self.assertEqual(jobs['reviewer']['permissions'],
                         {'contents': 'read', 'copilot-requests': 'write'})
        for name in ('quality', 'stage'):
            self.assertEqual(jobs[name]['permissions'], {'contents': 'read'})
        self.assertEqual(jobs['trusted_publisher']['permissions'],
                         {'contents': 'write', 'pull-requests': 'write'})
        for job in ('worker', 'trusted_publisher'):
            expression = jobs[job]['if']
            self.assertIn("github.ref == 'refs/heads/main'", expression)
            self.assertIn('vars.GADS_C05_APPROVED_SHA == github.sha', expression)
        self.assertEqual(jobs['trusted_publisher']['needs'], 'stage')
        self.assertEqual(jobs['reviewer']['needs'], 'quality')
        self.assertEqual(jobs['quality']['needs'], 'worker')
        self.assertEqual(jobs['stage']['needs'], 'reviewer')

    def test_quality_is_read_only(self):
        workflow = load_safely((ROOT / '.github/workflows/quality.yml').read_text())
        self.assertEqual(workflow['permissions'], {'contents': 'read'})
        self.assertEqual(workflow['jobs']['quality']['timeout-minutes'], '8')
        self.assertNotIn('pull_request_target', workflow['on'])

    def test_no_automatic_merge_or_approval_calls(self):
        source = (ROOT / 'scripts/publish.py').read_text()
        self.assertNotIn("api.call('PUT', '/merges", source)
        self.assertNotIn("api.call('POST', '/merges", source)
        self.assertNotIn("api.call('POST', '/pulls/", source)
        self.assertIn("'draft': True", source)


if __name__ == '__main__':
    unittest.main()
