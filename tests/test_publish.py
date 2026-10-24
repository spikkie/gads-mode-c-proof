import tempfile
import base64
import urllib.parse
import unittest
from pathlib import Path

from scripts.qualify import SOURCE, digest, stage, Rejected
from scripts.publish import blob_sha, run, verify_diff

BASE_SHA = '1' * 40


class FakeAPI:
    def __init__(self, protected=True, private=False):
        self.calls = []
        self.protected = protected
        self.private = private

    def call(self, method, path, body=None):
        self.calls.append((method, path))
        if path == '':
            return {'private': self.private}
        if path == '/branches/main':
            return {'protected': self.protected}
        if path == '/git/ref/heads/main':
            return {'object': {'sha': BASE_SHA}}
        if path.startswith('/pulls?'):
            return []
        raise AssertionError(f'unexpected endpoint {method} {path}')


class SimulatedGitHubAPI:
    """Deliberately synthetic GitHub REST responses; never used for live acceptance."""
    def __init__(self):
        self.calls = []
        self.branch_sha = None
        self.git_blobs = {}
        self.tree = None
        self.pr = None
        self.commits = {}
        self.n = 0

    def call(self, method, path, body=None):
        self.calls.append((method, path))
        if (method, path) == ('GET', ''):
            return {'private': False}
        if (method, path) == ('GET', '/branches/main'):
            return {'protected': True}
        if (method, path) == ('GET', '/git/ref/heads/main'):
            return {'object': {'sha': BASE_SHA}}
        if method == 'GET' and path.startswith('/pulls?'):
            return [self.pr] if self.pr else []
        if method == 'GET' and path.startswith('/git/ref/heads/autonomy/'):
            if self.branch_sha is None:
                raise Rejected('GITHUB_HTTP_404:GET:/git/ref/heads/autonomy')
            return {'object': {'sha': self.branch_sha}}
        if (method, path) == ('GET', '/git/commits/' + BASE_SHA):
            return {'tree': {'sha': 'synthetic-base-tree'}}
        if (method, path) == ('POST', '/git/blobs'):
            data = base64.b64decode(body['content'])
            sha = blob_sha(data)
            self.git_blobs[sha] = data
            return {'sha': sha}
        if (method, path) == ('POST', '/git/trees'):
            self.tree = body
            return {'sha': 'synthetic-tree'}
        if (method, path) == ('POST', '/git/commits'):
            assert body['parents'] == [BASE_SHA]
            self.n += 1
            return {'sha': '2'*40}
        if (method, path) == ('POST', '/git/refs'):
            self.branch_sha = body['sha']
            return {'ref': body['ref']}
        if method == 'GET' and path.startswith('/compare/'):
            assert self.tree is not None and self.branch_sha is not None
            files = [{'filename': x['path'], 'sha': x['sha'],
                      'status': 'added' if x['path'].startswith('docs/') else 'modified'}
                     for x in self.tree['tree']]
            return {'total_commits': 1, 'files': files}
        if (method, path) == ('POST', '/pulls'):
            assert body['draft'] is True and body['base'] == 'main'
            assert self.branch_sha is not None
            self.pr = {'number': 42, 'draft': True, 'merged': False,
                       'base': {'ref': 'main'},
                       'head': {'ref': body['head'], 'sha': self.branch_sha,
                                'repo': {'full_name': 'owner/gads-mode-c-proof'}}}
            return self.pr
        if (method, path) == ('GET', '/pulls/42'):
            return self.pr
        if (method, path) == ('GET', '/pulls/42/files?per_page=100'):
            return [{'filename': x['path'], 'sha': x['sha']} for x in self.tree['tree']]
        raise AssertionError(f'unexpected endpoint {method} {path}')


class PublisherTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        self.checkout = root / 'repo'; self.checkout.mkdir()
        (self.checkout / 'source.txt').write_text('synthetic\n')
        (self.checkout / 'SHA256SUMS').write_text(digest(b'synthetic\n') + '  source.txt\n')
        w = root / 'worker.py'; w.write_bytes(SOURCE)
        e1 = root / 'e1'; e1.write_text(digest(SOURCE) + '  worker.py\n')
        j01 = root / 'review'; j01.write_text('GADS_J01_APPROVE_' + digest(SOURCE))
        self.staged = root / 'staged'
        stage(self.checkout, w, e1, j01, BASE_SHA, self.staged)

    def execute(self, api, sha=BASE_SHA, ref='refs/heads/main', repo='owner/gads-mode-c-proof'):
        return run(api, self.checkout, self.staged, sha, ref, repo)

    def test_reject_unprotected_main_without_creating_branch(self):
        api = FakeAPI(protected=False)
        with self.assertRaisesRegex(Rejected, 'MAIN_NOT_PROTECTED'):
            self.execute(api)
        self.assertFalse(any(method == 'POST' for method, _ in api.calls))

    def test_reject_private_repo_without_writes(self):
        api = FakeAPI(private=True)
        with self.assertRaisesRegex(Rejected, 'PUBLIC_SYNTHETIC_ONLY'):
            self.execute(api)
        self.assertFalse(any(method == 'POST' for method, _ in api.calls))

    def test_reject_unapproved_ref_before_any_api(self):
        api = FakeAPI()
        with self.assertRaisesRegex(Rejected, 'UNTRUSTED_BASE_REF'):
            self.execute(api, ref='refs/heads/feature')
        self.assertFalse(api.calls)

    def test_reject_other_repository_before_any_api(self):
        api = FakeAPI()
        with self.assertRaisesRegex(Rejected, 'WRONG_SYNTHETIC_REPOSITORY'):
            self.execute(api, repo='owner/internal')
        self.assertFalse(api.calls)

    def test_reject_mismatched_sha_before_any_write(self):
        api = FakeAPI()
        with self.assertRaisesRegex(Rejected, 'PROOF_UNBOUND'):
            self.execute(api, sha='2'*40)
        self.assertFalse(any(method == 'POST' for method, _ in api.calls))

    def test_reject_tampered_proof_before_any_api(self):
        api = FakeAPI()
        (self.staged / 'docs/c05-proof.txt').write_text('bad')
        with self.assertRaises(Rejected):
            self.execute(api)
        self.assertFalse(api.calls)

    def test_reject_multiple_commit_diff(self):
        with self.assertRaisesRegex(Rejected, 'DIFF_SIZE_OR_COMMITS'):
            verify_diff({'total_commits': 2, 'files': []}, {})

    def test_reject_extra_file_diff(self):
        with self.assertRaisesRegex(Rejected, 'DIFF_SIZE_OR_COMMITS'):
            verify_diff({'total_commits': 1, 'files': [{'filename': 'source.txt'}]}, {})

    def test_reject_wrong_digest(self):
        with self.assertRaisesRegex(Rejected, 'DIFF_PATH_OR_BLOB'):
            verify_diff({'total_commits': 1, 'files': [
                {'filename': 'docs/c05-proof.txt', 'sha': 'bad', 'status': 'added'},
                {'filename': 'SHA256SUMS', 'sha': 'good', 'status': 'modified'}]},
                {'docs/c05-proof.txt': 'good', 'SHA256SUMS': 'good'})

    def test_one_draft_pr_idempotent_rerun(self):
        api = SimulatedGitHubAPI()
        first = self.execute(api)
        self.assertEqual(first['status'], 'C05_DRAFT_PR_VERIFIED_NOT_MERGED')
        self.assertEqual(first['number'], 42)
        self.assertEqual(len([c for c in api.calls if c == ('POST', '/pulls')]), 1)
        second = self.execute(api)
        self.assertEqual(second, first)
        self.assertEqual(len([c for c in api.calls if c == ('POST', '/pulls')]), 1)
        self.assertEqual(len([c for c in api.calls if c == ('POST', '/git/refs')]), 1)

    def test_git_blob_sha(self):
        self.assertEqual(blob_sha(b'hello\n'), 'ce013625030ba8dba906f756967f9e9ca394464a')


if __name__ == '__main__':
    unittest.main()
