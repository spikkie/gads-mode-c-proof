import json
import tempfile
import unittest
from pathlib import Path

from scripts.qualify import (PROOF, SOURCE, Rejected, digest, parse_manifest,
                             preflight, stage, verify_manifest)

BASE_SHA = '1' * 40


class QualifyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.checkout = root / 'repo'; self.checkout.mkdir()
        (self.checkout / 'source.txt').write_bytes(b'synthetic source\n')
        (self.checkout / 'SHA256SUMS').write_text(
            digest(b'synthetic source\n') + '  source.txt\n')
        self.work = root / 'worker.py'; self.work.write_bytes(SOURCE)
        self.e1 = root / 'qa.sha'; self.e1.write_text(digest(SOURCE) + '  worker.py\n')
        self.j01 = root / 'j01.txt'; self.j01.write_text('GADS_J01_APPROVE_' + digest(SOURCE))
        self.out = root / 'staged'

    def make_stage(self):
        return stage(self.checkout, self.work, self.e1, self.j01, BASE_SHA, self.out)

    def rejected(self, fn):
        with self.assertRaises(Rejected):
            fn()

    def test_positive_staging(self):
        self.assertEqual(self.make_stage()['status'], 'PREFLIGHT_PASS_NOT_PUBLISHED')
        self.assertEqual(preflight(self.checkout, self.out, BASE_SHA)['base_sha'], BASE_SHA)

    def test_reject_bad_worker(self):
        self.work.write_text('def is_even(n):\n    return True\n')
        self.rejected(self.make_stage)

    def test_reject_bad_qa(self):
        self.e1.write_text('0'*64 + '  worker.py\n')
        self.rejected(self.make_stage)

    def test_reject_j01_dissent(self):
        self.j01.write_text('GADS_J01_REJECT')
        self.rejected(self.make_stage)

    def test_reject_stale_sha(self):
        self.make_stage()
        self.rejected(lambda: preflight(self.checkout, self.out, '2'*40))

    def test_reject_tampered_proof(self):
        self.make_stage()
        (self.out / PROOF).write_text('forged')
        self.rejected(lambda: preflight(self.checkout, self.out, BASE_SHA))

    def test_reject_extra_file(self):
        self.make_stage()
        (self.out / 'credentials.txt').write_text('no')
        self.rejected(lambda: preflight(self.checkout, self.out, BASE_SHA))

    def test_reject_symlink(self):
        self.make_stage()
        (self.out / PROOF).unlink()
        (self.out / PROOF).symlink_to(self.checkout / 'source.txt')
        self.rejected(lambda: preflight(self.checkout, self.out, BASE_SHA))

    def test_reject_tampered_base_checkout(self):
        self.make_stage()
        (self.checkout / 'source.txt').write_text('evil')
        self.rejected(lambda: preflight(self.checkout, self.out, BASE_SHA))

    def test_reject_changed_manifest(self):
        self.make_stage()
        f = self.out / 'SHA256SUMS'
        f.write_text(f.read_text().replace(digest(b'synthetic source\n'), 'a'*64))
        self.rejected(lambda: preflight(self.checkout, self.out, BASE_SHA))

    def test_reject_bad_evidence(self):
        self.make_stage()
        f = self.out / 'evidence.json'
        obj = json.loads(f.read_text()); obj['status'] = 'PUBLISHED'
        f.write_text(json.dumps(obj))
        self.rejected(lambda: preflight(self.checkout, self.out, BASE_SHA))

    def test_reject_manifest_path_traversal(self):
        self.rejected(lambda: parse_manifest((('0'*64) + '  ../bad\n').encode()))

    def test_baseline_manifest_pass(self):
        self.assertIn('source.txt', verify_manifest(self.checkout))


if __name__ == '__main__':
    unittest.main()
