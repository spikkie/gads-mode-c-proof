"""Bounded complete-coverage J-01 review partition adversarial tests."""
import unittest
from gads import j01_batches as b
from gads import j01_runtime as r


def snapshot(count=8, patch_bytes=700):
    return {"schema": "gads.j01-diff.v1",
            "repository": r.REPO, "pr_number": 15,
            "base_head": "b" * 40, "reviewed_head": "a" * 40,
            "files": [{"path": "path-" + str(i), "status": "modified",
                       "patch": "@@ -1 +1 @@\n-old\n+" + ("x" * patch_bytes),
                       "additions": 1, "deletions": 1}
                      for i in range(count)]}


class BatchTests(unittest.TestCase):
    def test_roundtrip_exact_order_and_all_files(self):
        data = snapshot()
        groups = b.partition(data, max_batch_bytes=2300)
        self.assertGreater(len(groups), 1)
        self.assertLessEqual(len(groups), b.MAX_BATCHES)
        self.assertEqual([p for group in groups for p in group["files"]],
                         data["files"])
        self.assertEqual([group["batch_index"] for group in groups],
                         list(range(1, len(groups) + 1)))
        self.assertTrue(all(group["batch_count"] == len(groups) for group in groups))
        self.assertTrue(all(len(r.canonical(group)) <= 2300 for group in groups))

    def test_digest_is_stable(self):
        original = b.partition(snapshot())[0]
        self.assertEqual(b.batch_digest(original), b.batch_digest(original))
        self.assertEqual(len(b.batch_digest(original)), 64)

    def test_empty_fails_closed(self):
        data = snapshot(0)
        with self.assertRaisesRegex(r.ReviewBlocked, "UNREVIEWABLE"):
            b.partition(data)

    def test_one_file_too_large(self):
        with self.assertRaisesRegex(r.ReviewBlocked, "SINGLE_FILE"):
            b.partition(snapshot(1, 16000))

    def test_over_global_bytes(self):
        with self.assertRaisesRegex(r.ReviewBlocked, "TOTAL_INPUT"):
            b.partition(snapshot(8, 10000))

    def test_too_many_chunks(self):
        with self.assertRaisesRegex(r.ReviewBlocked, "TOO_MANY"):
            b.partition(snapshot(10, 850), max_batch_bytes=1350)

    def test_invalid_max_bytes_denied(self):
        with self.assertRaisesRegex(r.ReviewBlocked, "BATCH_BUDGET"):
            b.partition(snapshot(1), max_batch_bytes=200000)

    def test_metadata_invalid_denied(self):
        data = snapshot(2)
        data["schema"] = "untrusted"
        with self.assertRaisesRegex(r.ReviewBlocked, "INVALID_REVIEW"):
            b.partition(data)

    def test_model_input_never_exceeds_context_budget(self):
        data = snapshot(18, 400)
        groups = b.partition(data)
        self.assertEqual(sum(len(x["files"]) for x in groups), 18)
        self.assertTrue(all(len(r.canonical(x)) <= b.MAX_BATCH_BYTES for x in groups))


if __name__ == "__main__":
    unittest.main()
