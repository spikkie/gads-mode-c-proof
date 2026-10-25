"""Source integrity negative tests."""
import unittest
from gads import manifest as m
H="a"*64
class TestManifest(unittest.TestCase):
    def test_sorted(self):
        self.assertEqual(list(m.parse(H+"  a\n"+H+"  b\n")),["a","b"])
    def test_duplicate_denied(self):
        with self.assertRaises(m.InvalidManifest):m.parse(H+"  a\n"+H+"  a\n")
    def test_unsorted_denied(self):
        with self.assertRaises(m.InvalidManifest):m.parse(H+"  b\n"+H+"  a\n")
    def test_parent_denied(self):
        with self.assertRaises(m.InvalidManifest):m.parse(H+"  ../a\n")
    def test_short_sha_denied(self):
        with self.assertRaises(m.InvalidManifest):m.parse("abc  a\n")
    def test_missing_final_newline(self):
        with self.assertRaises(m.InvalidManifest):m.parse(H+"  a")
    def test_crlf_denied(self):
        with self.assertRaises(m.InvalidManifest):m.parse(H+"  a\r\n")
