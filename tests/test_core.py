import json
import tempfile
import unittest
from pathlib import Path

from datasentinel.core import ScopeError, load_suppressions, luhn, scan

KEY = b"a" * 32


class CoreTests(unittest.TestCase):
    def test_luhn(self):
        self.assertTrue(luhn("4111 1111 1111 1111"))
        self.assertFalse(luhn("4111 1111 1111 1112"))

    def test_masked_findings_and_permissions(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "sample.txt").write_text("review test.user@example.invalid and 4111 1111 1111 1111")
            result = scan(root, KEY)
        self.assertEqual(len(result["findings"]), 2)
        output = json.dumps(result)
        self.assertNotIn("test.user@example.invalid", output)
        self.assertNotIn("4111 1111 1111 1111", output)
        self.assertIn("mode_octal", result["findings"][0])

    def test_suppression_and_stable_fingerprint(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "sample.txt").write_text("test.user@example.invalid")
            first = scan(root, KEY)
            fingerprint = first["findings"][0]["fingerprint_hmac_sha256"]
            suppression = root / "suppressions.json"
            suppression.write_text(json.dumps([fingerprint]))
            second = scan(root, KEY, load_suppressions(suppression))
        self.assertEqual(second["findings"], [])

    def test_same_candidate_in_two_files_retains_locations(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "a.txt").write_text("test.user@example.invalid")
            (root / "b.txt").write_text("test.user@example.invalid")
            result = scan(root, KEY)
        self.assertEqual(len(result["findings"]), 2)
        self.assertTrue(result["findings"][1]["duplicate_fingerprint"])

    def test_symlink_and_short_key_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            link = root / "link"
            link.symlink_to(root, target_is_directory=True)
            with self.assertRaises(ScopeError):
                scan(link, KEY)
            with self.assertRaises(ScopeError):
                scan(root, b"short")


if __name__ == "__main__":
    unittest.main()
