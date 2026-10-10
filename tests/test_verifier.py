"""Tests for brute_force_cli.verifier.

The "string" target path and the lazy-import error handling need no
third-party libraries, so these run with plain `python -m unittest`. The
archive/document format branches (zip/7z/rar/pdf/office) need their
respective libraries installed (see requirements.txt) and real sample
files, so they're intentionally left for an integration pass rather than
mocked here.
"""

import unittest
from pathlib import Path

from brute_force_cli.verifier import verify_single_password, worker_batch_check


class TestStringTarget(unittest.TestCase):
    def test_correct_guess_matches(self):
        self.assertTrue(
            verify_single_password("string", "hunter2", Path("."), "hunter2")
        )

    def test_wrong_guess_does_not_match(self):
        self.assertFalse(
            verify_single_password("string", "hunter2", Path("."), "wrong")
        )

    def test_case_sensitive(self):
        self.assertFalse(
            verify_single_password("string", "Hunter2", Path("."), "hunter2")
        )


class TestWorkerBatchCheckString(unittest.TestCase):
    def test_empty_batch_returns_zero_and_none(self):
        size, result = worker_batch_check(([], "string", "target", Path(".")))
        self.assertEqual(size, 0)
        self.assertIsNone(result)

    def test_batch_without_match_returns_full_size_and_none(self):
        batch = ["a", "b", "c"]
        size, result = worker_batch_check((batch, "string", "target", Path(".")))
        self.assertEqual(size, 3)
        self.assertIsNone(result)

    def test_batch_with_match_returns_full_size_and_match(self):
        batch = ["a", "target", "c"]
        size, result = worker_batch_check((batch, "string", "target", Path(".")))
        self.assertEqual(size, 3)  # full batch size, not index of match
        self.assertEqual(result, "target")


class TestMissingOptionalDependency(unittest.TestCase):
    def test_unknown_target_type_falls_through_to_false(self):
        # Not "zip"/"7z"/"rar"/"pdf"/"office"/"string" -> no branch matches,
        # verify_single_password should return False rather than raise.
        self.assertFalse(
            verify_single_password("nonsense", "whatever", Path("."), "guess")
        )


if __name__ == "__main__":
    unittest.main()
