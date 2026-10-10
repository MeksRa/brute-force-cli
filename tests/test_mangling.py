"""Tests for brute_force_cli.mangling.

These exercise only pure-Python logic with no external dependencies, so
they run with plain `python -m unittest` as well as `pytest`.
"""

import unittest

from brute_force_cli.mangling import _generate_leetspeak, generate_mutations


class TestGenerateLeetspeak(unittest.TestCase):
    def test_includes_original_word(self):
        self.assertIn("test", _generate_leetspeak("test"))

    def test_substitutes_known_letters(self):
        variants = _generate_leetspeak("admin")
        # 'a' -> '@'/'4', 'i' -> '1'/'!'
        self.assertIn("@dm1n", variants)
        self.assertIn("4dmin", variants)

    def test_word_with_no_substitutable_letters_returns_itself_only(self):
        variants = _generate_leetspeak("xyz")
        self.assertEqual(variants, {"xyz"})

    def test_empty_word(self):
        self.assertEqual(_generate_leetspeak(""), {""})


class TestGenerateMutations(unittest.TestCase):
    def test_level_0_covers_basic_case_variants(self):
        mutations = set(generate_mutations(["Admin"], level=0))
        self.assertIn("Admin", mutations)
        self.assertIn("admin", mutations)
        self.assertIn("ADMIN", mutations)
        self.assertIn("Admin".capitalize(), mutations)
        # No suffixes should appear at level 0.
        self.assertNotIn("admin123", mutations)

    def test_level_1_adds_suffixes_and_prefixes(self):
        mutations = set(generate_mutations(["admin"], level=1))
        self.assertIn("admin123", mutations)
        self.assertIn("123admin", mutations)
        self.assertIn("admin!", mutations)

    def test_level_2_adds_reverse_and_extended_tails(self):
        mutations = set(generate_mutations(["admin"], level=2))
        self.assertIn("nimda", mutations)
        self.assertIn("adminpass", mutations)

    def test_level_3_adds_structural_rules(self):
        mutations = set(generate_mutations(["admin"], level=3))
        self.assertIn("admin".swapcase(), mutations)
        self.assertIn("adminadmin", mutations)
        self.assertIn("dmin", mutations)  # first char dropped
        self.assertIn("admi", mutations)  # last char dropped

    def test_level_3_skips_truncation_for_single_char_words(self):
        # len(word) > 1 guard: shouldn't raise or produce empty-string noise.
        mutations = set(generate_mutations(["a"], level=3))
        self.assertIn("a", mutations)

    def test_level_4_adds_leetspeak(self):
        mutations = set(generate_mutations(["admin"], level=4))
        self.assertIn("@dmin", mutations)

    def test_level_5_combines_word_pairs(self):
        mutations = set(generate_mutations(["foo", "bar"], level=5))
        self.assertIn("foobar", mutations)
        self.assertIn("foo_bar", mutations)
        self.assertIn("bar-foo", mutations)
        # A word is never paired with itself in the level-5 combination step
        # (though "foofoo" can still appear via level 3's word-dubbing rule
        # at level >= 3 -- level 5 here only exercises the pairing step).
        self.assertNotIn("foo_foo", mutations)

    def test_level_5_requires_multiple_words(self):
        # Single-word input: the len(base_words) > 1 guard should prevent
        # the combination step from running (no crash either way).
        mutations = generate_mutations(["onlyword"], level=5)
        self.assertIsInstance(mutations, list)

    def test_blank_and_non_string_entries_are_ignored(self):
        mutations = set(generate_mutations(["admin", "", None, "  "], level=0))
        self.assertIn("admin", mutations)
        self.assertNotIn("", mutations)

    def test_result_has_no_duplicates(self):
        mutations = generate_mutations(["admin", "Admin", "ADMIN"], level=1)
        self.assertEqual(len(mutations), len(set(mutations)))

    def test_higher_level_is_superset_in_spirit(self):
        # Not a strict superset (level 5's pairing step only runs once, not
        # per-level-cumulative in the same way), but level 2 output should
        # at minimum still contain everything level 1 guarantees for a
        # single word.
        level1 = set(generate_mutations(["admin"], level=1))
        level2 = set(generate_mutations(["admin"], level=2))
        self.assertTrue(level1.issubset(level2))


if __name__ == "__main__":
    unittest.main()
