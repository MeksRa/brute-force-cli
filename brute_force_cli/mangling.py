def generate_mutations(words: list[str], level: int) -> list[str]:
    """Generates password mutations based on structured, high-performance levels 0 to 5."""
    mutations = set()
    # Strip first, *then* filter on truthiness, so a whitespace-only entry
    # (e.g. "   ") doesn't survive as an empty-string candidate.
    base_words = [w.strip() for w in words if isinstance(w, str) and w.strip()]

    for word in base_words:
        # Level 0: Base registers
        mutations.add(word)
        mutations.add(word.lower())
        mutations.add(word.upper())
        mutations.add(word.capitalize())

        if level >= 1:
            # Level 1: Standard suffixes and prefixes
            suffixes_l1 = ["123", "1", "0", "!", "@", "2026", "2025"]
            for s in suffixes_l1:
                mutations.add(word + s)
                mutations.add(s + word)

        if level >= 2:
            # Level 2: Reverse and extended tails
            mutations.add(word[::-1])
            suffixes_l2 = ["12345", "777", "007", "_!", "123!", "pass"]
            for s in suffixes_l2:
                mutations.add(word + s)
                mutations.add(s + word)

        if level >= 3:
            # Level 3: Structural rules (Hashcat-style lite)
            mutations.add(word.swapcase())
            mutations.add(word + word)  # Dubbing (adminadmin)
            if len(word) > 1:
                mutations.add(
                    word[1:]
                )  # Removing the first character ( truncation left )
                mutations.add(
                    word[:-1]
                )  # Removing the last character ( truncation right )
                mutations.add(word[-1] + word[:-1])  # Cyclic shift

        if level >= 4:
            # Level 4: Leetspeak transformations (1337-speak)
            leet_variants = _generate_leetspeak(word.lower())
            mutations.update(leet_variants)

    # Level 5: Combination of word pairs
    if level >= 5 and len(base_words) > 1:
        separators = ["", "_", "-", "."]
        # top 200 most frequent words for hybrids so the processor doesn't get overwhelmed by millions
        combinable = base_words[:200]
        for w1 in combinable:
            for w2 in combinable[:80]:
                if w1 != w2:
                    for sep in separators:
                        mutations.add(f"{w1}{sep}{w2}")

    return list(mutations)


def _generate_leetspeak(word: str) -> set[str]:
    """Generates Leetspeak variations of a word at high speed."""
    replacements = {
        "a": ["@", "4"],
        "e": ["3"],
        "s": ["$", "5"],
        "i": ["1", "!"],
        "o": ["0"],
        "t": ["7"],
    }
    current = {word}
    for char, subs in replacements.items():
        if char in word:
            next_gen = set()
            for w in current:
                for sub in subs:
                    next_gen.add(w.replace(char, sub))
            current.update(next_gen)
    return current
