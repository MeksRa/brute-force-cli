def generate_mutations(word: str, level: int) -> set[str]:
    """Generates password mutations dynamically based on the configured mangling level."""
    mutations = {word, word.lower(), word.capitalize()}
    if level >= 1:
        mutations.update({word.upper(), word.title()})

    if level == 1:
        return mutations

    suffixes_l2 = ("", "1", "123", "!")
    extended = set()
    for m in mutations:
        for s in suffixes_l2:
            extended.add(m + s)

    if level >= 3:
        suffixes_l3 = ("2026", "123456", "#", "@", "12345")
        for m in mutations:
            for s in suffixes_l3:
                extended.add(m + s)
        return extended

    return extended