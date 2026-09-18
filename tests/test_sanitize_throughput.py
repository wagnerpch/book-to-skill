"""Cost and table-equivalence contract for ``sanitize_extracted_text``.

Sanitization runs over the full extracted corpus of every source, so its cost
per character is multiplied by the size of the book. Building one Python string
object per character made it the second amplifier in the decompression-bomb
chain: ~10.6 bytes and ~0.56 us per character, so a 209M-character corpus cost
roughly 2 GB and two minutes *after* extraction had already produced it.

``str.translate`` does the same filtering in C, in one pass, with one
allocation. The risk that introduces is drift: the extractor would filter from a
table while ``tools/scan_generated_skill.py`` keeps warning from
``is_invisible_codepoint``, so a character one layer strips is flagged by the
other — exactly the divergence the predicate's docstring says it exists to
prevent. The first test below pins the two together.
"""

import sys
import time
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from book_to_skill.sanitize import (  # noqa: E402
    _INVISIBLE_TRANSLATION,
    is_invisible_codepoint,
    sanitize_extracted_text,
)

# Every block the module names, plus the boundaries just outside each one, plus
# ordinary text. Sweeping the whole of Unicode would be slower than the thing
# under test; this covers each range the two layers could disagree about.
SWEPT_RANGES = (
    (0x0000, 0x0800),      # ASCII, Latin-1, the ARABIC LETTER MARK neighbourhood
    (0x1150, 0x1170),      # Hangul fillers
    (0x1800, 0x1820),      # MONGOLIAN VOWEL SEPARATOR
    (0x2000, 0x2080),      # zero-width spacers, bidi controls, invisible operators
    (0x3150, 0x3170),      # HANGUL FILLER
    (0xFE00, 0xFE20),      # variation selectors 1-16
    (0xFF90, 0xFFB0),      # halfwidth Hangul filler
    (0xFFF0, 0x10000),     # interlinear annotation controls
    (0x1D160, 0x1D190),    # musical beaming/phrasing controls
    (0xE0000, 0xE0200),    # tag block and variation selector supplement
)


def test_translation_table_agrees_with_the_invisible_predicate():
    """The table the extractor strips from and the predicate the generated-skill
    scanner warns from must describe exactly the same set of code points."""
    disagreements = []
    for start, end in SWEPT_RANGES:
        for codepoint in range(start, end):
            in_table = codepoint in _INVISIBLE_TRANSLATION
            by_predicate = is_invisible_codepoint(codepoint)
            if in_table != by_predicate:
                disagreements.append(
                    f"U+{codepoint:04X}: table={in_table} predicate={by_predicate}"
                )

    assert not disagreements, "extractor and scanner disagree on: " + ", ".join(
        disagreements[:20]
    )


def test_translation_table_maps_every_entry_to_removal():
    assert all(value is None for value in _INVISIBLE_TRANSLATION.values())


def test_sanitizing_a_book_sized_corpus_stays_within_its_cost_budget():
    """A full-length corpus must not cost seconds per pass.

    The bound is deliberately loose. The per-character loop this replaces
    measured 11.2 s for this input on the development machine, so it misses a
    4 s ceiling by ~3x even on fast hardware; ``str.translate`` measures ~0.4 s,
    so it clears the same ceiling by ~10x. That two-sided margin is what keeps
    the test a real gate instead of a timing flake.
    """
    corpus = ("Chapter 1. Bounded queues prevent overload. " * 10) + "​"
    corpus = corpus * (20_000_000 // len(corpus))

    start = time.perf_counter()
    text, removed = sanitize_extracted_text(corpus)
    elapsed = time.perf_counter() - start

    assert removed == corpus.count("​")
    assert "​" not in text
    assert elapsed < 4.0, f"sanitization took {elapsed:.2f}s for {len(corpus):,} chars"
