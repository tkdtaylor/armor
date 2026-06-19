# SPDX-License-Identifier: Apache-2.0
"""Datamark strategy for the armor.spotlight annotator.

Interleaves a sentinel token between every N words of marked spans (Microsoft's
datamarking approach). More robust than delimiter-only marking because the model
has a continuous structural signal throughout the span, not just at its edges.
However, this approach costs tokens and can degrade comprehension on some models.

Output structure for a marked span::

    «ARMOR-UNTRUSTED-SUFFIX» word1 ... wordN ARMOR-UNTRUSTED-SUFFIX wordN+1 ...
    «/ARMOR-UNTRUSTED-SUFFIX»

The outer delimiter pair is always applied (same as delimit strategy); sentinel
tokens are additionally interleaved between every N words inside the span.

ADR-043 section 4: datamark is the upgrade path for higher-assurance deployments.
Default word group size N=5.
"""

from __future__ import annotations

from armor.spotlight._strategies import delimit as _delimit


def _interleave_sentinel(text: str, sentinel: str, suffix: str, n: int) -> str:
    """Interleave ``{sentinel}-{suffix}`` between every N words in text.

    Args:
        text: The span text to mark.
        sentinel: Base sentinel string.
        suffix: Per-render random suffix.
        n: Group every N words before inserting a sentinel token.

    Returns:
        The text with sentinel tokens interleaved between word groups.
    """
    marker = f"{sentinel}-{suffix}"
    words = text.split()
    if not words:
        return text

    groups: list[str] = []
    for i in range(0, len(words), n):
        groups.append(" ".join(words[i : i + n]))

    return f" {marker} ".join(groups)


def apply(
    spans: list[tuple[str, bool, int]],
    sentinel: str,
    suffix: str,
    word_group_size: int = 5,
) -> tuple[str, list[tuple[int, str]]]:
    """Apply the datamark strategy to a list of (text, should_mark, span_index) tuples.

    Args:
        spans: List of (text, should_mark, span_index) where should_mark determines
            whether this span gets datamarked.
        sentinel: The base sentinel string (e.g. "ARMOR-UNTRUSTED").
        suffix: The per-render random suffix to append to the sentinel.
        word_group_size: Number of words between each interleaved sentinel token.

    Returns:
        A tuple of (marked_text, forgeries) where forgeries is a list of
        (span_index, neutralized_text) pairs for any spans that contained
        embedded sentinels.
    """
    open_delim = f"{_delimit._LDAQ}{sentinel}-{suffix}{_delimit._RDAQ}"
    close_delim = f"{_delimit._LDAQ}/{sentinel}-{suffix}{_delimit._RDAQ}"

    parts: list[str] = []
    forgeries: list[tuple[int, str]] = []

    for text, should_mark, span_index in spans:
        if not should_mark:
            parts.append(text)
            continue

        # Check for embedded sentinel BEFORE applying delimiters (AC6)
        if sentinel in text:
            neutralized = _delimit._neutralize_sentinel(text, sentinel)
            forgeries.append((span_index, neutralized))
            # Still apply datamarking on the neutralized text
            marked = _interleave_sentinel(neutralized, sentinel, suffix, word_group_size)
            parts.append(f"{open_delim}{marked}{close_delim}")
        else:
            marked = _interleave_sentinel(text, sentinel, suffix, word_group_size)
            parts.append(f"{open_delim}{marked}{close_delim}")

    return "\n".join(parts), forgeries
