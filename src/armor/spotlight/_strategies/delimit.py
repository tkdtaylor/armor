# SPDX-License-Identifier: Apache-2.0
"""Delimit strategy for the armor.spotlight annotator.

Wraps each untrusted span with randomized sentinel delimiters of the form::

    «{sentinel}-{SUFFIX}» ... «/{sentinel}-{SUFFIX}»

Where U+00AB is LEFT-POINTING DOUBLE ANGLE QUOTATION MARK and U+00BB is
RIGHT-POINTING DOUBLE ANGLE QUOTATION MARK, producing e.g.:

    «ARMOR-UNTRUSTED-Xr4qKz8w» ... «/ARMOR-UNTRUSTED-Xr4qKz8w»

SUFFIX is a cryptographically random alphanumeric string (>=6 chars) generated
fresh per annotate() call via the ``secrets`` module.

Sentinel forgery handling (ADR-043 section 4):
    If the span text contains the sentinel base string, the annotator neutralizes
    the embedded sentinel (replacing the opening angle-quote) then records the
    forgery so the caller can raise SentinelForgeryError. The neutralization
    happens BEFORE the outer delimiters are applied.
"""

from __future__ import annotations

import re
import secrets
import string

# LEFT-POINTING DOUBLE ANGLE QUOTATION MARK (U+00AB) and its right counterpart
_LDAQ = "«"  # «
_RDAQ = "»"  # »

# Alphanumeric character pool for suffix generation
_SUFFIX_CHARS = string.ascii_letters + string.digits
_SUFFIX_LENGTH = 8  # >=6 per spec; 8 gives wider entropy margin


def _generate_suffix() -> str:
    """Generate a cryptographically random alphanumeric suffix."""
    return "".join(secrets.choice(_SUFFIX_CHARS) for _ in range(_SUFFIX_LENGTH))


def _neutralize_sentinel(text: str, sentinel: str) -> str:
    """Replace opening angle-quote of any embedded sentinel pattern.

    Replaces every U+00AB (left double angle quotation mark) that precedes
    the sentinel string (or /sentinel) with U+2039 (single left-pointing
    angle quotation mark), breaking the delimiter pattern while preserving
    the text content.
    """
    # Pattern: U+00AB followed by optional slash then the sentinel base
    pattern = re.compile(re.escape(_LDAQ) + r"(?=/?" + re.escape(sentinel) + r")")
    # Replace with U+2039 SINGLE LEFT-POINTING ANGLE QUOTATION MARK
    return pattern.sub("‹", text)  # noqa: RUF001


def apply(
    spans: list[tuple[str, bool, int]],
    sentinel: str,
    suffix: str,
) -> tuple[str, list[tuple[int, str]]]:
    """Apply the delimit strategy to a list of (text, should_mark, span_index) tuples.

    Args:
        spans: List of (text, should_mark, span_index) where should_mark determines
            whether this span gets wrapped with sentinel delimiters.
        sentinel: The base sentinel string (e.g. "ARMOR-UNTRUSTED").
        suffix: The per-render random suffix to append to the sentinel.

    Returns:
        A tuple of (marked_text, forgeries) where forgeries is a list of
        (span_index, neutralized_text) pairs for any spans that contained
        embedded sentinels. Callers are responsible for raising SentinelForgeryError
        if forgeries is non-empty.
    """
    open_delim = f"{_LDAQ}{sentinel}-{suffix}{_RDAQ}"
    close_delim = f"{_LDAQ}/{sentinel}-{suffix}{_RDAQ}"

    parts: list[str] = []
    forgeries: list[tuple[int, str]] = []

    for text, should_mark, span_index in spans:
        if not should_mark:
            parts.append(text)
            continue

        # Check for embedded sentinel BEFORE applying outer delimiters (AC6)
        if sentinel in text:
            neutralized = _neutralize_sentinel(text, sentinel)
            forgeries.append((span_index, neutralized))
            parts.append(f"{open_delim}{neutralized}{close_delim}")
        else:
            parts.append(f"{open_delim}{text}{close_delim}")

    return "\n".join(parts), forgeries
