"""Span dataclass for the armor.spotlight annotator."""

from __future__ import annotations

from dataclasses import dataclass

from armor.types import Source


@dataclass(frozen=True)
class Span:
    """A provenance-annotated text span for use with the spotlight annotator.

    Attributes:
        text: The text content of this span.
        source: The provenance / trust label for this span (from armor.types.Source).
            Determines whether the span gets wrapped with provenance delimiters.

    Example::

        from armor.spotlight import Span
        from armor.types import Source

        span = Span(text="fetched web page body", source=Source.TOOL_RESULT_UNTRUSTED)
    """

    text: str
    source: Source
