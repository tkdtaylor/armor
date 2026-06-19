"""Error types for the armor.spotlight annotator package."""

from __future__ import annotations


class SentinelForgeryError(Exception):
    """Raised when an untrusted span contains the sentinel base string.

    This indicates a boundary-escape / pre-close attempt: the span's text
    already contains the sentinel delimiter pattern, which could be used to
    escape the provenance boundary armor imposes.

    The annotator neutralizes the embedded sentinel (replacing the angle-bracket
    characters so it no longer forms a valid delimiter), then raises this error
    so callers can log the attempt. The ``partial_result`` attribute contains the
    marked text with the forgery neutralized and proper outer delimiters applied.

    Attributes:
        partial_result: The marked text with the forgery neutralized. Outer
            delimiters are applied around the neutralized content — the forged
            sentinel can no longer escape the boundary.
        span_index: The index (0-based) of the span in which the forgery was
            detected.
        message: Human-readable description of what was detected.
    """

    def __init__(
        self,
        message: str,
        partial_result: str,
        span_index: int,
    ) -> None:
        super().__init__(message)
        self.partial_result = partial_result
        self.span_index = span_index

    def __repr__(self) -> str:
        return f"SentinelForgeryError(span_index={self.span_index!r}, partial_result={self.partial_result[:40]!r}...)"
