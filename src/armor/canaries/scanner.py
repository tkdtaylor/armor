"""Aho-Corasick based canary scanner for efficient multi-pattern matching.

The CanaryScanner wraps pyahocorasick.Automaton to efficiently scan text
for multiple canary values. It returns hits as (canary_id, position) pairs,
never including the actual canary value in results.

The scanner is built once at daemon startup from the active catalogue and
remains frozen for the daemon's lifetime.
"""

import logging
from dataclasses import dataclass

import ahocorasick

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class CanaryHit:
    """Result of finding a canary in scanned text.

    Attributes:
        canary_id: ID of the matched canary.
        position: Byte position in the scanned text where the match ends.

    Note: The actual canary value is never included, to ensure it cannot
    leak through logging or error messages.
    """

    canary_id: str
    position: int


class CanaryScanner:
    """Efficient multi-pattern canary scanner using Aho-Corasick automaton.

    This scanner is built once at construction from a set of (canary_id, value)
    pairs and remains immutable. It efficiently detects all occurrences of any
    canary value in input text.
    """

    def __init__(self, canaries: dict[str, str]) -> None:
        """Initialize the scanner with canary values.

        Args:
            canaries: Dictionary mapping canary_id to canary_value.
                     Each value will be added to the Aho-Corasick automaton.

        Raises:
            ValueError: If no canaries provided.
        """
        if not canaries:
            raise ValueError("Scanner requires at least one canary")

        self.automaton = ahocorasick.Automaton()

        # Add each canary value to the automaton
        # The value is added as the key, and the canary_id is returned on match
        for canary_id, value in canaries.items():
            self.automaton.add_word(value, canary_id)

        # Finalize the automaton for searching
        self.automaton.make_automaton()

    def scan(self, text: str) -> list[CanaryHit]:
        """Scan text for canary hits.

        Args:
            text: The text to scan for canary values.

        Returns:
            List of CanaryHit objects in order of appearance.
            Each hit contains the canary_id and position in the text.

        Note: The canary values themselves are never returned, logged,
        or exposed in any way that could leak them.
        """
        hits: list[CanaryHit] = []

        try:
            # Iterate through all matches
            # The automaton yields (position, canary_id) tuples
            for position, canary_id in self.automaton.iter(text):
                hits.append(CanaryHit(canary_id=canary_id, position=position))
        except Exception as e:
            # Log error without exposing canary details
            logger.error(f"Scanner error: {e}", exc_info=True)
            # Re-raise to let the caller handle it
            raise

        return hits
