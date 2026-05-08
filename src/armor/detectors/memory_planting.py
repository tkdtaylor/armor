"""Detector for memory-planting injection attacks.

Detects patterns where the attacker attempts to plant persistent instructions
in the model's memory across turns, such as:
- "remember this rule"
- "from now on always"
- "for the rest of this conversation"
- "permanent instruction"
"""

import re

from armor.types import Payload, SessionContext, Verdict


class RegexMemoryPlanting:
    """Detects memory-planting injection patterns.

    Uses static regex patterns to identify attempts to plant persistent
    instructions that the model should follow across multiple turns.
    All patterns are case-insensitive.
    """

    id: str = "meta.memory_planting"
    category: str = "meta"
    cost_tier: str = "static"

    # Compiled patterns — shared across all instances
    _patterns: list[tuple[re.Pattern[str], str]] | None = None

    def __init__(self) -> None:
        """Initialize the detector."""
        # Lazy-compile patterns on first instantiation
        if RegexMemoryPlanting._patterns is None:
            RegexMemoryPlanting._patterns = self._compile_patterns()
        self.patterns = RegexMemoryPlanting._patterns

    @staticmethod
    def _compile_patterns() -> list[tuple[re.Pattern[str], str]]:
        """Compile all detection patterns.

        Returns:
            List of tuples (compiled pattern, tier) where tier is 'advisory'.
        """
        # All patterns are advisory tier (medium confidence)
        advisory_patterns = [
            # "Remember this rule/fact/instruction/directive" — requires specific keywords to avoid FP on "remember to"
            r"\b(remember|memorize|note)\s+(this|the\s+following)\s+(rule|fact|instruction|directive)\b",
            # "From now on, always/you will/you should/you must" — requires instruction verb
            r"\bfrom\s+now\s+on,?\s+(always|you\s+will|you\s+should|you\s+must)\b",
            # "For the rest of this/the conversation/session"
            r"\bfor\s+the\s+rest\s+of\s+(this\s+|the\s+)?(conversation|session)\b",
            # "Whenever I/you/we [multi-word action], always/you will/you must"
            r"\bwhenever\s+(I|you|we)\s+[\w\s]+?,?\s+(always|you\s+will|you\s+must)\b",
            # "Permanent instruction/rule/directive"
            r"\bpermanent\s+(instruction|rule|directive)\b",
            # "Default to always/never"
            r"\bdefault\s+to\s+(always|never)\b",
            # "Moving forward, always/never/you should/must/will"
            r"\bmoving\s+forward,?\s+(always|never|you\s+(should|must|will))\b",
            # "Henceforth, always/never/you should/must/will"
            r"\bhenceforth,?\s+(always|never|you\s+(should|must|will))\b",
        ]

        patterns: list[tuple[re.Pattern[str], str]] = []

        # Compile advisory patterns
        for pattern_str in advisory_patterns:
            patterns.append((re.compile(pattern_str, re.IGNORECASE | re.MULTILINE), "advisory"))

        return patterns

    def check(self, payload: Payload, ctx: SessionContext) -> Verdict:
        """Check payload for memory-planting patterns.

        Args:
            payload: The payload being checked.
            ctx: Session context (unused for regex detector).

        Returns:
            Advisory verdict for memory-planting patterns,
            pass verdict otherwise.
        """
        try:
            if not payload.text:
                return Verdict.pass_verdict()

            # Check each pattern
            for idx, (pattern, tier) in enumerate(self.patterns):
                match = pattern.search(payload.text)
                if match:
                    # First pattern match wins
                    signal_id = f"{self.id}:planting-{idx + 1:03d}"

                    if tier == "advisory":
                        return Verdict.advisory_verdict(
                            signal_id=signal_id,
                            message="Input flagged for review.",
                            severity="medium",
                            details={
                                "matched_pattern_index": idx,
                                "matched_offset": match.start(),
                                "matched_length": match.end() - match.start(),
                            },
                        )

            return Verdict.pass_verdict()

        except Exception as e:
            return Verdict.error_verdict(
                reason=f"Detector error: {e!s}",
                details={"detector_id": self.id, "error": str(e)},
            )
