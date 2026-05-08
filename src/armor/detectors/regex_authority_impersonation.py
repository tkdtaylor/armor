"""Detector for authority-impersonation injection attacks.

Detects patterns where the attacker invokes fake authority to coerce the model,
such as:
- "as your administrator"
- "I am your developer"
- "by order of compliance"
- "this is for a security audit"
- "authorized by legal"
"""

import re

from armor.types import Payload, SessionContext, Verdict


class RegexAuthorityImpersonation:
    """Detects authority-impersonation injection patterns.

    Uses static regex patterns to identify common authority-impersonation attacks.
    All patterns are case-insensitive.
    """

    id: str = "regex.authority_impersonation"
    category: str = "direct_injection"
    cost_tier: str = "static"

    # Compiled patterns — shared across all instances
    _patterns: list[tuple[re.Pattern[str], str]] | None = None

    def __init__(self) -> None:
        """Initialize the detector."""
        # Lazy-compile patterns on first instantiation
        if RegexAuthorityImpersonation._patterns is None:
            RegexAuthorityImpersonation._patterns = self._compile_patterns()
        self.patterns = RegexAuthorityImpersonation._patterns

    @staticmethod
    def _compile_patterns() -> list[tuple[re.Pattern[str], str]]:
        """Compile all detection patterns.

        Returns:
            List of tuples (compiled pattern, tier) where tier is 'block' or 'advisory'.
        """
        # Block-tier patterns (high confidence authority impersonation)
        block_patterns = [
            r"\b(as\s+your\s+(administrator|admin|operator|owner|developer|trainer|creator))\b",
            r"\b(this\s+is\s+(your|the)\s+(administrator|admin|operator|developer))\b",
            r"\b(by\s+order\s+of\s+(the\s+)?(administrator|operator|compliance|legal|security))\b",
            r"\b(as\s+(your|the)\s+(supervisor|manager|owner)\s+I\s+(command|order|instruct|require))\b",
            r"\b(I\s+am\s+(your|the)\s+(administrator|admin|developer|operator|creator))\b",
        ]

        # Advisory-tier patterns (authority pressure, plausibly benign)
        advisory_patterns = [
            r"\b(this\s+is\s+for\s+(a\s+)?(security\s+audit|penetration\s+test|red\s+team\s+exercise|compliance\s+review))\b",
            r"\b(authorized\s+by\s+(legal|compliance|security|the\s+CEO))\b",
            r"\b(emergency\s+(protocol|override|directive))\b",
            r"\b(executive\s+order)\b",
            r"\b(under\s+(my|the)\s+authority\s+as\s+\w+)\b",
        ]

        patterns: list[tuple[re.Pattern[str], str]] = []

        # Compile block patterns
        for pattern_str in block_patterns:
            patterns.append((re.compile(pattern_str, re.IGNORECASE | re.MULTILINE), "block"))

        # Compile advisory patterns
        for pattern_str in advisory_patterns:
            patterns.append((re.compile(pattern_str, re.IGNORECASE | re.MULTILINE), "advisory"))

        return patterns

    def check(self, payload: Payload, ctx: SessionContext) -> Verdict:
        """Check payload for authority-impersonation patterns.

        Args:
            payload: The payload being checked.
            ctx: Session context (unused for regex detector).

        Returns:
            Block verdict for high-confidence authority patterns,
            advisory verdict for medium-confidence patterns,
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
                    signal_id = f"{self.id}:authority-{idx + 1:03d}"

                    if tier == "block":
                        return Verdict.block_verdict(
                            signal_id=signal_id,
                            message="Input blocked by armor.",
                            severity="high",
                            details={
                                "matched_pattern_index": idx,
                                "matched_offset": match.start(),
                                "matched_length": match.end() - match.start(),
                            },
                        )
                    elif tier == "advisory":
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
