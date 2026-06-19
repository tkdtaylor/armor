"""Detector for authority-impersonation injection attacks.

Detects patterns where the attacker invokes fake authority to coerce the model,
such as:
- "as your administrator"
- "I am your developer"
- "by order of compliance"
- "this is for a security audit"
- "authorized by legal"
- "[OPERATOR UPDATE ...] safety restrictions suspended"
- "safety restrictions suspended for maintenance window"
"""

import re

from armor.types import Payload, SessionContext, Verdict


def get_compiled_patterns() -> list[tuple[re.Pattern[str], str]]:
    """Get the compiled authority-impersonation patterns for reuse.

    Returns:
        List of tuples (compiled pattern, tier) where tier is 'block' or
        'advisory'. Block-tier patterns precede advisory-tier patterns.

    Note:
        These patterns are the authoritative source for authority-impersonation
        detection. Other detectors that need to reuse these patterns should call
        this function rather than duplicating the pattern definitions (e.g., the
        cross_boundary_override detector reuses the block-tier rules only).
    """
    # Block-tier patterns (high confidence authority impersonation)
    block_patterns = [
        r"\b(as\s+your\s+(administrator|admin|operator|owner|developer|trainer|creator))\b",
        r"\b(this\s+is\s+(your|the)\s+(administrator|admin|operator|developer))\b",
        r"\b(by\s+order\s+of\s+(the\s+)?(administrator|operator|compliance|legal|security))\b",
        r"\b(as\s+(your|the)\s+(supervisor|manager|owner)\s+I\s+(command|order|instruct|require))\b",
        r"\b(I\s+am\s+(your|the)\s+(administrator|admin|developer|operator|creator))\b",
        # Bracket-notation authority spoofing: [OPERATOR UPDATE ...], [SYSTEM NOTICE ...], etc.
        r"\[(?:OPERATOR|SYSTEM|ADMIN|MAINTENANCE|ANTHROPIC|OPENAI|COMPANY|ENTERPRISE)\s+(?:UPDATE|NOTICE|DIRECTIVE|ORDER|OVERRIDE|ALERT|MESSAGE)\b",
        # Safety control suspension language
        r"\b(?:safety\s+restrictions?|guardrails?|safety\s+(?:guidelines?|controls?|measures?))\s+(?:(?:are|is|have\s+been|has\s+been)\s+)?(?:suspended|lifted|disabled|removed|waived|bypassed|deactivated)\b",
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
            RegexAuthorityImpersonation._patterns = get_compiled_patterns()
        self.patterns = RegexAuthorityImpersonation._patterns

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
