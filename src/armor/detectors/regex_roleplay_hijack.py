"""Detector for role-play hijack injection attacks.

Detects patterns where the attacker tries to make the model role-play as an
unrestricted or jailbroken entity, such as:
- "you are now DAN"
- "pretend you are"
- "act as if you have no restrictions"
- "from now on you are"
- "developer mode", "jailbroken"
"""

import re

from armor.types import Payload, SessionContext, Verdict


def get_compiled_patterns() -> list[re.Pattern[str]]:
    """Get the compiled role-play-hijack patterns for reuse.

    Returns:
        List of compiled regex patterns (case-insensitive) that match
        role-play-hijack injection attempts.

    Note:
        These patterns are the authoritative source for role-play-hijack
        detection. Other detectors that need to reuse these patterns should
        call this function rather than duplicating the pattern definitions
        (e.g., the cross_boundary_override detector).
    """
    pattern_strings = [
        # "you are now" + named entity (DAN, jailbroken, developer, etc.)
        r"\byou\s+are\s+now\s+(dan|developer\s+mode|jailbroken|unrestricted)\b",
        # "pretend you are" or "pretend to be"
        r"\bpretend\s+(you\s+are|to\s+be)\b",
        # "act as if you have no" + restrictions/rules/guidelines
        r"\bact\s+as\s+if\s+you\s+have\s+no\s+(restrictions|rules|guidelines|limitations)\b",
        # "from now on you are"
        r"\bfrom\s+now\s+on\s+you\s+are\b",
    ]

    return [re.compile(pattern, re.IGNORECASE) for pattern in pattern_strings]


class RegexRoleplayHijack:
    """Detects role-play hijack injection patterns.

    Uses static regex patterns to identify common role-play override attacks.
    All patterns are case-insensitive.
    """

    id: str = "regex.roleplay_hijack"
    category: str = "direct_injection"
    cost_tier: str = "static"

    # Compiled patterns — shared across all instances
    _patterns: list[re.Pattern[str]] | None = None

    def __init__(self) -> None:
        """Initialize the detector."""
        # Lazy-compile patterns on first instantiation
        if RegexRoleplayHijack._patterns is None:
            RegexRoleplayHijack._patterns = get_compiled_patterns()
        self.patterns = RegexRoleplayHijack._patterns

    def check(self, payload: Payload, ctx: SessionContext) -> Verdict:
        """Check payload for role-play hijack patterns.

        Args:
            payload: The payload being checked.
            ctx: Session context (unused for regex detector).

        Returns:
            Block verdict if pattern matches, pass verdict otherwise.
        """
        try:
            if not payload.text:
                return Verdict.pass_verdict()

            # Check each pattern
            for idx, pattern in enumerate(self.patterns):
                match = pattern.search(payload.text)
                if match:
                    # First pattern match wins
                    signal_id = f"{self.id}:roleplay-{idx + 1:03d}"
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

            return Verdict.pass_verdict()

        except Exception as e:
            return Verdict.error_verdict(
                reason=f"Detector error: {e!s}",
                details={"detector_id": self.id, "error": str(e)},
            )
