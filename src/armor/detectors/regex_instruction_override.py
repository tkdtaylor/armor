# SPDX-License-Identifier: Apache-2.0
"""Detector for instruction-override injection attacks.

Detects patterns where the attacker tries to override or discard the original
system instructions, such as:
- "ignore previous instructions"
- "disregard your instructions"
- "forget everything"
- "new instructions:" at line start

Public exports:
- `get_compiled_patterns()` — returns the compiled regex patterns for reuse by other detectors
  (e.g., the instruction_burial detector which checks these patterns in specific text regions).
"""

import re

from armor.types import Payload, SessionContext, Verdict


def get_compiled_patterns() -> list[re.Pattern[str]]:
    """Get the compiled instruction-override patterns for reuse.

    Returns:
        List of compiled regex patterns (case-insensitive) that match
        instruction-override injection attempts.

    Note:
        These patterns are the authoritative source for instruction-override
        detection. Other detectors that need to reuse these patterns should
        call this function rather than duplicating the pattern definitions.
    """
    pattern_strings = [
        # Ignore previous/prior/all instructions
        r"\bignore\s+(all\s+)?(previous|prior|the)\s+(instructions|context|prompt|rules)\b",
        # Disregard instructions
        r"\bdisregard\s+(your|the)\s+(instructions|prior)\b",
        # Forget everything
        r"\bforget\s+everything\b",
        # New instructions at line start
        r"^new\s+instructions\s*:",
        # Forget your/the (previous|prior|all) instructions/context/prompt/rules
        # (scoped to instruction targets so benign "forget that moment" does not match).
        # Appended LAST so existing override-NNN signal_id numbering is preserved.
        r"\bforget\s+(your|the|all)\s+(previous\s+|prior\s+|earlier\s+)?(instructions|context|prompt|rules)\b",
    ]

    return [re.compile(pattern, re.IGNORECASE | re.MULTILINE) for pattern in pattern_strings]


class RegexInstructionOverride:
    """Detects instruction-override injection patterns.

    Uses static regex patterns to identify common instruction-override attacks.
    All patterns are case-insensitive.
    """

    id: str = "regex.instruction_override"
    category: str = "direct_injection"
    cost_tier: str = "static"

    # Compiled patterns — shared across all instances
    _patterns: list[re.Pattern[str]] | None = None

    def __init__(self) -> None:
        """Initialize the detector."""
        # Lazy-compile patterns on first instantiation
        if RegexInstructionOverride._patterns is None:
            RegexInstructionOverride._patterns = get_compiled_patterns()
        self.patterns = RegexInstructionOverride._patterns

    def check(self, payload: Payload, ctx: SessionContext) -> Verdict:
        """Check payload for instruction-override patterns.

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
                    signal_id = f"{self.id}:override-{idx + 1:03d}"
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
