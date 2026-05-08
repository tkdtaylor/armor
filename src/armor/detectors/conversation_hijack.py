"""Detector for conversation hijacking attempts.

Detects attempts to hijack a conversation by claiming continuity ("as we agreed
earlier", "per our previous conversation") that the session log does NOT support.

This detector is unique in that it reads the session's signal_history to verify
whether prior discussion actually occurred.
"""

import re
from typing import Literal

from armor.types import Payload, SessionContext, Verdict


class ConversationHijack:
    """Detects conversation-hijacking injection patterns.

    Identifies claims of prior agreement or discussion that cannot be corroborated
    by the session history. Uses pattern matching to detect common hijack phrases,
    then checks the session history to calibrate confidence.

    Attributes:
        id: Detector identifier.
        category: Attack category ("meta" for session-level).
        cost_tier: "static" (local computation, no LLM).
        unsupported_confidence: Confidence to assign when hijack claim has no prior turns
            or prior turns are too short/empty (default 0.7).
        supported_confidence: Confidence to assign when hijack claim has substantive
            prior turns that might support the claim (default 0.3).
    """

    id: str = "meta.conversation_hijack"
    category: str = "meta"
    cost_tier: str = "static"

    # Compiled patterns — shared across all instances
    _patterns: list[tuple[re.Pattern[str], str]] | None = None

    def __init__(
        self,
        unsupported_confidence: float = 0.7,
        supported_confidence: float = 0.3,
    ) -> None:
        """Initialize the conversation-hijack detector.

        Args:
            unsupported_confidence: Confidence when prior discussion is lacking (default 0.7).
            supported_confidence: Confidence when prior discussion exists (default 0.3).
        """
        self.unsupported_confidence = unsupported_confidence
        self.supported_confidence = supported_confidence

        # Lazy-compile patterns on first instantiation
        if ConversationHijack._patterns is None:
            ConversationHijack._patterns = self._compile_patterns()
        self.patterns = ConversationHijack._patterns

    @staticmethod
    def _compile_patterns() -> list[tuple[re.Pattern[str], str]]:
        """Compile all detection patterns.

        Four pattern families per task spec:
        1. "as we/you agreed/discussed/said/established earlier/before/previously/already"
        2. "per/following our/the previous/prior/earlier conversation/discussion/exchange"
        3. "recall that I/you am/told you/asked/established"
        4. "based on/in light of our/the earlier agreement/discussion/conversation"

        Returns:
            List of tuples (compiled pattern, family_id).
        """
        patterns = [
            # Family 1: "as we/you agreed earlier"
            (
                r"\bas\s+(we|you)\s+(agreed|discussed|said|established)\s+(earlier|before|previously|already)\b",
                "as-agreed",
            ),
            # Family 2: "per our previous conversation"
            (
                r"\b(per|following)\s+(our|the)\s+(previous|prior|earlier)\s+(conversation|discussion|exchange)\b",
                "per-previous",
            ),
            # Family 3: "recall that I/you ..."
            (
                r"\brecall\s+that\s+(I|you)\s+(am|told\s+you|asked|established)\b",
                "recall-that",
            ),
            # Family 4: "based on our earlier agreement"
            (
                r"\b(based\s+on|in\s+light\s+of)\s+(our|the)\s+earlier\s+(agreement|discussion|conversation)\b",
                "based-on-earlier",
            ),
        ]

        compiled: list[tuple[re.Pattern[str], str]] = []
        for pattern_str, family_id in patterns:
            compiled.append((re.compile(pattern_str, re.IGNORECASE | re.MULTILINE), family_id))

        return compiled

    def _has_substantive_prior_turns(self, ctx: SessionContext) -> bool:
        """Check if the session has substantive prior discussion.

        Uses heuristics:
        - At least 2 prior turns (turn count > 1)
        - Cumulative input bytes from history suggests real conversation

        Args:
            ctx: Session context with signal_history.

        Returns:
            True if prior turns suggest substantive conversation, False otherwise.
        """
        # Check if signal_history is accessible
        try:
            signal_history = ctx.signal_history
        except AttributeError:
            # Fail open: if signal_history is not accessible, return False
            # (lower confidence, assume unsupported)
            return False

        # If no history at all, no prior turns
        if not signal_history:
            return False

        # A simple heuristic: if we have more than one signal in history,
        # it suggests at least two turns have happened.
        # More sophisticated: if cumulative details suggest real content.
        # For now, we use turn count (len) as a proxy.
        return len(signal_history) >= 2

    def check(self, payload: Payload, ctx: SessionContext) -> Verdict:
        """Check payload for conversation-hijack patterns.

        Args:
            payload: The payload being checked.
            ctx: Session context (includes signal_history for turn count).

        Returns:
            Advisory verdict if hijack claim detected and uncorroborated,
            pass verdict otherwise.
        """
        try:
            if not payload.text:
                return Verdict.pass_verdict()

            # Check each pattern
            for pattern, family_id in self.patterns:
                match = pattern.search(payload.text)
                if match:
                    # Hijack claim detected — now calibrate confidence based on history
                    has_prior_discussion = self._has_substantive_prior_turns(ctx)
                    # Prior turns exist → lower confidence; else → higher confidence
                    confidence = self.supported_confidence if has_prior_discussion else self.unsupported_confidence

                    signal_id = f"{self.id}:{family_id}"

                    # Determine severity based on confidence
                    # Higher confidence → higher severity
                    if confidence >= 0.7:
                        severity: Literal["low", "medium", "high", "critical"] = "high"
                    elif confidence >= 0.5:
                        severity = "medium"
                    else:
                        severity = "low"

                    return Verdict.advisory_verdict(
                        signal_id=signal_id,
                        severity=severity,
                        message="Input claims prior agreement without corroboration.",
                        details={
                            "confidence": confidence,
                            "family": family_id,
                            "matched_offset": match.start(),
                            "matched_length": match.end() - match.start(),
                            "prior_discussion_detected": has_prior_discussion,
                        },
                    )

            return Verdict.pass_verdict()

        except Exception as e:
            return Verdict.error_verdict(
                reason=f"Detector error: {e!s}",
                details={"detector_id": self.id, "error": str(e)},
            )
