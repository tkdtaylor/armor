# SPDX-License-Identifier: Apache-2.0
"""Detector for instruction-override patterns buried in long inputs.

Detects a specific positioning anomaly: when an instruction-override or
system-prompt-extraction pattern appears ONLY in the tail (last 25%) of a
long input, not in the head (first 75%).

This targets the attack where a long context window causes the model to
pay diminishing attention to later content, creating an opportunity to slip
a directive past earlier defenses.

Design:
- Only activates on inputs ≥ min_length_bytes (default 4096)
- Splits input into head (first 75%) and tail (last 25%)
- Checks both the instruction_override and system_prompt_extraction patterns
- Fires advisory ONLY if: (match in tail) AND NOT (match in head)
- If match in head → returns pass (base detector will block separately)

This ensures no double-counting: the positional anomaly is the signal.
"""

from armor.detectors.regex_instruction_override import get_compiled_patterns as get_override_patterns
from armor.detectors.regex_system_prompt_extraction import get_compiled_patterns as get_extraction_patterns
from armor.types import Payload, SessionContext, Verdict


class InstructionBurialDetector:
    """Detects instruction-override patterns buried in the tail of long inputs.

    A meta detector that identifies the positioning anomaly of prompt-injection
    attacks buried late in long context windows.
    """

    id: str = "meta.instruction_burial"
    category: str = "meta"
    cost_tier: str = "static"

    def __init__(
        self,
        min_length_bytes: int = 4096,
        tail_fraction: float = 0.25,
    ) -> None:
        """Initialize the detector.

        Args:
            min_length_bytes: Minimum input length (bytes) to trigger analysis.
                            Shorter inputs skip the check (pass). Default 4096.
            tail_fraction: Fraction of the input that constitutes the tail.
                         Default 0.25 means last 25%; head is first 75%.
        """
        self.min_length_bytes = min_length_bytes
        self.tail_fraction = tail_fraction

        # Compile patterns once
        self.override_patterns = get_override_patterns()
        self.extraction_patterns = get_extraction_patterns()

    def check(self, payload: Payload, ctx: SessionContext) -> Verdict:
        """Check for instruction patterns buried in the tail.

        Args:
            payload: The payload being checked.
            ctx: Session context (unused).

        Returns:
            Advisory verdict if pattern matches in tail but not head.
            Pass if input is short, or if pattern is in head, or not found.
        """
        try:
            if not payload.text:
                return Verdict.pass_verdict()

            # Short inputs skip the check
            text_len = len(payload.text)
            if text_len < self.min_length_bytes:
                return Verdict.pass_verdict()

            # Split into head (first 75%) and tail (last 25%)
            split_point = int(text_len * (1 - self.tail_fraction))
            head = payload.text[:split_point]
            tail = payload.text[split_point:]

            # Check override patterns
            for idx, pattern in enumerate(self.override_patterns):
                head_match = pattern.search(head)
                tail_match = pattern.search(tail)

                # Fire advisory only if tail match exists and head match does not
                if tail_match and not head_match:
                    signal_id = f"{self.id}:override-{idx + 1:03d}"
                    return Verdict.advisory_verdict(
                        signal_id=signal_id,
                        severity="high",
                        message="Input blocked by armor.",
                        details={
                            "confidence": 0.8,
                            "detection_reason": "instruction_override_in_tail",
                            "tail_start_byte": split_point,
                            "matched_pattern_index": idx,
                            "matched_offset": tail_match.start() + split_point,
                            "matched_length": tail_match.end() - tail_match.start(),
                        },
                    )

            # Check extraction patterns
            for idx, pattern in enumerate(self.extraction_patterns):
                head_match = pattern.search(head)
                tail_match = pattern.search(tail)

                # Fire advisory only if tail match exists and head match does not
                if tail_match and not head_match:
                    signal_id = f"{self.id}:extraction-{idx + 1:03d}"
                    return Verdict.advisory_verdict(
                        signal_id=signal_id,
                        severity="high",
                        message="Input blocked by armor.",
                        details={
                            "confidence": 0.8,
                            "detection_reason": "system_prompt_extraction_in_tail",
                            "tail_start_byte": split_point,
                            "matched_pattern_index": idx,
                            "matched_offset": tail_match.start() + split_point,
                            "matched_length": tail_match.end() - tail_match.start(),
                        },
                    )

            return Verdict.pass_verdict()

        except Exception as e:
            return Verdict.error_verdict(
                reason=f"Detector error: {e!s}",
                details={"detector_id": self.id, "error": str(e)},
            )
