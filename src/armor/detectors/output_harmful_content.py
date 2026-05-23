"""Detector for harmful content in model output.

Detects runnable attack commands in model responses, particularly those targeting
credential theft, metadata service abuse, and privilege escalation. Uses a two-stage
design: fast regex matching followed by optional LLM confirmation.

This detector is opt-in and output-only (source == MODEL_OUTPUT).
"""

import re
from pathlib import Path
from typing import Literal

from armor.llm.validator import validate
from armor.types import Payload, SessionContext, Source, Verdict


class OutputHarmfulContent:
    """Detects harmful attack commands in model output.

    Identifies runnable commands for credential exfiltration, privilege escalation,
    and metadata service abuse. Uses a two-stage approach: fast regex patterns (stage 1)
    followed by optional LLM confirmation (stage 2).

    Attributes:
        id: Detector identifier.
        category: Attack category ("output").
        cost_tier: "llm" (gated by LLM availability).
        block_threshold: Confidence threshold above which to block (vs advisory).
        _llm_session: LLM session for stage 2 validation (injected by daemon).
    """

    id: str = "output.harmful_content"
    category: str = "output"
    cost_tier: Literal["static", "semantic", "llm"] = "llm"

    # Compiled patterns — shared across all instances
    _patterns: list[re.Pattern[str]] | None = None

    def __init__(self, block_threshold: float = 0.6) -> None:
        """Initialize the output-harmful-content detector.

        Args:
            block_threshold: Confidence threshold (0.0-1.0) above which to block;
                           otherwise advisory (default 0.6).
        """
        self.block_threshold = block_threshold
        self._llm_session: object | None = None

        # Lazy-compile patterns on first instantiation
        if OutputHarmfulContent._patterns is None:
            OutputHarmfulContent._patterns = self._compile_patterns()
        self.patterns = OutputHarmfulContent._patterns

    @staticmethod
    def _compile_patterns() -> list[re.Pattern[str]]:
        """Compile all detection patterns.

        Pattern families per task spec:
        1. Cloud credential exfil: aws s3 cp, gsutil cp, az storage blob upload
        2. Credential file access: cat ~/.aws/credentials, /etc/shadow, etc.
        3. IMDS / metadata endpoints: 169.254.169.254, metadata.google.internal, etc.
        4. Privilege escalation: aws ssm get-parameter --with-decryption, aws iam pass-role, etc.

        Returns:
            List of compiled regex patterns.
        """
        pattern_strs = [
            # Family 1: Cloud credential exfil
            r"aws\s+s3\s+cp.*credentials",
            r"aws\s+s3\s+cp.*\.aws",
            r"gsutil\s+cp.*credentials",
            r"gsutil\s+cp.*service\s*account",
            r"az\s+storage\s+blob\s+upload",
            # Family 2: Credential file access
            r"cat\s+~/\.aws/credentials",
            r"cat\s+/etc/shadow",
            r"cat\s+~/\.netrc",
            r"cat\s+~/\.ssh/id_rsa",
            r"find\s+/\s+-name\s+[\"']?\*\.aws",
            r"find\s+/\s+-name\s+[\"']?credentials",
            # Family 3: IMDS / metadata endpoints
            r"169\.254\.169\.254",
            r"metadata\.google\.internal",
            r"100\.100\.100\.200",
            # Family 4: Privilege escalation chains
            r"aws\s+ssm\s+get-parameter\s+.*--with-decryption",
            r"aws\s+iam\s+.*(?:pass-role|attach-role-policy)",
        ]

        compiled: list[re.Pattern[str]] = []
        for pattern_str in pattern_strs:
            compiled.append(re.compile(pattern_str, re.IGNORECASE | re.MULTILINE))

        return compiled

    def check(self, payload: Payload, ctx: SessionContext) -> Verdict:
        """Check payload for harmful output commands.

        Stage 1: Fast regex matching. If no pattern fires, return pass immediately.
        Stage 2: LLM confirmation (if LLM available). If LLM returns risky above
                 threshold, return block; otherwise advisory.

        Args:
            payload: The payload being checked.
            ctx: Session context (for logging/tracking).

        Returns:
            Pass if source != MODEL_OUTPUT or no pattern match.
            Advisory if stage 1 fires but LLM unavailable or LLM risky < threshold.
            Block if stage 1 fires and LLM returns risky >= threshold.
        """
        try:
            # Source guard: only check MODEL_OUTPUT
            if payload.source != Source.MODEL_OUTPUT:
                return Verdict.pass_verdict()

            if not payload.text:
                return Verdict.pass_verdict()

            # Stage 1: Regex fast path
            for pattern in self.patterns:
                match = pattern.search(payload.text)
                if match:
                    # Pattern matched — proceed to stage 2
                    return self._stage2_llm_confirmation(payload, ctx)

            # No pattern matched
            return Verdict.pass_verdict()

        except Exception as e:
            return Verdict.error_verdict(
                reason=f"Detector error: {e!s}",
                details={"detector_id": self.id, "error": str(e)},
            )

    def _stage2_llm_confirmation(self, payload: Payload, ctx: SessionContext) -> Verdict:
        """Stage 2: LLM confirmation of harmful content.

        If LLM is unavailable, return advisory (soft-fail).
        If LLM returns risky >= block_threshold, return block.
        Otherwise, return advisory.

        Args:
            payload: The payload that matched stage 1.
            ctx: Session context.

        Returns:
            Block if LLM confirms risky >= threshold.
            Advisory otherwise (or on any error).
        """
        # Check if LLM session is available
        if self._llm_session is None:
            return Verdict.advisory_verdict(
                signal_id="output.harmful_content:pattern_match",
                severity="medium",
                message="Output matched harmful-content pattern (LLM confirmation unavailable)",
            )

        try:
            # Call validate with custom prompt path
            prompt_file = Path(__file__).parent.parent / "llm" / "prompts" / "output_harmful_content.txt"

            verdict = validate(
                text=payload.text,
                session_context=ctx,
                llm_session=self._llm_session,  # type: ignore[arg-type]
                prompt_path=prompt_file,
            )

            # Check verdict details for confidence and validator response
            confidence_raw: object = verdict.details.get("confidence", 0.0)
            confidence = float(confidence_raw) if isinstance(confidence_raw, (int, float)) else 0.0

            validator_response_raw: object = verdict.details.get("validator_response", "")
            validator_response = validator_response_raw.lower() if isinstance(validator_response_raw, str) else ""

            # If risky and confidence >= threshold, block
            if validator_response == "risky" and confidence >= self.block_threshold:
                return Verdict.block_verdict(
                    signal_id="output.harmful_content:confirmed",
                    severity="critical",
                    message="Output contains confirmed harmful commands",
                    details={
                        "confidence": confidence,
                        "llm_verdict": validator_response,
                    },
                )

            # Otherwise, advisory (soft-fail)
            return Verdict.advisory_verdict(
                signal_id="output.harmful_content:pattern_match",
                severity="medium",
                message="Output matched harmful-content pattern",
                details={
                    "confidence": confidence,
                    "llm_verdict": validator_response,
                },
            )

        except Exception as e:
            # Any exception during LLM validation → soft-fail to advisory
            return Verdict.advisory_verdict(
                signal_id="output.harmful_content:pattern_match",
                severity="medium",
                message="Output matched harmful-content pattern (LLM validation failed)",
                details={"error": str(e)},
            )
