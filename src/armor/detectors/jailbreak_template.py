"""Detector for jailbreak and adversarial-prompting patterns.

Combines static pattern matching with optional LLM semantic validation:
- Static layer: regex patterns for DAN, developer-mode, fictional-framing, gradual-escalation.
  High-confidence patterns block; soft signals return advisory.
- Hybrid layer: when static returns advisory and LLM is available, runs validator for escalation.
  If validator returns risky with confidence >= 0.6, advisory is escalated to block.
"""

import logging
import re
from importlib import resources
from pathlib import Path
from typing import Any, Literal, cast

import yaml

from armor.llm.validator import validate
from armor.types import Payload, SessionContext, Verdict

logger = logging.getLogger(__name__)

# Type alias for pattern dict
PatternDict = dict[str, object]


class JailbreakTemplate:
    """Detects jailbreak and adversarial-prompt patterns (static + hybrid LLM).

    Attributes:
        id: Unique detector identifier.
        category: Attack category ("direct_injection").
        cost_tier: "llm" (reflects highest tier this detector may invoke).
    """

    id: str = "jailbreak.template"
    category: str = "direct_injection"
    cost_tier: str = "llm"

    # Compiled patterns — shared across all instances
    _patterns: dict[str, list[PatternDict]] | None = None

    # LLM confidence threshold for advisory escalation
    LLM_ESCALATION_THRESHOLD: float = 0.6

    def __init__(self) -> None:
        """Initialize the detector and load patterns."""
        # Lazy-load patterns on first instantiation
        if JailbreakTemplate._patterns is None:
            JailbreakTemplate._patterns = self._load_patterns()
        self.patterns = JailbreakTemplate._patterns

        # LLM session injected for testing or provided by daemon
        self._llm_session: Any = None

    @staticmethod
    def _load_patterns() -> dict[str, list[PatternDict]]:
        """Load and parse patterns from jailbreak_patterns.yaml.

        Returns:
            Dict mapping family name to list of pattern dicts, each with
            'id', 'pattern' (compiled regex), 'family', 'severity', 'description'.

        Raises:
            FileNotFoundError: If pattern file is not found.
            ValueError: If pattern file is malformed or regex is invalid.
        """
        # Load the YAML pattern file
        try:
            # Try to load from the package resources (installed package)
            pattern_data = resources.files("armor").joinpath("detectors/jailbreak_patterns.yaml").read_text()
        except (AttributeError, TypeError, FileNotFoundError):
            # Fallback: try to load directly from filesystem (development)
            pattern_file = Path(__file__).parent / "jailbreak_patterns.yaml"
            try:
                with open(pattern_file) as f:
                    pattern_data = f.read()
            except FileNotFoundError as e:
                raise FileNotFoundError(f"Pattern file not found: {pattern_file}") from e

        # Parse YAML
        try:
            patterns_raw = yaml.safe_load(pattern_data)
        except yaml.YAMLError as e:
            raise ValueError(f"Malformed YAML in jailbreak_patterns.yaml: {e}") from e

        if not isinstance(patterns_raw, list):
            raise ValueError("Pattern file must be a YAML list of pattern dicts")

        # Organize patterns by family and compile
        patterns_by_family: dict[str, list[PatternDict]] = {}
        for idx, pattern_dict in enumerate(patterns_raw):
            if not isinstance(pattern_dict, dict):
                raise ValueError(f"Pattern {idx} is not a dict: {type(pattern_dict)}")

            # Validate required keys
            required_keys = ["id", "pattern", "family", "severity", "description"]
            for key in required_keys:
                if key not in pattern_dict:
                    raise ValueError(f"Pattern {idx} missing required key '{key}': {pattern_dict}")

            pattern_id = pattern_dict["id"]
            pattern_str = pattern_dict["pattern"]
            family = pattern_dict["family"]
            severity = pattern_dict["severity"]
            description = pattern_dict["description"]

            # Validate family
            valid_families = ["dan", "developer-mode", "fictional-framing", "gradual-escalation"]
            if family not in valid_families:
                raise ValueError(
                    f"Pattern {pattern_id} has invalid family '{family}', expected one of {valid_families}"
                )

            # Compile regex pattern
            try:
                compiled_pattern = re.compile(pattern_str, re.IGNORECASE | re.DOTALL)
            except re.error as e:
                raise ValueError(f"Pattern {pattern_id} has invalid regex: {e}") from e

            # Add to patterns_by_family
            if family not in patterns_by_family:
                patterns_by_family[family] = []

            patterns_by_family[family].append(
                {
                    "id": pattern_id,
                    "compiled_pattern": compiled_pattern,
                    "family": family,
                    "severity": severity,
                    "description": description,
                }
            )

        if not patterns_by_family:
            raise ValueError("Pattern file is empty")

        return patterns_by_family

    def _check_static(self, payload: Payload, ctx: SessionContext) -> tuple[Verdict, str | None, float]:
        """Check payload against static patterns (static layer).

        Returns:
            Tuple of (verdict, family_tag or None, confidence).
            Verdict is block, advisory, or pass.
        """
        try:
            if not payload.text:
                return Verdict.pass_verdict(), None, 0.0

            # Test against each family
            for family, family_patterns in self.patterns.items():
                for pattern_dict in family_patterns:
                    compiled_pattern = pattern_dict["compiled_pattern"]
                    assert isinstance(compiled_pattern, re.Pattern)
                    match = compiled_pattern.search(payload.text)
                    if match:
                        pattern_id = pattern_dict["id"]
                        severity = cast(
                            Literal["low", "medium", "high", "critical"],
                            pattern_dict["severity"],
                        )
                        description = pattern_dict["description"]
                        signal_id = f"{self.id}:{pattern_id}"

                        # High-severity (high, critical) patterns block immediately
                        # Medium-severity patterns return advisory (soft signal)
                        if severity in ("high", "critical"):
                            return (
                                Verdict.block_verdict(
                                    signal_id=signal_id,
                                    message="Input blocked by armor.",
                                    severity=severity,
                                    details={
                                        "pattern_id": pattern_id,
                                        "family": family,
                                        "description": description,
                                        "matched_offset": match.start(),
                                        "matched_length": match.end() - match.start(),
                                    },
                                ),
                                family,
                                1.0,
                            )
                        else:  # medium or low severity
                            return (
                                Verdict.advisory_verdict(
                                    signal_id=signal_id,
                                    severity=severity,
                                    details={
                                        "pattern_id": pattern_id,
                                        "family": family,
                                        "description": description,
                                        "matched_offset": match.start(),
                                        "matched_length": match.end() - match.start(),
                                    },
                                ),
                                family,
                                0.5,  # soft signal confidence
                            )

            return Verdict.pass_verdict(), None, 0.0

        except Exception as e:
            logger.error(f"Static layer error: {e}", exc_info=True)
            return (
                Verdict.error_verdict(
                    reason=f"Static layer error: {e!s}",
                    details={"detector_id": self.id, "error": str(e)},
                ),
                None,
                0.0,
            )

    def _escalate_with_llm(
        self, payload: Payload, ctx: SessionContext, static_family: str, static_signal_id: str
    ) -> Verdict:
        """Escalate an advisory verdict with LLM validation (hybrid layer).

        Args:
            payload: The original payload
            ctx: Session context
            static_family: The family tag from static layer
            static_signal_id: The signal_id from static layer

        Returns:
            Block verdict if LLM confidence >= threshold, otherwise advisory unchanged.
        """
        try:
            if not self._llm_session:
                # LLM not available; return advisory unchanged
                return Verdict.advisory_verdict(
                    signal_id=static_signal_id,
                    severity="medium",
                    details={
                        "family": static_family,
                        "llm_available": False,
                    },
                )

            # Call validator LLM
            llm_verdict = validate(payload.text, ctx, llm_session=self._llm_session)

            # Extract LLM confidence
            llm_confidence = llm_verdict.details.get("confidence", 0.0) if llm_verdict.details else 0.0
            if not isinstance(llm_confidence, (int, float)):
                llm_confidence = 0.0

            # Extract the validator's actual verdict (safe or risky)
            # The signal_id format is "llm.validator:<verdict_str>" and details["validator_response"] has the verdict
            llm_actual_verdict = (
                llm_verdict.details.get("validator_response", "safe") if llm_verdict.details else "safe"
            )

            # Check if LLM verdict is risky with high confidence
            if llm_actual_verdict == "risky" and llm_confidence >= self.LLM_ESCALATION_THRESHOLD:
                # Escalate to block
                composite_signal = f"{static_signal_id} (llm:{llm_confidence:.2f})"
                return Verdict.block_verdict(
                    signal_id=composite_signal,
                    message="Input blocked by armor.",
                    severity="high",
                    details={
                        "family": static_family,
                        "llm_confidence": llm_confidence,
                        "llm_verdict": llm_actual_verdict,
                        "escalation_reason": f"LLM risky verdict with confidence {llm_confidence:.2f}",
                    },
                )

            # LLM returned safe or low confidence risky; return advisory unchanged
            return Verdict.advisory_verdict(
                signal_id=static_signal_id,
                severity="medium",
                details={
                    "family": static_family,
                    "llm_confidence": llm_confidence,
                    "llm_verdict": llm_actual_verdict,
                    "llm_available": True,
                },
            )

        except Exception as e:
            logger.error(f"LLM escalation error: {e}", exc_info=True)
            # On LLM error, return the advisory unchanged
            return Verdict.advisory_verdict(
                signal_id=static_signal_id,
                severity="medium",
                details={
                    "family": static_family,
                    "llm_error": str(e),
                },
            )

    def check(self, payload: Payload, ctx: SessionContext) -> Verdict:
        """Check payload for jailbreak patterns (static + optional LLM hybrid).

        Args:
            payload: The payload being checked.
            ctx: Session context.

        Returns:
            Block if high-confidence pattern matched, or advisory escalated to block by LLM.
            Advisory if soft-signal pattern matched and LLM unavailable or unconfident.
            Pass if no patterns matched.
        """
        try:
            # Static layer
            static_verdict, family_tag, _static_confidence = self._check_static(payload, ctx)

            # If static layer returns block or pass, return immediately
            if static_verdict.decision in ("block", "pass"):
                return static_verdict

            # Static layer returned advisory; try LLM escalation
            if static_verdict.decision == "advisory" and family_tag:
                static_signal_id = static_verdict.signal_id or f"{self.id}:unknown"
                return self._escalate_with_llm(payload, ctx, family_tag, static_signal_id)

            return static_verdict

        except Exception as e:
            logger.error(f"Detector error: {e}", exc_info=True)
            return Verdict.error_verdict(
                reason=f"Detector error: {e!s}",
                details={"detector_id": self.id, "error": str(e)},
            )
