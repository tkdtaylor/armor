"""Pipeline runner that aggregates detector verdicts.

The pipeline runs a list of detectors on a payload and composes their verdicts
according to aggregation rules: first block short-circuits, otherwise the
highest-severity advisory propagates. Per-detector timeouts are enforced.

Per ADR-041, applies per-source multipliers to detector confidence to calibrate
strictness based on payload provenance.
"""

import asyncio
import logging
from typing import ClassVar, cast

from armor.detectors import Detector
from armor.types import Payload, SessionContext, Source, Verdict

logger = logging.getLogger(__name__)

# Default timeouts per detector cost tier (seconds)
# - static: pure regex/parsing (≤100ms typical)
# - semantic: local non-LLM ML like ONNX embeddings (≤100ms typical, but budget set higher)
# - llm: local LLM inference (≤500ms validator, ≤16s honeypot)
DEFAULT_TIMEOUTS = {
    "static": 0.1,  # 100ms
    "semantic": 0.1,  # 100ms (per_detector_budget_ms from config)
    "llm": 0.5,  # 500ms (validator_budget_ms from config)
}

# Default source multipliers (per ADR-041 §2)
# These can be overridden via armor.toml pipeline.source_multipliers
DEFAULT_SOURCE_MULTIPLIERS: dict[Source, float] = {
    Source.USER_INPUT: 1.0,
    Source.MODEL_OUTPUT: 1.0,
    Source.TOOL_PARAMS: 1.0,
    Source.TOOL_RESULT_TRUSTED: 0.5,
    Source.TOOL_RESULT_UNTRUSTED: 1.5,
}


class Pipeline:
    """Async pipeline runner that aggregates detector verdicts.

    Pipeline.run is async because per-detector timeouts use ``asyncio.wait_for``
    against the running event loop. Sync callers (tests, scripts) wrap the call
    in ``asyncio.run(Pipeline.run(...))``.

    Per ADR-041, applies per-source multipliers to detector confidence to calibrate
    strictness based on payload provenance (user_input, tool_result_untrusted, etc.).
    """

    # Source multipliers (can be set via set_source_multipliers for config loading)
    _source_multipliers: ClassVar[dict[Source | str, float]] = cast(
        dict[Source | str, float], dict(DEFAULT_SOURCE_MULTIPLIERS)
    )

    @classmethod
    def set_source_multipliers(cls, multipliers: dict[str, float]) -> None:
        """Set per-source multipliers from configuration.

        Args:
            multipliers: Dict mapping source names (str) to multiplier values.
                        E.g., {"user_input": 1.0, "tool_result_untrusted": 1.5}
        """
        cls._source_multipliers = cast(dict[Source | str, float], dict(DEFAULT_SOURCE_MULTIPLIERS))
        for source_name, multiplier in multipliers.items():
            # Map string source names to Source enum
            try:
                source = Source(source_name)
                cls._source_multipliers[source] = float(multiplier)
            except ValueError:
                logger.warning(f"Unknown source in multipliers config: {source_name}")

    @staticmethod
    async def run(
        detectors: list[Detector],
        payload: Payload,
        ctx: SessionContext,
    ) -> Verdict:
        """Run the detector pipeline on a payload.

        Aggregation rules:
        1. If any detector returns block, short-circuit and return block
           (after applying source multiplier).
        2. If all detectors return pass, return pass.
        3. Otherwise, return the highest-severity advisory.
        4. If all detectors error, return fail-closed (block).
        5. Per-detector exceptions are caught and converted to error verdicts.
        6. Per-detector timeouts are enforced via asyncio.wait_for.
        7. Per ADR-041, apply per-source multiplier to detector confidence.

        Args:
            detectors: List of detectors to run.
            payload: The payload being checked.
            ctx: Session context.

        Returns:
            Aggregated Verdict.
        """
        # When source is TOOL_RESULT_TRUSTED (ADR-041), skip indirect-injection regex detectors
        # (trust applies to origin, not content — canary/entropy detectors still run)
        detectors_to_run = detectors
        if payload.source == Source.TOOL_RESULT_TRUSTED:
            indirect_injection_detectors = {
                "regex.instruction_override",
                "regex.roleplay_hijack",
                "regex.system_prompt_extraction",
                "regex.authority_impersonation",
                "regex.encoding_request",
            }
            detectors_to_run = [d for d in detectors if d.id not in indirect_injection_detectors]

        try:
            verdicts: list[Verdict] = []

            for detector in detectors_to_run:
                try:
                    timeout = DEFAULT_TIMEOUTS.get(detector.cost_tier, DEFAULT_TIMEOUTS["static"])
                    verdict = await Pipeline._run_detector_with_timeout(detector, payload, ctx, timeout)
                    # Apply source multiplier to the verdict
                    verdict = Pipeline._apply_source_multiplier(verdict, payload.source)
                    verdicts.append(verdict)

                    if verdict.decision == "block":
                        return verdict

                except Exception as e:
                    logger.error(
                        f"Detector {detector.id} failed: {e}",
                        exc_info=True,
                    )
                    verdicts.append(
                        Verdict.error_verdict(
                            reason=f"Detector {detector.id} error: {e!s}",
                            details={"detector_id": detector.id},
                        )
                    )

            return Pipeline._aggregate_verdicts(verdicts)

        except Exception as e:
            logger.error(f"Pipeline error: {e}", exc_info=True)
            return Verdict.block_verdict(
                signal_id="pipeline.fail_closed",
                message="Pipeline error (fail-closed)",
                severity="critical",
                details={"error": str(e)},
            )

    @staticmethod
    def _apply_source_multiplier(verdict: Verdict, source: Source) -> Verdict:
        """Apply per-source multiplier to detector confidence.

        Per ADR-041, re-evaluates the verdict based on multiplied confidence.
        If raw confidence x multiplier crosses a threshold, the decision may change.

        Args:
            verdict: The raw detector verdict.
            source: The payload source (determines multiplier).

        Returns:
            Verdict with adjusted confidence and possibly changed decision.
        """
        # Get the multiplier for this source
        multiplier = Pipeline._source_multipliers.get(source, 1.0)
        if multiplier == 1.0:
            # No adjustment needed
            return verdict

        # Skip non-confidence verdicts (pass, error, etc.)
        if verdict.decision == "pass" or verdict.decision == "error":
            return verdict

        # Extract confidence from details
        details = dict(verdict.details) if verdict.details else {}
        raw_confidence_obj = details.get("confidence")

        if raw_confidence_obj is None:
            # No confidence to multiply; return as-is
            return verdict

        try:
            raw_confidence = float(cast(float | int | str, raw_confidence_obj))
        except (TypeError, ValueError):
            # Invalid confidence; return as-is
            return verdict

        # Apply multiplier
        adjusted_confidence = raw_confidence * multiplier

        # Update details with multiplied confidence
        details["confidence"] = adjusted_confidence
        details["source_multiplier"] = multiplier

        # Re-evaluate decision based on adjusted confidence
        # Block threshold is 1.0, advisory threshold is lower (0.4 nominal)
        # This is a simplification; in production, thresholds would be configurable
        block_threshold = 1.0
        advisory_threshold = 0.4

        # Only change decision if adjusted confidence crosses a boundary
        if adjusted_confidence >= block_threshold and verdict.decision != "block":
            # Promote advisory to block
            return Verdict.block_verdict(
                signal_id=verdict.signal_id or "source_multiplier.escalation",
                message=verdict.message,
                severity=verdict.severity,
                details=details,
            )
        if adjusted_confidence < advisory_threshold and verdict.decision == "advisory":
            # Demote advisory to pass
            return Verdict.pass_verdict(
                message=verdict.message,
                details=details,
            )

        # Keep original decision but update confidence
        if verdict.decision == "advisory":
            return Verdict.advisory_verdict(
                signal_id=verdict.signal_id or "unknown",
                severity=verdict.severity,
                message=verdict.message,
                details=details,
            )
        # verdict.decision must be "block" here; all other cases returned earlier
        return Verdict.block_verdict(
            signal_id=verdict.signal_id or "unknown",
            message=verdict.message,
            severity=verdict.severity,
            details=details,
        )

    @staticmethod
    async def _run_detector_with_timeout(
        detector: Detector,
        payload: Payload,
        ctx: SessionContext,
        timeout: float,
    ) -> Verdict:
        """Run a (sync) detector in a worker thread with an async timeout.

        ``asyncio.to_thread`` dispatches the sync ``detector.check`` to the
        default executor; ``asyncio.wait_for`` enforces the timeout cooperatively.
        """
        try:
            return await asyncio.wait_for(
                asyncio.to_thread(detector.check, payload, ctx),
                timeout=timeout,
            )
        except TimeoutError:
            return Verdict.error_verdict(
                reason=f"Detector {detector.id} timed out after {timeout}s",
                details={"detector_id": detector.id, "timeout": timeout},
            )

    @staticmethod
    def _aggregate_verdicts(verdicts: list[Verdict]) -> Verdict:
        """Aggregate a list of verdicts into a single verdict.

        Rules:
        1. If all are pass, return pass.
        2. If any is block, return block (should not happen; blocks short-circuit).
        3. If all are error (no pass/advisory), return fail-closed (block).
        4. Otherwise, return the highest-severity advisory.
        5. If there are passes and errors (no advisory), return pass.

        Args:
            verdicts: List of verdicts.

        Returns:
            Aggregated Verdict.
        """
        if not verdicts:
            # No detectors
            return Verdict.pass_verdict()

        # Separate verdicts by decision
        passes = [v for v in verdicts if v.decision == "pass"]
        blocks = [v for v in verdicts if v.decision == "block"]
        advisories = [v for v in verdicts if v.decision == "advisory"]
        errors = [v for v in verdicts if v.decision == "error"]

        # Block short-circuits (should not happen in practice)
        if blocks:
            return blocks[0]

        # If any advisory, return the highest severity
        if advisories:
            advisory_severity_values = {
                "low": 1,
                "medium": 2,
                "high": 3,
                "critical": 4,
            }
            highest_advisory = max(
                advisories,
                key=lambda v: advisory_severity_values.get(v.severity, 0),
            )
            return highest_advisory

        # All errors (no pass, no advisory) → fail-closed
        if errors and not passes:
            return Verdict.block_verdict(
                signal_id="pipeline.fail_closed",
                message="All detectors failed",
                severity="critical",
            )

        # Mix of pass and error → pass
        # Or all pass
        return Verdict.pass_verdict()
