"""Pipeline runner that aggregates detector verdicts.

The pipeline runs a list of detectors on a payload and composes their verdicts
according to aggregation rules: first block short-circuits, otherwise the
highest-severity advisory propagates. Per-detector timeouts are enforced.
"""

import asyncio
import logging

from armor.detectors import Detector
from armor.types import Payload, SessionContext, Verdict

logger = logging.getLogger(__name__)

# Default timeouts per detector cost tier
DEFAULT_TIMEOUTS = {
    "static": 0.1,  # 100ms
    "semantic": 0.5,  # 500ms
}


class Pipeline:
    """Async pipeline runner that aggregates detector verdicts.

    Pipeline.run is async because per-detector timeouts use ``asyncio.wait_for``
    against the running event loop. Sync callers (tests, scripts) wrap the call
    in ``asyncio.run(Pipeline.run(...))``.
    """

    @staticmethod
    async def run(
        detectors: list[Detector],
        payload: Payload,
        ctx: SessionContext,
    ) -> Verdict:
        """Run the detector pipeline on a payload.

        Aggregation rules:
        1. If any detector returns block, short-circuit and return block.
        2. If all detectors return pass, return pass.
        3. Otherwise, return the highest-severity advisory.
        4. If all detectors error, return fail-closed (block).
        5. Per-detector exceptions are caught and converted to error verdicts.
        6. Per-detector timeouts are enforced via asyncio.wait_for.

        Args:
            detectors: List of detectors to run.
            payload: The payload being checked.
            ctx: Session context.

        Returns:
            Aggregated Verdict.
        """
        try:
            verdicts: list[Verdict] = []

            for detector in detectors:
                try:
                    timeout = DEFAULT_TIMEOUTS.get(detector.cost_tier, DEFAULT_TIMEOUTS["static"])
                    verdict = await Pipeline._run_detector_with_timeout(detector, payload, ctx, timeout)
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
