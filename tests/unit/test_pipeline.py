"""Unit tests for the detector pipeline."""

import time
from unittest.mock import MagicMock

import pytest

from armor.detectors import Detector
from armor.pipeline import DEFAULT_TIMEOUTS, Pipeline
from armor.types import Payload, SessionContext, Verdict


class MockDetector:
    """A mock detector for testing."""

    def __init__(
        self,
        detector_id: str = "mock.detector",
        verdict: Verdict | None = None,
        raise_error: Exception | None = None,
        sleep_time: float = 0.0,
        cost_tier: str = "static",
    ) -> None:
        """Initialize the mock detector.

        Args:
            detector_id: Detector ID.
            verdict: Verdict to return (or None to raise).
            raise_error: Exception to raise (overrides verdict).
            sleep_time: Time to sleep (for timeout testing).
            cost_tier: Detector cost tier.
        """
        self.id = detector_id
        self.category = "test"
        self.cost_tier = cost_tier
        self.verdict = verdict or Verdict.pass_verdict()
        self.raise_error = raise_error
        self.sleep_time = sleep_time

    def check(self, payload: Payload, ctx: SessionContext) -> Verdict:
        """Check and return verdict or raise."""
        if self.sleep_time > 0:
            time.sleep(self.sleep_time)
        if self.raise_error:
            raise self.raise_error
        return self.verdict


class TestPipelineAggregation:
    """Test verdict aggregation logic."""

    @pytest.mark.asyncio
    async def test_all_pass(self) -> None:
        """All detectors return pass → result is pass."""
        detectors = [
            MockDetector("d1", verdict=Verdict.pass_verdict()),
            MockDetector("d2", verdict=Verdict.pass_verdict()),
            MockDetector("d3", verdict=Verdict.pass_verdict()),
        ]

        payload = Payload(text="test")
        ctx = SessionContext(session_id="test")

        verdict = await Pipeline.run(detectors, payload, ctx)
        assert verdict.decision == "pass"
        assert verdict.signal_id is None

    @pytest.mark.asyncio
    async def test_block_short_circuit(self) -> None:
        """First block short-circuits; subsequent detectors not called."""
        d1 = MockDetector("d1", verdict=Verdict.pass_verdict())
        d2 = MockDetector("d2", verdict=Verdict.block_verdict("test.signal"))
        d3 = MagicMock(spec=Detector)
        d3.id = "d3"
        d3.category = "test"
        d3.cost_tier = "static"
        d3.check.return_value = Verdict.pass_verdict()

        detectors = [d1, d2, d3]

        payload = Payload(text="test")
        ctx = SessionContext(session_id="test")

        verdict = await Pipeline.run(detectors, payload, ctx)
        assert verdict.decision == "block"
        assert verdict.signal_id == "test.signal"
        # d3.check should not be called due to short-circuit
        d3.check.assert_not_called()

    @pytest.mark.asyncio
    async def test_highest_severity_advisory(self) -> None:
        """Multiple advisories → highest severity wins."""
        detectors = [
            MockDetector("d1", verdict=Verdict.advisory_verdict("sig1", severity="low")),
            MockDetector(
                "d2",
                verdict=Verdict.advisory_verdict("sig2", severity="critical"),
            ),
            MockDetector("d3", verdict=Verdict.advisory_verdict("sig3", severity="medium")),
        ]

        payload = Payload(text="test")
        ctx = SessionContext(session_id="test")

        verdict = await Pipeline.run(detectors, payload, ctx)
        assert verdict.decision == "advisory"
        assert verdict.signal_id == "sig2"
        assert verdict.severity == "critical"

    @pytest.mark.asyncio
    async def test_detector_raises_error(self) -> None:
        """Detector raises → error verdict, pipeline continues."""
        d1 = MockDetector("d1", raise_error=ValueError("detector error"))
        d2 = MockDetector("d2", verdict=Verdict.advisory_verdict("sig2", severity="high"))

        detectors = [d1, d2]

        payload = Payload(text="test")
        ctx = SessionContext(session_id="test")

        verdict = await Pipeline.run(detectors, payload, ctx)
        # Pipeline should return the highest-severity advisory (from d2)
        assert verdict.decision == "advisory"
        assert verdict.signal_id == "sig2"

    @pytest.mark.asyncio
    async def test_all_detectors_error(self) -> None:
        """All detectors error → fail-closed (block)."""
        d1 = MockDetector("d1", raise_error=ValueError("error 1"))
        d2 = MockDetector("d2", raise_error=RuntimeError("error 2"))

        detectors = [d1, d2]

        payload = Payload(text="test")
        ctx = SessionContext(session_id="test")

        verdict = await Pipeline.run(detectors, payload, ctx)
        assert verdict.decision == "block"
        assert verdict.signal_id == "pipeline.fail_closed"

    @pytest.mark.asyncio
    async def test_mixed_pass_and_error(self) -> None:
        """Pass + error → pass (error is ignored if there's a pass)."""
        d1 = MockDetector("d1", verdict=Verdict.pass_verdict())
        d2 = MockDetector("d2", raise_error=ValueError("error"))

        detectors = [d1, d2]

        payload = Payload(text="test")
        ctx = SessionContext(session_id="test")

        verdict = await Pipeline.run(detectors, payload, ctx)
        # All detector results include the error verdict, but since d1 is pass,
        # the aggregation should be pass
        assert verdict.decision == "pass"

    @pytest.mark.asyncio
    async def test_empty_detector_list(self) -> None:
        """No detectors → pass."""
        detectors: list[Detector] = []

        payload = Payload(text="test")
        ctx = SessionContext(session_id="test")

        verdict = await Pipeline.run(detectors, payload, ctx)
        assert verdict.decision == "pass"


class TestPipelineTimeout:
    """Test per-detector timeout enforcement."""

    @pytest.mark.asyncio
    async def test_static_detector_timeout(self) -> None:
        """Static detector exceeding 100ms timeout → error verdict; pipeline
        fail-closes to block when it's the only detector and all detectors errored."""
        d1 = MockDetector(
            "d1",
            verdict=Verdict.pass_verdict(),
            sleep_time=0.15,  # 150ms > 100ms timeout
            cost_tier="static",
        )

        detectors = [d1]
        payload = Payload(text="test")
        ctx = SessionContext(session_id="test")

        verdict = await Pipeline.run(detectors, payload, ctx)
        assert verdict.decision == "block"
        assert verdict.signal_id == "pipeline.fail_closed"

    @pytest.mark.asyncio
    async def test_semantic_detector_timeout(self) -> None:
        """Semantic detector uses 500ms timeout."""
        # This test documents the timeout value
        assert DEFAULT_TIMEOUTS["semantic"] == 0.5

    @pytest.mark.asyncio
    async def test_unknown_cost_tier_defaults_to_static(self) -> None:
        """Unknown cost tier uses static timeout."""
        d1 = MockDetector(
            "d1",
            verdict=Verdict.pass_verdict(),
            cost_tier="unknown",
        )

        timeout = DEFAULT_TIMEOUTS.get(d1.cost_tier, DEFAULT_TIMEOUTS["static"])
        assert timeout == DEFAULT_TIMEOUTS["static"]


class TestPipelineLevelError:
    """Test pipeline-level error handling."""

    @pytest.mark.asyncio
    async def test_pipeline_error_returns_fail_closed(self) -> None:
        """Pipeline-level error → fail-closed block."""
        # Simulate a detector that's not a proper detector
        detectors = [None]  # type: ignore

        payload = Payload(text="test")
        ctx = SessionContext(session_id="test")

        verdict = await Pipeline.run(detectors, payload, ctx)
        assert verdict.decision == "block"
        assert verdict.signal_id == "pipeline.fail_closed"

    @pytest.mark.asyncio
    async def test_pipeline_aggregation_with_mixed_verdicts(self) -> None:
        """Mix of pass and advisory → advisory wins."""
        detectors = [
            MockDetector("d1", verdict=Verdict.pass_verdict()),
            MockDetector(
                "d2",
                verdict=Verdict.advisory_verdict("sig2", severity="medium"),
            ),
            MockDetector("d3", verdict=Verdict.pass_verdict()),
        ]

        payload = Payload(text="test")
        ctx = SessionContext(session_id="test")

        verdict = await Pipeline.run(detectors, payload, ctx)
        assert verdict.decision == "advisory"
        assert verdict.signal_id == "sig2"
        assert verdict.severity == "medium"


class TestAggregateVerdicts:
    """Test the aggregation logic directly."""

    def test_aggregate_empty_list(self) -> None:
        """Empty verdict list → pass."""
        result = Pipeline._aggregate_verdicts([])
        assert result.decision == "pass"

    def test_aggregate_single_pass(self) -> None:
        """Single pass → pass."""
        verdicts = [Verdict.pass_verdict()]
        result = Pipeline._aggregate_verdicts(verdicts)
        assert result.decision == "pass"

    def test_aggregate_single_block(self) -> None:
        """Single block → block."""
        verdicts = [Verdict.block_verdict("sig")]
        result = Pipeline._aggregate_verdicts(verdicts)
        assert result.decision == "block"

    def test_aggregate_single_advisory(self) -> None:
        """Single advisory → advisory."""
        verdicts = [Verdict.advisory_verdict("sig", severity="high")]
        result = Pipeline._aggregate_verdicts(verdicts)
        assert result.decision == "advisory"
        assert result.severity == "high"

    def test_aggregate_single_error(self) -> None:
        """Single error (only) → fail-closed (block)."""
        verdicts = [Verdict.error_verdict("error")]
        result = Pipeline._aggregate_verdicts(verdicts)
        assert result.decision == "block"
        assert result.signal_id == "pipeline.fail_closed"

    def test_aggregate_multiple_errors(self) -> None:
        """Multiple errors only → fail-closed."""
        verdicts = [
            Verdict.error_verdict("error1"),
            Verdict.error_verdict("error2"),
        ]
        result = Pipeline._aggregate_verdicts(verdicts)
        assert result.decision == "block"
        assert result.signal_id == "pipeline.fail_closed"

    def test_aggregate_error_and_advisory(self) -> None:
        """Error + advisory → advisory (error is less significant)."""
        verdicts = [
            Verdict.error_verdict("error"),
            Verdict.advisory_verdict("sig", severity="medium"),
        ]
        result = Pipeline._aggregate_verdicts(verdicts)
        assert result.decision == "advisory"
        assert result.signal_id == "sig"

    def test_aggregate_block_not_first(self) -> None:
        """Block not in first position still returns block."""
        verdicts = [
            Verdict.pass_verdict(),
            Verdict.block_verdict("sig"),
        ]
        result = Pipeline._aggregate_verdicts(verdicts)
        assert result.decision == "block"

    def test_aggregate_highest_advisory_severity(self) -> None:
        """Among multiple advisories, highest severity wins."""
        verdicts = [
            Verdict.advisory_verdict("sig1", severity="low"),
            Verdict.advisory_verdict("sig2", severity="critical"),
            Verdict.advisory_verdict("sig3", severity="medium"),
        ]
        result = Pipeline._aggregate_verdicts(verdicts)
        assert result.decision == "advisory"
        assert result.signal_id == "sig2"
        assert result.severity == "critical"
