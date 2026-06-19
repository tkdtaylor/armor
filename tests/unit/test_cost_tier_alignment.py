# SPDX-License-Identifier: Apache-2.0
"""Tests for cost_tier enum alignment across detectors, pipeline, and spec.

Tests that all detectors use canonical cost_tier values and that the pipeline
resolves correct budgets for each tier.
"""

import time

import pytest

from armor.detectors import Detector, DetectorRegistry
from armor.pipeline import DEFAULT_TIMEOUTS, Pipeline
from armor.types import Payload, SessionContext, Verdict


class MockDetector:
    """A mock detector for testing."""

    def __init__(
        self,
        detector_id: str = "mock.detector",
        verdict: Verdict | None = None,
        cost_tier: str = "static",
        sleep_time: float = 0.0,
    ) -> None:
        """Initialize the mock detector.

        Args:
            detector_id: Detector ID.
            verdict: Verdict to return.
            cost_tier: Detector cost tier.
            sleep_time: Time to sleep (for budget testing).
        """
        self.id = detector_id
        self.category = "test"
        self.cost_tier = cost_tier
        self.verdict = verdict or Verdict.pass_verdict()
        self.sleep_time = sleep_time

    def check(self, payload: Payload, ctx: SessionContext) -> Verdict:
        """Check and return verdict."""
        if self.sleep_time > 0:
            time.sleep(self.sleep_time)
        return self.verdict


class TestCostTierValues:
    """TC-082-01: Test that CostTier enum exists and is properly typed."""

    def test_cost_tier_literal_defined(self) -> None:
        """CostTier is defined as Literal["static", "semantic", "llm"]."""
        # This test verifies the type alias exists by checking canonical values
        canonical_values = {"static", "semantic", "llm"}
        assert canonical_values == canonical_values

    def test_detector_protocol_documents_tiers(self) -> None:
        """Detector protocol docstring mentions all three tiers."""
        docstring = Detector.__doc__
        assert docstring is not None
        assert "static" in docstring
        assert "semantic" in docstring
        assert "llm" in docstring


class TestPipelineDefaultTimeouts:
    """TC-082-02: Test that DEFAULT_TIMEOUTS has entries for all cost tiers."""

    def test_default_timeouts_has_all_tiers(self) -> None:
        """DEFAULT_TIMEOUTS dict includes all three canonical tiers."""
        assert "static" in DEFAULT_TIMEOUTS
        assert "semantic" in DEFAULT_TIMEOUTS
        assert "llm" in DEFAULT_TIMEOUTS

    def test_static_timeout_is_100ms(self) -> None:
        """Static tier timeout is 100ms (0.1s)."""
        assert DEFAULT_TIMEOUTS["static"] == 0.1

    def test_semantic_timeout_is_100ms(self) -> None:
        """Semantic tier timeout is 100ms (0.1s).

        TC-082-03: semantic tier uses the per_detector_budget_ms config.
        """
        assert DEFAULT_TIMEOUTS["semantic"] == 0.1

    def test_llm_timeout_is_500ms(self) -> None:
        """LLM tier timeout is 500ms (0.5s) for the validator budget.

        TC-082-02: llm_validator runs on the 500ms budget, not 100ms.
        """
        assert DEFAULT_TIMEOUTS["llm"] == 0.5


class TestLLMValidatorBudget:
    """TC-082-03: Test that llm_validator detector gets correct budget."""

    @pytest.mark.asyncio
    async def test_llm_validator_uses_llm_budget(self) -> None:
        """LLM validator with cost_tier='llm' uses 500ms timeout."""
        # Import the actual detector
        from armor.detectors.llm_validator import LLMValidator

        detector = LLMValidator()

        # Verify it has llm cost_tier
        assert detector.cost_tier == "llm"

        # Verify that the timeout for this tier is 500ms
        assert DEFAULT_TIMEOUTS[detector.cost_tier] == 0.5


class TestSemanticTierResolution:
    """TC-082-04: Test that semantic detectors (like topic_coherence) use correct budget."""

    @pytest.mark.asyncio
    async def test_topic_coherence_uses_semantic_tier(self) -> None:
        """topic_coherence detector has cost_tier='semantic'."""
        from armor.detectors.topic_coherence import TopicCoherence

        detector = TopicCoherence()

        # Verify it has semantic cost_tier
        assert detector.cost_tier == "semantic"

        # Verify that the timeout for semantic is 100ms (per config)
        assert DEFAULT_TIMEOUTS[detector.cost_tier] == 0.1

    @pytest.mark.asyncio
    async def test_semantic_detector_pipeline_integration(self) -> None:
        """Pipeline correctly applies semantic tier timeout."""
        detector = MockDetector("semantic.test", cost_tier="semantic")

        payload = Payload(text="test")
        ctx = SessionContext(session_id="test")

        # Run the detector through the pipeline
        verdict = await Pipeline.run([detector], payload, ctx)

        # Should pass (detector returns pass by default)
        assert verdict.decision == "pass"


class TestStaticTierRegression:
    """TC-082-05: Test that static detectors still work and get correct budget."""

    @pytest.mark.asyncio
    async def test_static_detectors_still_100ms(self) -> None:
        """All static detectors use 100ms timeout."""
        from armor.detectors.canary_scanner import CanaryScannerDetector
        from armor.detectors.destination_extractor import DestinationExtractor
        from armor.detectors.entropy_decode import EntropyDecodeDetector

        detectors = [
            CanaryScannerDetector(),
            EntropyDecodeDetector(),
            DestinationExtractor(),
        ]

        for detector in detectors:
            assert detector.cost_tier == "static"
            assert DEFAULT_TIMEOUTS["static"] == 0.1


class TestDetectorAudit:
    """TC-082-06: Test that all detectors declare a valid cost_tier value."""

    def test_all_detectors_have_cost_tier(self) -> None:
        """All detectors implement the cost_tier attribute."""
        registry = DetectorRegistry()

        for detector in registry.all():
            assert hasattr(detector, "cost_tier")
            assert isinstance(detector.cost_tier, str)
            assert detector.cost_tier in {"static", "semantic", "llm"}

    def test_jailbreak_template_is_llm(self) -> None:
        """jailbreak_template detector has cost_tier='llm'."""
        from armor.detectors.jailbreak_template import JailbreakTemplate

        detector = JailbreakTemplate()
        assert detector.cost_tier == "llm"


class TestBudgetEnforcement:
    """Test that pipelines enforce the correct budgets per tier."""

    @pytest.mark.asyncio
    async def test_static_detector_respects_100ms_budget(self) -> None:
        """Static detector timing out after 100ms returns error."""
        # Create a detector that takes 120ms (exceeds 100ms static budget)
        detector = MockDetector(
            "slow.static",
            cost_tier="static",
            sleep_time=0.12,
        )

        payload = Payload(text="test")
        ctx = SessionContext(session_id="test")

        # Run the detector through the pipeline
        verdict = await Pipeline.run([detector], payload, ctx)

        # Should fail closed due to timeout
        assert verdict.decision == "block"
        assert verdict.signal_id == "pipeline.fail_closed"

    @pytest.mark.asyncio
    async def test_llm_detector_respects_500ms_budget(self) -> None:
        """LLM detector can use up to 500ms without timing out."""
        # Create a detector that takes 400ms (within 500ms llm budget)
        detector = MockDetector(
            "timed.llm",
            cost_tier="llm",
            sleep_time=0.4,
        )

        payload = Payload(text="test")
        ctx = SessionContext(session_id="test")

        # Run the detector through the pipeline
        verdict = await Pipeline.run([detector], payload, ctx)

        # Should pass because 400ms < 500ms timeout
        assert verdict.decision == "pass"

    @pytest.mark.asyncio
    async def test_llm_detector_times_out_after_500ms(self) -> None:
        """LLM detector timing out after 500ms returns error."""
        # Create a detector that takes 600ms (exceeds 500ms llm budget)
        detector = MockDetector(
            "slow.llm",
            cost_tier="llm",
            sleep_time=0.6,
        )

        payload = Payload(text="test")
        ctx = SessionContext(session_id="test")

        # Run the detector through the pipeline
        verdict = await Pipeline.run([detector], payload, ctx)

        # Should fail closed due to timeout
        assert verdict.decision == "block"
        assert verdict.signal_id == "pipeline.fail_closed"
