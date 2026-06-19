# SPDX-License-Identifier: Apache-2.0
"""Unit tests for source multiplier application (per ADR-041, task 065)."""

from unittest.mock import MagicMock

import pytest

from armor.pipeline import Pipeline
from armor.types import Payload, SessionContext, Source, Verdict


class TestSourceMultiplierDefaults:
    """Test source multiplier defaults."""

    def test_default_multipliers_exist(self) -> None:
        """Test that default multipliers are configured."""
        from armor.pipeline import DEFAULT_SOURCE_MULTIPLIERS

        assert DEFAULT_SOURCE_MULTIPLIERS[Source.USER_INPUT] == 1.0
        assert DEFAULT_SOURCE_MULTIPLIERS[Source.MODEL_OUTPUT] == 1.0
        assert DEFAULT_SOURCE_MULTIPLIERS[Source.TOOL_PARAMS] == 1.0
        assert DEFAULT_SOURCE_MULTIPLIERS[Source.TOOL_RESULT_TRUSTED] == 0.5
        assert DEFAULT_SOURCE_MULTIPLIERS[Source.TOOL_RESULT_UNTRUSTED] == 1.5


class TestSourceMultiplierApplication:
    """Test _apply_source_multiplier method."""

    def test_no_multiplier_for_user_input(self) -> None:
        """Test that USER_INPUT has 1.0 multiplier (no change)."""
        verdict = Verdict.advisory_verdict(
            signal_id="test.signal",
            message="Test",
            severity="medium",
            details={"confidence": 0.6},
        )
        payload = Payload(text="test", source=Source.USER_INPUT)
        result = Pipeline._apply_source_multiplier(verdict, payload.source)

        # Confidence should remain unchanged
        assert result.details["confidence"] == 0.6
        assert result.decision == "advisory"

    def test_multiply_by_1_5_on_untrusted(self) -> None:
        """Test that TOOL_RESULT_UNTRUSTED has 1.5 multiplier."""
        verdict = Verdict.advisory_verdict(
            signal_id="test.signal",
            message="Test",
            severity="medium",
            details={"confidence": 0.6},
        )
        payload = Payload(text="test", source=Source.TOOL_RESULT_UNTRUSTED)
        result = Pipeline._apply_source_multiplier(verdict, payload.source)

        # Confidence should be multiplied by 1.5
        assert abs(result.details["confidence"] - 0.9) < 1e-9
        assert result.details["source_multiplier"] == 1.5
        # Still advisory (0.9 < 1.0 block threshold)
        assert result.decision == "advisory"

    def test_multiply_by_0_5_on_trusted(self) -> None:
        """Test that TOOL_RESULT_TRUSTED has 0.5 multiplier."""
        verdict = Verdict.advisory_verdict(
            signal_id="test.signal",
            message="Test",
            severity="medium",
            details={"confidence": 0.6},
        )
        payload = Payload(text="test", source=Source.TOOL_RESULT_TRUSTED)
        result = Pipeline._apply_source_multiplier(verdict, payload.source)

        # Confidence should be multiplied by 0.5
        assert abs(result.details["confidence"] - 0.3) < 1e-9
        assert result.details["source_multiplier"] == 0.5
        # Demoted to pass (0.3 < 0.4 advisory threshold)
        assert result.decision == "pass"

    def test_untrusted_crosses_block_threshold(self) -> None:
        """Test that 1.5x multiplier can promote advisory to block.

        Per TC-065-06: raw 0.7 x 1.5 = 1.05 (crosses to block).
        """
        verdict = Verdict.advisory_verdict(
            signal_id="test.signal",
            message="Test injection detected",
            severity="high",
            details={"confidence": 0.7},
        )
        payload = Payload(text="test", source=Source.TOOL_RESULT_UNTRUSTED)
        result = Pipeline._apply_source_multiplier(verdict, payload.source)

        # Confidence should be multiplied by 1.5
        assert abs(result.details["confidence"] - 1.05) < 1e-9
        # Should be promoted to block (1.05 >= 1.0 block threshold)
        assert result.decision == "block"
        assert result.signal_id == "test.signal"

    def test_pass_verdict_unmodified(self) -> None:
        """Test that pass verdicts are not modified."""
        verdict = Verdict.pass_verdict(message="Test passed")
        payload = Payload(text="test", source=Source.TOOL_RESULT_UNTRUSTED)
        result = Pipeline._apply_source_multiplier(verdict, payload.source)

        # Pass verdicts should return as-is
        assert result.decision == "pass"
        assert result == verdict

    def test_error_verdict_unmodified(self) -> None:
        """Test that error verdicts are not modified."""
        verdict = Verdict.error_verdict(reason="Test error")
        payload = Payload(text="test", source=Source.TOOL_RESULT_UNTRUSTED)
        result = Pipeline._apply_source_multiplier(verdict, payload.source)

        # Error verdicts should return as-is
        assert result.decision == "error"
        assert result == verdict

    def test_no_confidence_in_details(self) -> None:
        """Test that verdicts without confidence are passed through."""
        verdict = Verdict.advisory_verdict(
            signal_id="test.signal",
            message="Test",
            severity="medium",
            details={"some_other_field": "value"},
        )
        payload = Payload(text="test", source=Source.TOOL_RESULT_UNTRUSTED)
        result = Pipeline._apply_source_multiplier(verdict, payload.source)

        # Should return as-is
        assert result == verdict

    def test_invalid_confidence_type(self) -> None:
        """Test that non-numeric confidence is ignored."""
        verdict = Verdict.advisory_verdict(
            signal_id="test.signal",
            message="Test",
            severity="medium",
            details={"confidence": "not a number"},
        )
        payload = Payload(text="test", source=Source.TOOL_RESULT_UNTRUSTED)
        result = Pipeline._apply_source_multiplier(verdict, payload.source)

        # Should return as-is
        assert result == verdict


class TestSourceMultiplierConfiguration:
    """Test Pipeline.set_source_multipliers configuration loading."""

    def test_set_source_multipliers(self) -> None:
        """Test setting custom multipliers."""
        custom = {
            "user_input": 1.0,
            "tool_result_untrusted": 2.0,  # Override to 2.0
        }
        Pipeline.set_source_multipliers(custom)

        verdict = Verdict.advisory_verdict(
            signal_id="test.signal",
            message="Test",
            severity="medium",
            details={"confidence": 0.6},
        )
        payload = Payload(text="test", source=Source.TOOL_RESULT_UNTRUSTED)
        result = Pipeline._apply_source_multiplier(verdict, payload.source)

        # Confidence should be multiplied by 2.0
        assert abs(result.details["confidence"] - 1.2) < 1e-9
        assert result.decision == "block"  # 1.2 >= 1.0

    def test_unknown_source_in_multipliers_ignored(self) -> None:
        """Test that unknown sources in config are warned and ignored."""
        custom = {
            "unknown_source": 2.0,
            "user_input": 1.0,
        }
        Pipeline.set_source_multipliers(custom)

        # Should not crash, just ignore unknown source
        verdict = Verdict.advisory_verdict(
            signal_id="test.signal",
            message="Test",
            severity="medium",
            details={"confidence": 0.6},
        )
        payload = Payload(text="test", source=Source.USER_INPUT)
        result = Pipeline._apply_source_multiplier(verdict, payload.source)

        # Should use the 1.0 multiplier for user_input
        assert result.details["confidence"] == 0.6


class TestSourceMultiplierIntegration:
    """Integration tests for multipliers in the pipeline."""

    @pytest.mark.asyncio
    async def test_pipeline_applies_multipliers_to_verdicts(self) -> None:
        """Test that the pipeline applies multipliers to detector verdicts."""
        # Create a mock detector that returns advisory with confidence
        detector = MagicMock()
        detector.id = "test.detector"
        detector.cost_tier = "static"
        detector.check.return_value = Verdict.advisory_verdict(
            signal_id="test.signal",
            message="Test",
            severity="medium",
            details={"confidence": 0.7},
        )

        payload = Payload(text="test", source=Source.TOOL_RESULT_UNTRUSTED)
        ctx = SessionContext(session_id="test-session")

        # Set multipliers
        Pipeline.set_source_multipliers(
            {
                "user_input": 1.0,
                "tool_result_untrusted": 1.5,
            }
        )

        verdict = await Pipeline.run([detector], payload, ctx)

        # The advisory should be promoted to block due to the multiplier
        assert verdict.decision == "block"
        assert abs(verdict.details["confidence"] - 1.05) < 1e-9

    @pytest.mark.asyncio
    async def test_pipeline_block_short_circuits_after_multiplier(self) -> None:
        """Test that block verdicts short-circuit the pipeline after multiplier is applied."""
        detector = MagicMock()
        detector.id = "test.detector"
        detector.cost_tier = "static"
        detector.check.return_value = Verdict.block_verdict(
            signal_id="test.block",
            message="Injection detected",
            details={"confidence": 0.8},
        )

        payload = Payload(text="test", source=Source.TOOL_RESULT_UNTRUSTED)
        ctx = SessionContext(session_id="test-session")

        verdict = await Pipeline.run([detector], payload, ctx)

        # Should be block
        assert verdict.decision == "block"
        assert verdict.signal_id == "test.block"
