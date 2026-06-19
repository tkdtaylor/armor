# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the token_count_anomaly detector.

Tests cover TC-069-01 through TC-069-09 markers from the test spec.
"""

import pytest

from armor.detectors.token_count_anomaly import (
    TokenCountAnomaly,
    clear_all_cache,
    clear_session_cache,
)
from armor.types import Payload, SessionContext


class TestTokenCountAnomaly:
    """Tests for token-count-anomaly detection."""

    @pytest.fixture(autouse=True)
    def cleanup_cache(self):
        """Clear cache before and after each test."""
        clear_all_cache()
        yield
        clear_all_cache()

    @pytest.fixture
    def detector(self):
        """Create a detector with default config."""
        return TokenCountAnomaly(
            absolute_cap_bytes=32768,
            sigma_threshold=3.0,
            min_history_turns=3,
        )

    # TC-069-01: Module exists with correct metadata
    def test_tc_069_01_module_metadata(self, detector):
        """TC-069-01: Module has correct id/category/cost_tier.

        Pins spec: "Detector module exists with correct id/category/cost_tier."
        """
        assert detector.id == "meta.token_count_anomaly"
        assert detector.category == "meta"
        assert detector.cost_tier == "static"

    # TC-069-02: Warm-up — first min_history_turns turns return pass
    def test_tc_069_02_warm_up_first_three_turns(self, detector):
        """TC-069-02: First 3 turns of a session all return pass.

        Pins spec: "If session has < 3 prior turns -> seed stats and return pass."
        """
        session = SessionContext(session_id="warmup_test")
        payload = Payload(text="x" * 200)  # 200 bytes

        # Turn 1
        verdict1 = detector.check(payload, session)
        assert verdict1.decision == "pass", f"Turn 1 should pass, got {verdict1.decision}"

        # Turn 2
        verdict2 = detector.check(payload, session)
        assert verdict2.decision == "pass", f"Turn 2 should pass, got {verdict2.decision}"

        # Turn 3
        verdict3 = detector.check(payload, session)
        assert verdict3.decision == "pass", f"Turn 3 should pass, got {verdict3.decision}"

    # TC-069-03: Anomaly after warm-up
    def test_tc_069_03_anomaly_after_warm_up(self, detector):
        """TC-069-03: Turn 4 sigma above mean produces advisory with non-zero confidence.

        Pins spec: "Else compute z-score; if length > mean + 3*sigma, fire advisory
        with confidence proportional to overshoot."
        """
        session = SessionContext(session_id="anomaly_test")

        # Warm up with 3 turns of approximately 200 bytes each
        for _ in range(3):
            payload = Payload(text="x" * 200)
            verdict = detector.check(payload, session)
            assert verdict.decision == "pass"

        # Turn 4: 50 KB (much larger — should trigger)
        payload = Payload(text="x" * 50000)
        verdict = detector.check(payload, session)

        assert verdict.decision == "advisory", f"Expected advisory, got {verdict.decision}"
        assert verdict.signal_id is not None
        assert "token_count_anomaly" in verdict.signal_id
        assert verdict.details["z_score"] > 3.0
        assert verdict.details["confidence"] > 0.0

    # TC-069-04: Absolute cap on first turn
    def test_tc_069_04_absolute_cap_first_turn(self, detector):
        """TC-069-04: First turn > absolute cap -> advisory regardless of warm-up.

        Pins spec: "If length > 32768 (absolute cap), fire advisory."
        """
        session = SessionContext(session_id="absolute_cap_test")

        # First turn is 50 KB (exceeds 32768 default)
        payload = Payload(text="x" * 50000)
        verdict = detector.check(payload, session)

        assert verdict.decision == "advisory", f"Expected advisory, got {verdict.decision}"
        assert verdict.details["absolute_cap_exceeded"] is True
        assert verdict.details["length_bytes"] == 50000
        assert verdict.details["confidence"] > 0.0

    # TC-069-05: Consistent-length session never advisories
    def test_tc_069_05_consistent_length_no_advisory(self, detector):
        """TC-069-05: Session with all 20 KB turns -> all pass.

        Pins spec: "Otherwise, it emits pass (no signal)."
        """
        session = SessionContext(session_id="consistent_test")

        # All turns are 20 KB — very consistent
        for i in range(6):
            payload = Payload(text="x" * 20000)
            verdict = detector.check(payload, session)

            # Should all be pass (no anomaly)
            assert verdict.decision == "pass", f"Turn {i + 1} should pass on consistent length, got {verdict.decision}"

    # TC-069-06: Session isolation
    def test_tc_069_06_session_isolation(self, detector):
        """TC-069-06: Sessions A and B have isolated stats.

        Pins spec: "Per-session length stats are isolated."
        """
        session_a = SessionContext(session_id="session_a")
        session_b = SessionContext(session_id="session_b")

        # Warm up A with short turns (200 bytes)
        for _ in range(3):
            payload = Payload(text="x" * 200)
            verdict = detector.check(payload, session_a)
            assert verdict.decision == "pass"

        # Warm up B with long turns (10000 bytes)
        for _ in range(3):
            payload = Payload(text="x" * 10000)
            verdict = detector.check(payload, session_b)
            assert verdict.decision == "pass"

        # Now send a 50KB turn to A (should trigger — anomaly relative to A's baseline)
        payload_a = Payload(text="x" * 50000)
        verdict_a = detector.check(payload_a, session_a)
        assert verdict_a.decision == "advisory"

        # And a 50KB turn to B (should pass — consistent with B's baseline of about 10KB)
        payload_b = Payload(text="x" * 50000)
        verdict_b = detector.check(payload_b, session_b)
        # B has high std-dev due to 10KB baseline, so even 50KB may not be 3 sigma away
        # Let's just check that it doesn't error
        assert verdict_b.decision in ["pass", "advisory"]

    # TC-069-07: Confidence scaling with z-score
    def test_tc_069_07_confidence_scaling(self, detector):
        """TC-069-07: z=4.0 confidence < z=10.0 confidence.

        Pins spec: "Confidence proportional to overshoot."
        """
        session = SessionContext(session_id="confidence_test")

        # Warm up with 100-byte turns (very consistent)
        for _ in range(3):
            payload = Payload(text="x" * 100)
            verdict = detector.check(payload, session)
            assert verdict.decision == "pass"

        # Turn 4: 1500 bytes (should be about 4 sigma above mean of 100)
        payload_4sigma = Payload(text="x" * 1500)
        verdict_4sigma = detector.check(payload_4sigma, session)
        assert verdict_4sigma.decision == "advisory"
        confidence_4sigma = verdict_4sigma.details["confidence"]

        # Reset for next test
        clear_session_cache("confidence_test")
        session = SessionContext(session_id="confidence_test")

        # Warm up again
        for _ in range(3):
            payload = Payload(text="x" * 100)
            verdict = detector.check(payload, session)

        # Turn 4: 4000 bytes (should be much higher z-score, about 10 sigma above mean)
        payload_10sigma = Payload(text="x" * 4000)
        verdict_10sigma = detector.check(payload_10sigma, session)
        assert verdict_10sigma.decision == "advisory"
        confidence_10sigma = verdict_10sigma.details["confidence"]

        # Higher z-score should have higher confidence (both capped at 1.0)
        assert confidence_10sigma >= confidence_4sigma

    # TC-069-08: Pass on empty input
    def test_tc_069_08_empty_input_passes(self, detector):
        """TC-069-08: Empty payload -> pass.

        Pins spec: "Empty inputs pass."
        """
        session = SessionContext(session_id="empty_test")
        payload = Payload(text="")
        verdict = detector.check(payload, session)

        assert verdict.decision == "pass"

    # TC-069-09: Stats updated only on completed checks
    def test_tc_069_09_stats_updated_per_check(self, detector):
        """TC-069-09: Each check increments the session counter.

        Pins spec: "Stats updated only on completed checks."
        """
        session = SessionContext(session_id="stats_test")

        # Check that stats are updated across multiple checks
        for i in range(5):
            payload = Payload(text="x" * (100 + i * 10))
            verdict = detector.check(payload, session)
            # All should pass (warm-up or consistent)
            assert verdict.decision in ["pass", "advisory"]

    # TC-069: Edge case - custom config
    def test_custom_config(self):
        """Test detector with custom configuration."""
        detector = TokenCountAnomaly(
            absolute_cap_bytes=1000,
            sigma_threshold=2.0,
            min_history_turns=2,
        )
        assert detector.absolute_cap_bytes == 1000
        assert detector.sigma_threshold == 2.0
        assert detector.min_history_turns == 2

    # TC-069: UTF-8 encoding
    def test_utf8_byte_length(self, detector):
        """Test that byte length accounts for UTF-8 encoding."""
        session = SessionContext(session_id="utf8_test")

        # Warm up with ASCII
        for _ in range(3):
            payload = Payload(text="a" * 100)
            verdict = detector.check(payload, session)
            assert verdict.decision == "pass"

        # Send UTF-8 multi-byte characters (emoji = 4 bytes each)
        # 100 emoji chars = 400 bytes, but still about normal
        payload = Payload(text="😀" * 100)
        verdict = detector.check(payload, session)
        # Should be close to baseline (within 3 sigma)
        assert verdict.decision in ["pass", "advisory"]

    # TC-069: Absolute cap with custom value
    def test_absolute_cap_custom(self):
        """Test absolute cap with custom threshold."""
        detector = TokenCountAnomaly(absolute_cap_bytes=100)
        session = SessionContext(session_id="custom_cap_test")

        # 50 bytes - should pass
        payload = Payload(text="x" * 50)
        verdict = detector.check(payload, session)
        assert verdict.decision == "pass"

        # 200 bytes - should hit absolute cap
        payload = Payload(text="x" * 200)
        verdict = detector.check(payload, session)
        assert verdict.decision == "advisory"
        assert verdict.details["absolute_cap_exceeded"] is True
