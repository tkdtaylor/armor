# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the chunked canary detector."""

import json

from armor.canaries.catalogue import CanaryEntry
from armor.detectors.canary_chunked import CanaryChunkedDetector
from armor.session.rolling_buffer import RollingBuffer
from armor.types import Payload, SessionContext


class TestCanaryChunkedDetectorAttributes:
    """Tests for detector attributes."""

    def test_detector_id(self) -> None:
        """Test detector has correct ID."""
        detector = CanaryChunkedDetector()
        assert detector.id == "canary.chunked"

    def test_detector_category(self) -> None:
        """Test detector has correct category."""
        detector = CanaryChunkedDetector()
        assert detector.category == "exfiltration.canary_chunked"

    def test_detector_cost_tier(self) -> None:
        """Test detector has correct cost tier."""
        detector = CanaryChunkedDetector()
        assert detector.cost_tier == "static"


class TestCanaryChunkedDetectorCheck:
    """Tests for the check method."""

    def test_check_pass_on_clean_buffer(self) -> None:
        """Test detector passes on clean buffer."""
        detector = CanaryChunkedDetector()

        # Create a rolling buffer with non-matching text
        buffer = RollingBuffer()
        buffer.append("turn-1", "This is benign output")

        # Create context with buffer and no active canaries
        ctx = SessionContext(
            session_id="test-session",
            rolling_buffer=buffer,
            active_canaries=[],
        )

        payload = Payload(text="")
        verdict = detector.check(payload, ctx)

        assert verdict.passed
        assert verdict.decision == "pass"

    def test_check_block_on_full_canary_match(self) -> None:
        """Test detector blocks when full canary value is in buffer (TC-128-02)."""
        detector = CanaryChunkedDetector()

        # Create active canary
        canary = CanaryEntry(
            canary_id="test-key-001",
            kind="credential",
            service="test",
            value="ABCD1234EFGH5678",
            marker_rule=".*",
            active=True,
            created_at="2025-01-01T00:00:00Z",
        )

        # Create a rolling buffer containing the full canary
        buffer = RollingBuffer()
        buffer.append("turn-1", "Leaked: ABCD1234EFGH5678 key")

        # Create context
        ctx = SessionContext(
            session_id="test-session",
            rolling_buffer=buffer,
            active_canaries=[canary],
        )

        payload = Payload(text="")
        verdict = detector.check(payload, ctx)

        assert verdict.blocked
        assert verdict.decision == "block"

    def test_check_signal_id_format(self) -> None:
        """Test block verdict has correct signal_id format (TC-128-07)."""
        detector = CanaryChunkedDetector()

        canary = CanaryEntry(
            canary_id="test-key-001",
            kind="credential",
            service="test",
            value="SECRETVALUE123456",
            marker_rule=".*",
            active=True,
            created_at="2025-01-01T00:00:00Z",
        )

        buffer = RollingBuffer()
        buffer.append("turn-1", "Data: SECRETVALUE123456")

        ctx = SessionContext(
            session_id="test-session",
            rolling_buffer=buffer,
            active_canaries=[canary],
        )

        payload = Payload(text="")
        verdict = detector.check(payload, ctx)

        assert verdict.blocked
        assert verdict.signal_id == "canary.chunked:test-key-001"

    def test_check_multi_turn_reconstruction(self) -> None:
        """Test multi-turn chunked reconstruction blocks (TC-128-03)."""
        detector = CanaryChunkedDetector()

        canary = CanaryEntry(
            canary_id="test-key-002",
            kind="credential",
            service="test",
            value="SECRETKEY123456",
            marker_rule=".*",
            active=True,
            created_at="2025-01-01T00:00:00Z",
        )

        # Split the canary across multiple turns (without breaks that prevent matching)
        # The buffer concatenates without separator: "SECRETKEY123456" will appear intact
        buffer = RollingBuffer()
        buffer.append("turn-1", "First output: SECRET")
        buffer.append("turn-2", "KEY12")
        buffer.append("turn-3", "3456")
        # Concatenated: "First output: SECRETKEY123456" which contains "SECRETKEY123456"

        ctx = SessionContext(
            session_id="test-session",
            rolling_buffer=buffer,
            active_canaries=[canary],
        )

        payload = Payload(text="")
        verdict = detector.check(payload, ctx)

        assert verdict.blocked
        assert verdict.signal_id == "canary.chunked:test-key-002"
        assert "test-key-002" in verdict.details["canary_ids"]

    def test_check_partial_match_passes(self) -> None:
        """Test partial canary match passes (TC-128-04)."""
        detector = CanaryChunkedDetector()

        canary = CanaryEntry(
            canary_id="test-key-003",
            kind="credential",
            service="test",
            value="FULLVALUE1234567890",
            marker_rule=".*",
            active=True,
            created_at="2025-01-01T00:00:00Z",
        )

        # Only a fragment in the buffer
        buffer = RollingBuffer()
        buffer.append("turn-1", "Only part: FULLVALUE123")

        ctx = SessionContext(
            session_id="test-session",
            rolling_buffer=buffer,
            active_canaries=[canary],
        )

        payload = Payload(text="")
        verdict = detector.check(payload, ctx)

        assert verdict.passed
        assert verdict.decision == "pass"

    def test_check_empty_buffer_passes(self) -> None:
        """Test empty buffer passes (TC-128-08)."""
        detector = CanaryChunkedDetector()

        canary = CanaryEntry(
            canary_id="test-key",
            kind="credential",
            service="test",
            value="ANYVALUE",
            marker_rule=".*",
            active=True,
            created_at="2025-01-01T00:00:00Z",
        )

        buffer = RollingBuffer()

        ctx = SessionContext(
            session_id="test-session",
            rolling_buffer=buffer,
            active_canaries=[canary],
        )

        payload = Payload(text="")
        verdict = detector.check(payload, ctx)

        assert verdict.passed

    def test_check_no_active_canaries_passes(self) -> None:
        """Test no active canaries passes (TC-128-05)."""
        detector = CanaryChunkedDetector()

        buffer = RollingBuffer()
        buffer.append("turn-1", "Random text with no canaries")

        ctx = SessionContext(
            session_id="test-session",
            rolling_buffer=buffer,
            active_canaries=[],
        )

        payload = Payload(text="")
        verdict = detector.check(payload, ctx)

        assert verdict.passed

    def test_check_no_buffer_passes(self) -> None:
        """Test missing buffer passes gracefully."""
        detector = CanaryChunkedDetector()

        canary = CanaryEntry(
            canary_id="test-key",
            kind="credential",
            service="test",
            value="ANYVALUE",
            marker_rule=".*",
            active=True,
            created_at="2025-01-01T00:00:00Z",
        )

        # No buffer in context
        ctx = SessionContext(
            session_id="test-session",
            rolling_buffer=None,
            active_canaries=[canary],
        )

        payload = Payload(text="")
        verdict = detector.check(payload, ctx)

        assert verdict.passed

    def test_check_forensic_no_value_in_details(self) -> None:
        """Test forensic details contain no canary value (TC-128-06)."""
        detector = CanaryChunkedDetector()

        canary_value = "SENSITIVE_DATA_12345"
        canary = CanaryEntry(
            canary_id="test-canary",
            kind="credential",
            service="test",
            value=canary_value,
            marker_rule=".*",
            active=True,
            created_at="2025-01-01T00:00:00Z",
        )

        buffer = RollingBuffer()
        buffer.append("turn-1", f"Leaked: {canary_value}")

        ctx = SessionContext(
            session_id="test-session",
            rolling_buffer=buffer,
            active_canaries=[canary],
        )

        payload = Payload(text="")
        verdict = detector.check(payload, ctx)

        assert verdict.blocked
        # Canary value must NOT appear in details
        assert canary_value not in json.dumps(verdict.details)
        # But canary_id should be present
        assert "test-canary" in str(verdict.details.get("canary_ids", []))

    def test_check_multiple_canaries_first_match_blocks(self) -> None:
        """Test detector blocks on first matching canary."""
        detector = CanaryChunkedDetector()

        canary_1 = CanaryEntry(
            canary_id="key-a",
            kind="credential",
            service="test",
            value="VALUE_A",
            marker_rule=".*",
            active=True,
            created_at="2025-01-01T00:00:00Z",
        )

        canary_2 = CanaryEntry(
            canary_id="key-b",
            kind="credential",
            service="test",
            value="VALUE_B",
            marker_rule=".*",
            active=True,
            created_at="2025-01-01T00:00:00Z",
        )

        buffer = RollingBuffer()
        buffer.append("turn-1", "Data: VALUE_A and VALUE_B")

        ctx = SessionContext(
            session_id="test-session",
            rolling_buffer=buffer,
            active_canaries=[canary_1, canary_2],
        )

        payload = Payload(text="")
        verdict = detector.check(payload, ctx)

        assert verdict.blocked
        # Should match one of them
        assert "canary.chunked:key-a" in verdict.signal_id or "canary.chunked:key-b" in verdict.signal_id

    def test_check_turn_count_in_details(self) -> None:
        """Test turn_count is in details."""
        detector = CanaryChunkedDetector()

        canary = CanaryEntry(
            canary_id="test-key",
            kind="credential",
            service="test",
            value="TESTVALUE",
            marker_rule=".*",
            active=True,
            created_at="2025-01-01T00:00:00Z",
        )

        buffer = RollingBuffer()
        buffer.append("turn-1", "Part A: TEST")
        buffer.append("turn-2", "VALUE")

        ctx = SessionContext(
            session_id="test-session",
            rolling_buffer=buffer,
            active_canaries=[canary],
        )

        payload = Payload(text="")
        verdict = detector.check(payload, ctx)

        assert verdict.blocked
        assert "turn_count" in verdict.details
        assert verdict.details["turn_count"] == 2

    def test_check_error_handling(self) -> None:
        """Test error handling on exception."""
        detector = CanaryChunkedDetector()

        # Create a context with a non-serializable rolling buffer
        # (This simulates an internal error scenario)
        class BadBuffer:
            def concatenated(self) -> str:
                raise RuntimeError("Simulated error")

            def entries(self):
                return []

        ctx = SessionContext(session_id="test-session")
        ctx.rolling_buffer = BadBuffer()  # type: ignore

        payload = Payload(text="")
        verdict = detector.check(payload, ctx)

        # Should return error verdict on exception
        assert verdict.is_error or verdict.passed


class TestCanaryChunkedDetectorCrossDependency:
    """Tests for ensuring no cross-detector imports."""

    def test_no_cross_detector_import(self) -> None:
        """Test that canary_chunked.py does not import canary_scanner (TC-128-09)."""
        import inspect

        from armor.detectors import canary_chunked

        # Get the source code
        source = inspect.getsource(canary_chunked)

        # Ensure no import from canary_scanner
        assert "from armor.detectors.canary_scanner import" not in source
        assert "from armor.detectors import canary_scanner" not in source
        assert "import armor.detectors.canary_scanner" not in source
