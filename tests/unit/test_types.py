# SPDX-License-Identifier: Apache-2.0
"""Unit tests for core types (Verdict, Payload, SessionContext, etc.)."""

import pytest

from armor.types import (
    Payload,
    SessionContext,
    Severity,
    Signal,
    Verdict,
)


class TestVerdictImmutability:
    """Test that Verdict is frozen (immutable)."""

    def test_verdict_is_frozen(self) -> None:
        """Attempt to mutate a Verdict field should raise."""
        verdict = Verdict.pass_verdict()
        with pytest.raises((AttributeError, TypeError)):
            verdict.decision = "block"  # type: ignore


class TestVerdictEquality:
    """Test that Verdict equality works correctly."""

    def test_identical_verdicts_are_equal(self) -> None:
        """Two Verdicts with identical fields should be equal."""
        v1 = Verdict.pass_verdict(message="test")
        v2 = Verdict.pass_verdict(message="test")
        assert v1 == v2

    def test_different_verdicts_not_equal(self) -> None:
        """Verdicts with different fields should not be equal."""
        v1 = Verdict.pass_verdict()
        v2 = Verdict.block_verdict("test.signal")
        assert v1 != v2

    def test_different_signal_ids_not_equal(self) -> None:
        """Verdicts with different signal IDs should not be equal."""
        v1 = Verdict.block_verdict("signal.1")
        v2 = Verdict.block_verdict("signal.2")
        assert v1 != v2


class TestSeverityOrdering:
    """Test that Severity ordering is correct."""

    def test_severity_ordering(self) -> None:
        """Verify severity ordering: low < medium < high < critical."""
        assert Severity.LOW < Severity.MEDIUM
        assert Severity.MEDIUM < Severity.HIGH
        assert Severity.HIGH < Severity.CRITICAL
        assert Severity.LOW < Severity.CRITICAL

    def test_severity_equality(self) -> None:
        """Verify severity equality."""
        assert Severity.LOW == Severity.LOW
        assert Severity.LOW != Severity.MEDIUM

    def test_severity_le_ge(self) -> None:
        """Verify <= and >= operators."""
        assert Severity.LOW <= Severity.MEDIUM
        assert Severity.LOW <= Severity.LOW
        assert Severity.CRITICAL >= Severity.HIGH
        assert Severity.HIGH >= Severity.HIGH

    def test_severity_gt(self) -> None:
        """Verify > operator."""
        assert Severity.CRITICAL > Severity.HIGH
        assert not (Severity.LOW > Severity.MEDIUM)


class TestVerdictFactories:
    """Test Verdict factory methods."""

    def test_pass_verdict_factory(self) -> None:
        """Test Verdict.pass_verdict()."""
        v = Verdict.pass_verdict()
        assert v.decision == "pass"
        assert v.signal_id is None
        assert v.severity == "low"

    def test_block_verdict_factory(self) -> None:
        """Test Verdict.block_verdict()."""
        v = Verdict.block_verdict("test.signal", message="Blocked", severity="critical")
        assert v.decision == "block"
        assert v.signal_id == "test.signal"
        assert v.severity == "critical"
        assert v.message == "Blocked"

    def test_advisory_verdict_factory(self) -> None:
        """Test Verdict.advisory_verdict()."""
        v = Verdict.advisory_verdict("test.signal", severity="medium", message="Advisory")
        assert v.decision == "advisory"
        assert v.signal_id == "test.signal"
        assert v.severity == "medium"

    def test_error_verdict_factory(self) -> None:
        """Test Verdict.error_verdict()."""
        v = Verdict.error_verdict(reason="Test error")
        assert v.decision == "error"
        assert v.signal_id is None
        assert v.message == "Test error"

    def test_verdict_blocked_property(self) -> None:
        """Test Verdict.blocked property."""
        assert Verdict.block_verdict("sig").blocked is True
        assert Verdict.pass_verdict().blocked is False

    def test_verdict_passed_property(self) -> None:
        """Test Verdict.passed property."""
        assert Verdict.pass_verdict().passed is True
        assert Verdict.block_verdict("sig").passed is False

    def test_verdict_is_error_property(self) -> None:
        """Test Verdict.is_error property."""
        assert Verdict.error_verdict().is_error is True
        assert Verdict.pass_verdict().is_error is False


class TestPayload:
    """Test Payload dataclass."""

    def test_payload_with_text(self) -> None:
        """Test Payload with text."""
        p = Payload(text="test input")
        assert p.text == "test input"
        assert p.tool is None
        assert p.params is None

    def test_payload_with_tool(self) -> None:
        """Test Payload with tool and params."""
        p = Payload(text="", tool="bash", params={"cmd": "ls"})
        assert p.tool == "bash"
        assert p.params == {"cmd": "ls"}

    def test_payload_default_text(self) -> None:
        """Test Payload default text."""
        p = Payload()
        assert p.text == ""

    def test_payload_frozen(self) -> None:
        """Test that Payload is frozen."""
        p = Payload(text="test")
        with pytest.raises((AttributeError, TypeError)):
            p.text = "modified"  # type: ignore


class TestSessionContext:
    """Test SessionContext dataclass."""

    def test_session_context_initialization(self) -> None:
        """Test SessionContext initialization."""
        ctx = SessionContext(session_id="test-session")
        assert ctx.session_id == "test-session"
        assert ctx.signal_history == []

    def test_session_context_with_signals(self) -> None:
        """Test SessionContext with signal history."""
        signal = Signal(
            timestamp=1234567890.0,
            kind="detector",
            signal_id="test.signal",
            severity="medium",
        )
        ctx = SessionContext(
            session_id="test-session",
            signal_history=[signal],
        )
        assert len(ctx.signal_history) == 1
        assert ctx.signal_history[0].signal_id == "test.signal"

    def test_signal_dataclass(self) -> None:
        """Test Signal dataclass."""
        sig = Signal(
            timestamp=1234567890.0,
            kind="detector",
            signal_id="test.signal",
            severity="high",
        )
        assert sig.timestamp == 1234567890.0
        assert sig.kind == "detector"
        assert sig.signal_id == "test.signal"
        assert sig.severity == "high"
