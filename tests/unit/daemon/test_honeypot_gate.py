"""Unit tests for the honeypot gate function.

Tests cover:
- TC-019-11: Honeypot gate is testable in isolation
"""

from armor.daemon.honeypot_gate import should_invoke_honeypot
from armor.types import SessionContext, Verdict


class TestHoneypotGate:
    """Test the honeypot invocation gate."""

    def test_gate_returns_false_without_session_state(self) -> None:
        """TC-019-11: Gate returns False when session state is None."""
        ctx = SessionContext(session_id="test-session", state=None)
        verdict = Verdict.block_verdict(
            signal_id="regex.instruction_override:override-001",
            message="Injection detected",
        )

        result = should_invoke_honeypot(ctx, verdict)

        # Returns False because session state is not elevated
        assert result is False

    def test_gate_returns_false_when_normal_session_with_block(self) -> None:
        """TC-019-11: Gate returns False when session is in Normal state (not elevated)."""
        ctx = SessionContext(session_id="test-session", state="normal")
        verdict = Verdict.block_verdict(
            signal_id="regex.instruction_override:override-001",
            message="Injection detected",
        )

        result = should_invoke_honeypot(ctx, verdict)

        assert result is False

    def test_gate_returns_true_when_elevated_with_block(self) -> None:
        """TC-019-11: Gate returns True when session is Elevated and pipeline detected block."""
        ctx = SessionContext(session_id="test-session", state="elevated")
        verdict = Verdict.block_verdict(
            signal_id="regex.instruction_override:override-001",
            message="Injection detected",
        )

        result = should_invoke_honeypot(ctx, verdict)

        assert result is True

    def test_gate_returns_true_when_elevated_with_advisory(self) -> None:
        """TC-019-11: Gate returns True when session is Elevated and pipeline detected advisory."""
        ctx = SessionContext(session_id="test-session", state="elevated")
        verdict = Verdict.advisory_verdict(
            signal_id="regex.roleplay_hijack:hijack-001",
            severity="medium",
            message="Potential roleplay hijack",
        )

        result = should_invoke_honeypot(ctx, verdict)

        assert result is True

    def test_gate_returns_false_when_elevated_but_no_detection(self) -> None:
        """TC-019-11: Gate returns False when elevated but pipeline detected pass."""
        ctx = SessionContext(session_id="test-session", state="elevated")
        verdict = Verdict.pass_verdict(message="All checks passed")

        result = should_invoke_honeypot(ctx, verdict)

        assert result is False

    def test_gate_returns_true_when_high_state(self) -> None:
        """TC-019-11: Gate returns True for high state (or higher)."""
        ctx = SessionContext(session_id="test-session", state="high")
        verdict = Verdict.block_verdict(
            signal_id="regex.instruction_override:override-001",
            message="Injection detected",
        )

        result = should_invoke_honeypot(ctx, verdict)

        assert result is True

    def test_gate_signature_accepts_session_and_verdict(self) -> None:
        """TC-019-11: Gate function has the expected signature."""
        ctx = SessionContext(session_id="test-session", state="elevated")
        advisory_verdict = Verdict.advisory_verdict(
            signal_id="regex.roleplay_hijack:hijack-001",
            severity="medium",
            message="Potential roleplay hijack",
        )

        # Should not raise
        result = should_invoke_honeypot(ctx, advisory_verdict)
        assert isinstance(result, bool)
