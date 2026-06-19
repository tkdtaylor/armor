# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the honeypot gate function.

Tests cover:
- TC-087-01 through TC-087-07: Honeypot gate behavior with various session states and verdicts
"""

from armor.daemon.honeypot_gate import should_invoke_honeypot
from armor.session.state_machine import SessionState
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
        """TC-087-05: Gate returns False when session is in Normal state (not elevated)."""
        ctx = SessionContext(session_id="test-session", state=SessionState.NORMAL)
        verdict = Verdict.block_verdict(
            signal_id="regex.instruction_override:override-001",
            message="Injection detected",
        )

        result = should_invoke_honeypot(ctx, verdict)

        assert result is False

    def test_gate_returns_true_when_elevated_with_block(self) -> None:
        """TC-087-01: Gate returns True when session is ELEVATED and pipeline detected block."""
        ctx = SessionContext(session_id="test-session", state=SessionState.ELEVATED)
        verdict = Verdict.block_verdict(
            signal_id="regex.instruction_override:override-001",
            message="Injection detected",
        )

        result = should_invoke_honeypot(ctx, verdict)

        assert result is True

    def test_gate_returns_true_when_elevated_with_advisory(self) -> None:
        """TC-087-02: Gate returns True when session is ELEVATED and pipeline detected advisory."""
        ctx = SessionContext(session_id="test-session", state=SessionState.ELEVATED)
        verdict = Verdict.advisory_verdict(
            signal_id="regex.roleplay_hijack:hijack-001",
            severity="medium",
            message="Potential roleplay hijack",
        )

        result = should_invoke_honeypot(ctx, verdict)

        assert result is True

    def test_gate_returns_false_when_elevated_but_no_detection(self) -> None:
        """TC-087-07: Gate returns False when elevated but pipeline detected pass."""
        ctx = SessionContext(session_id="test-session", state=SessionState.ELEVATED)
        verdict = Verdict.pass_verdict(message="All checks passed")

        result = should_invoke_honeypot(ctx, verdict)

        assert result is False

    def test_gate_returns_true_when_high_state(self) -> None:
        """TC-087-03: Gate returns True for HIGH state (or higher)."""
        ctx = SessionContext(session_id="test-session", state=SessionState.HIGH)
        verdict = Verdict.block_verdict(
            signal_id="regex.instruction_override:override-001",
            message="Injection detected",
        )

        result = should_invoke_honeypot(ctx, verdict)

        assert result is True

    def test_gate_accepts_blocked_state(self) -> None:
        """TC-087-04: Gate returns True for BLOCKED state (session stays gated even after blocked)."""
        ctx = SessionContext(session_id="test-session", state=SessionState.BLOCKED)
        verdict = Verdict.block_verdict(
            signal_id="regex.instruction_override:override-001",
            message="Injection detected",
        )

        result = should_invoke_honeypot(ctx, verdict)

        assert result is True

    def test_gate_accepts_watching_state(self) -> None:
        """TC-087-01b: Gate returns True for WATCHING state with block (per B-011: ≥ Watching)."""
        ctx = SessionContext(session_id="test-session", state=SessionState.WATCHING)
        verdict = Verdict.block_verdict(
            signal_id="regex.instruction_override:override-001",
            message="Injection detected",
        )

        result = should_invoke_honeypot(ctx, verdict)

        assert result is True

    def test_gate_signature_accepts_session_and_verdict(self) -> None:
        """TC-087-01c: Gate function has the expected signature."""
        ctx = SessionContext(session_id="test-session", state=SessionState.ELEVATED)
        advisory_verdict = Verdict.advisory_verdict(
            signal_id="regex.roleplay_hijack:hijack-001",
            severity="medium",
            message="Potential roleplay hijack",
        )

        # Should not raise
        result = should_invoke_honeypot(ctx, advisory_verdict)
        assert isinstance(result, bool)
