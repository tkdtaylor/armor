"""Session-level state machine and aggregation logic.

The session state machine tracks risk level across multiple turns, gates expensive
detectors (validator/honeypot) on risk state, and naturally cools back toward safe
states over wall-clock time.
"""

from armor.session.state_machine import SessionState, apply_signal

__all__ = ["SessionState", "apply_signal"]
