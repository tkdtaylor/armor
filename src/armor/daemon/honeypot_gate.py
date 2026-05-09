"""Honeypot invocation gate — testable in isolation.

Determines whether the honeypot should be invoked based on session state
and pipeline signals. This gate is called by the daemon when appropriate,
and its invocation deferral is explicitly documented in ADR-021.
"""

from armor.session.state_machine import SessionState
from armor.types import SessionContext, Verdict


def should_invoke_honeypot(
    session_context: SessionContext,
    static_pipeline_verdict: Verdict,
) -> bool:
    """Determine if the honeypot should be invoked per B-011.

    The honeypot is invoked when:
    1. The static pipeline detected an injection attempt (returns block or advisory)
    2. The session state is WATCHING or higher (per B-011 and ADR-024)

    Args:
        session_context: The current session context (includes state: SessionState | None).
        static_pipeline_verdict: The verdict from the static detector pipeline (before honeypot).

    Returns:
        True if honeypot should be invoked, False otherwise.
    """
    # Check if session state is high enough to invoke honeypot (WATCHING or higher)
    if session_context.state is None:
        # None is treated as NORMAL, which does not invoke honeypot
        session_elevated = False
    else:
        session_elevated = session_context.state in (
            SessionState.WATCHING,
            SessionState.ELEVATED,
            SessionState.HIGH,
            SessionState.BLOCKED,
        )

    # Check if static pipeline detected an injection attempt
    injection_detected = static_pipeline_verdict.decision in ("block", "advisory")

    # Invoke honeypot only if both conditions are met
    return session_elevated and injection_detected
