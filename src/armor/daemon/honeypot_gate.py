"""Honeypot invocation gate — testable in isolation.

Determines whether the honeypot should be invoked based on session state
and pipeline signals. This gate is called by the daemon when appropriate,
and its invocation deferral is explicitly documented in ADR-021.
"""

from armor.types import SessionContext, Verdict


def should_invoke_honeypot(
    session_context: SessionContext,
    static_pipeline_verdict: Verdict,
) -> bool:
    """Determine if the honeypot should be invoked.

    The honeypot is invoked when:
    1. The static pipeline detected an injection attempt (returns block or advisory)
    2. The session is in Elevated state (or higher)

    Note: As of v0.3, session state tracking (task 022) is partially available via
    the optional SessionContext.state field. When task 022 lands and replaces this
    with a full session state machine, this gate will be updated to use the enum.

    Args:
        session_context: The current session context (includes optional state field).
        static_pipeline_verdict: The verdict from the static detector pipeline (before honeypot).

    Returns:
        True if honeypot should be invoked, False otherwise.
    """
    # Check if session is in elevated state
    session_elevated = session_context.state in ("elevated", "high", "blocked")

    # Check if static pipeline detected an injection attempt
    injection_detected = static_pipeline_verdict.decision in ("block", "advisory")

    # Invoke honeypot only if both conditions are met
    return session_elevated and injection_detected
