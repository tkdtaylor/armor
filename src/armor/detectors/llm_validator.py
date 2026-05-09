"""LLM validator detector for semantic threat classification.

This detector runs the validator LLM on payloads when triggered by:
1. Session state at Watching or higher (FSM-gated)

The validator is a meta detector that wraps the core validate() function
and integrates it into the detection pipeline.

When run standalone (e.g. in tests), an LLMSession can be injected via
_llm_session attribute. Without it, the detector returns pass to avoid
polluting test verdicts.
"""

import logging
from typing import Any

from armor.llm.validator import validate
from armor.session.state_machine import SessionState
from armor.types import Payload, SessionContext, Verdict

logger = logging.getLogger(__name__)


class LLMValidator:
    """LLM-based validator detector for semantic threat classification.

    Attributes:
        id: Unique detector identifier.
        category: Attack category ("meta" for system-level).
        cost_tier: "llm" (uses LLM inference, higher latency).
    """

    id: str = "llm.validator"
    category: str = "meta"
    cost_tier: str = "llm"

    def __init__(self) -> None:
        """Initialize the detector.

        The LLMSession is injected by the daemon after registry initialization (mechanism A).
        Can be set to None for testing; in production, the daemon will fail to start if
        this detector is registered but no LLM was loaded.
        """
        self._llm_session: Any = None  # Will be injected by daemon via setattr()

    def check(self, payload: Payload, ctx: SessionContext) -> Verdict:
        """Check a payload using the LLM validator.

        The detector is gated: it only runs validate() when session state
        is Watching or higher (per B-005). This gates the expensive LLM
        cost tier on the session FSM state.

        Without gating condition or an LLMSession, returns pass.

        Args:
            payload: The payload being checked.
            ctx: Session context.

        Returns:
            Advisory verdict if triggered and LLM available, pass otherwise.
        """
        try:
            if not payload.text:
                return Verdict.pass_verdict(message="Empty payload; validator not triggered")

            # Gate on FSM state: only run if state >= Watching
            if ctx.state not in (SessionState.WATCHING, SessionState.ELEVATED, SessionState.HIGH, SessionState.BLOCKED):
                return Verdict.pass_verdict(message="LLM validator not triggered (state below Watching threshold)")

            # Gating condition met; call validate() if we have an LLMSession
            if not self._llm_session:
                return Verdict.pass_verdict(message="LLM validator unavailable (no LLM session)")

            # Call the validator with the injected session
            result = validate(payload.text, ctx, llm_session=self._llm_session)
            return result

        except Exception as e:
            logger.error(f"LLM validator detector error: {e}", exc_info=True)
            return Verdict.error_verdict(
                reason=f"Validator detector error: {e!s}",
                details={"error": str(e)},
            )
