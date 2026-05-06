"""LLM validator detector for semantic threat classification.

This detector runs the validator LLM on payloads when triggered by:
1. An advisory from a static detector (soft signal detected)
2. Session state at Watching or higher

The validator is a meta detector that wraps the core validate() function
and integrates it into the detection pipeline.

When run standalone (e.g. in tests), an LLMSession can be injected via
_llm_session attribute. Without it, the detector returns pass to avoid
polluting test verdicts.
"""

import logging
from typing import Any

from armor.llm.validator import validate
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

        The LLMSession is optionally injected (for testing) or provided by daemon.
        """
        self._llm_session: Any = None

    def check(self, payload: Payload, ctx: SessionContext) -> Verdict:
        """Check a payload using the LLM validator.

        The detector is gated: it only runs validate() when:
        1. A prior advisory signal exists in signal_history, OR
        2. Session state is Watching or higher (future: task 022)

        Without gating conditions or an LLMSession, returns pass.

        Args:
            payload: The payload being checked.
            ctx: Session context.

        Returns:
            Advisory verdict if triggered and LLM available, pass otherwise.
        """
        try:
            if not payload.text:
                return Verdict.pass_verdict(message="Empty payload; validator not triggered")

            # Check gating condition: prior advisory signal?
            has_prior_advisory = any(sig.kind == "advisory" for sig in ctx.signal_history)

            if not has_prior_advisory:
                return Verdict.pass_verdict(message="LLM validator not triggered (no prior advisory)")

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
