# SPDX-License-Identifier: Apache-2.0
"""LLM validator for semantic-level threat classification.

The validator runs a small quantized LLM on payloads flagged by static detectors
or when the session is in elevated state. It returns "safe" or "risky" with a
confidence score, feeding into the session risk score (never blocks unilaterally).
"""

import json
import logging
import threading
from pathlib import Path
from typing import Any

from armor.llm.session import LLMSession
from armor.types import SessionContext, Verdict

logger = logging.getLogger(__name__)


def _load_validator_prompt(prompt_path: Path | None = None) -> str:
    """Load the validator system prompt from disk.

    Args:
        prompt_path: Optional path to a custom prompt file. If provided and exists,
                    load from that path. Otherwise, load from the default location.

    Returns:
        The prompt text.

    Raises:
        FileNotFoundError: If the prompt file is missing.
    """
    if prompt_path and prompt_path.exists():
        return prompt_path.read_text(encoding="utf-8")

    default_path = Path(__file__).parent / "prompts" / "validator.txt"
    if not default_path.exists():
        raise FileNotFoundError(f"Validator prompt not found at {default_path}")
    return default_path.read_text(encoding="utf-8")


def _invoke_with_deadline(fn: Any, args: tuple[Any, ...], budget_ms: int) -> Any:
    """Call fn(*args) with a deadline; return None on timeout (soft-fail).

    Uses threading to enforce a deadline. If the deadline is exceeded, the function
    returns None and the background thread continues (best-effort cancellation).

    Args:
        fn: Callable to invoke
        args: Positional arguments to pass to fn
        budget_ms: Timeout in milliseconds

    Returns:
        The result of fn(*args), or None if the deadline is exceeded.
    """
    result: list[Any] = [None]
    exception: list[Exception | None] = [None]

    def target() -> None:
        try:
            result[0] = fn(*args)
        except Exception as e:
            exception[0] = e

    thread = threading.Thread(target=target, daemon=True)
    thread.start()
    thread.join(timeout=budget_ms / 1000.0)

    if thread.is_alive():
        # Deadline exceeded; thread continues in background
        logger.warning(f"LLM validator deadline exceeded ({budget_ms} ms); result discarded")
        return None

    if exception[0] is not None:
        raise exception[0]

    return result[0]


def validate(
    text: str,
    session_context: SessionContext,
    llm_session: LLMSession | None = None,
    budget_ms: int | None = None,
    prompt_path: Path | None = None,
) -> Verdict:
    """Validate a payload for adversarial content using the LLM.

    Args:
        text: The text payload to validate.
        session_context: Session context (for logging/tracking).
        llm_session: The loaded LLM session. If None, returns advisory with confidence=0.
        budget_ms: Optional budget override in milliseconds. If not provided, uses
                  llm_session.validator_budget_ms if available.
        prompt_path: Optional path to a custom prompt file. If provided and exists,
                    load from that path instead of the default validator.txt.

    Returns:
        An advisory Verdict with confidence score in details["confidence"].
        Parse failure → advisory(confidence=0).
        Model unavailable → advisory(confidence=0).
        Timeout → advisory(confidence=0).
    """
    if not text or not llm_session:
        return Verdict.advisory_verdict(
            signal_id="llm.validator:no_model",
            severity="low",
            message="LLM validator unavailable",
            details={"confidence": 0.0},
        )

    # Determine budget to use
    if budget_ms is None or not isinstance(budget_ms, int):
        # Try to get from llm_session, fall back to default
        if llm_session and hasattr(llm_session, "validator_budget_ms"):
            val = getattr(llm_session, "validator_budget_ms", None)
            budget_ms = val if isinstance(val, int) else 500
        else:
            budget_ms = 500

    try:
        # Load validator system prompt (with optional custom path)
        system_prompt = _load_validator_prompt(prompt_path=prompt_path)

        # Define the LLM call wrapped with deadline enforcement
        def _llm_call() -> Any:
            # Call the LLM
            # llama_cpp.Llama.create_chat_completion returns a dict with structure:
            # {"choices": [{"message": {"content": "..."}}], ...}
            # Type: CreateChatCompletionResponse (dict-like)
            return llm_session.instance.create_chat_completion(
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": text},
                ],
                temperature=0.3,  # Low temperature for deterministic classification
                top_p=0.9,
                max_tokens=100,  # Short response
            )

        # Invoke with deadline
        response_obj = _invoke_with_deadline(_llm_call, (), budget_ms)

        # Check for timeout
        if response_obj is None:
            logger.warning(f"LLM validator timeout (budget: {budget_ms} ms)")
            return Verdict.advisory_verdict(
                signal_id="llm.validator:soft_fail",
                severity="low",
                message="LLM validator timed out",
                details={"confidence": 0.0},
            )

        # Type guard: response_obj should be a dict, not an iterator (stream=False)
        if not isinstance(response_obj, dict):
            logger.error("LLM returned non-dict response (unexpected streaming mode)")
            return Verdict.advisory_verdict(
                signal_id="llm.validator:empty_response",
                severity="low",
                message="LLM validator returned empty response",
                details={"confidence": 0.0},
            )

        # Extract the response text
        if not response_obj or "choices" not in response_obj or not response_obj["choices"]:
            logger.error("LLM returned empty response")
            return Verdict.advisory_verdict(
                signal_id="llm.validator:empty_response",
                severity="low",
                message="LLM validator returned empty response",
                details={"confidence": 0.0},
            )

        response_text = response_obj["choices"][0]["message"]["content"]
        if not isinstance(response_text, str):
            logger.error(f"LLM returned non-string content: {type(response_text)}")
            return Verdict.advisory_verdict(
                signal_id="llm.validator:empty_response",
                severity="low",
                message="LLM validator returned empty response",
                details={"confidence": 0.0},
            )

        response_text = response_text.strip()

        # Parse JSON response
        try:
            parsed = json.loads(response_text)
        except json.JSONDecodeError as e:
            logger.warning(f"LLM returned invalid JSON: {response_text[:100]} — {e}")
            return Verdict.advisory_verdict(
                signal_id="llm.validator:parse_error",
                severity="low",
                message="LLM validator returned malformed JSON",
                details={"confidence": 0.0, "raw_response": response_text[:100]},
            )

        # Extract verdict and confidence
        verdict_str = parsed.get("verdict", "").lower()
        confidence = float(parsed.get("confidence", 0.0))

        # Validate fields
        if verdict_str not in ("safe", "risky"):
            logger.warning(f"LLM returned invalid verdict: {verdict_str}")
            return Verdict.advisory_verdict(
                signal_id="llm.validator:invalid_verdict",
                severity="low",
                message="LLM validator returned invalid verdict",
                details={"confidence": 0.0},
            )

        if not (0.0 <= confidence <= 1.0):
            logger.warning(f"LLM returned invalid confidence: {confidence}")
            confidence = max(0.0, min(1.0, confidence))

        # Return advisory with confidence in details
        return Verdict.advisory_verdict(
            signal_id=f"llm.validator:{verdict_str}",
            severity="high" if verdict_str == "risky" else "low",
            message=f"LLM validator: {verdict_str}",
            details={
                "confidence": confidence,
                "validator_response": verdict_str,
            },
        )

    except Exception as e:
        logger.error(f"Validator error: {e}", exc_info=True)
        return Verdict.advisory_verdict(
            signal_id="llm.validator:error",
            severity="low",
            message="LLM validator error",
            details={"confidence": 0.0, "error": str(e)},
        )
