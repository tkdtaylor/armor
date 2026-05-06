"""Honeypot prompt system with runtime canary value injection.

The honeypot module loads a system prompt template containing placeholder strings
like {{canary:aws-key-001}} and substitutes actual canary values from the runtime
catalogue before running the LLM. The validator.py module NEVER reads canary values
— substitution happens only in this path to enforce a strict isolation invariant.
"""

import logging
import re
import threading
from pathlib import Path
from typing import Any

from armor.canaries.catalogue import Catalogue
from armor.llm.session import LLMSession
from armor.types import SessionContext

logger = logging.getLogger(__name__)


def _load_honeypot_prompt() -> str:
    """Load the honeypot system prompt from disk.

    Returns:
        The prompt text with placeholders intact (e.g., {{canary:aws-key-001}}).

    Raises:
        FileNotFoundError: If the prompt file is missing.
    """
    prompt_path = Path(__file__).parent / "prompts" / "honeypot.txt"
    if not prompt_path.exists():
        raise FileNotFoundError(f"Honeypot prompt not found at {prompt_path}")
    return prompt_path.read_text(encoding="utf-8")


def _substitute_canary_values(prompt_text: str, catalogue: Catalogue) -> str:
    """Substitute canary value placeholders in the prompt.

    Finds all placeholders matching {{canary:<canary_id>}} and replaces them
    with the corresponding value from the catalogue. Unknown canary IDs are
    left unchanged.

    Args:
        prompt_text: The prompt template with placeholders.
        catalogue: The loaded canary catalogue with values.

    Returns:
        The prompt text with placeholders substituted by actual values.
    """
    # Pattern matches {{canary:<canary_id>}}
    pattern = r"\{\{canary:([a-zA-Z0-9\-_]+)\}\}"

    def replacer(match: re.Match[str]) -> str:
        canary_id = match.group(1)
        # Find the canary in the catalogue
        for entry in catalogue.entries:
            if entry.canary_id == canary_id:
                return entry.value
        # If not found, leave the placeholder unchanged
        logger.warning(f"Canary ID not found in catalogue: {canary_id}")
        return match.group(0)

    return re.sub(pattern, replacer, prompt_text)


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
        logger.warning(f"LLM honeypot deadline exceeded ({budget_ms} ms); result discarded")
        return None

    if exception[0] is not None:
        raise exception[0]

    return result[0]


def respond(
    text: str,
    session_context: SessionContext,
    catalogue: Catalogue,
    llm_session: LLMSession | None = None,
    budget_ms: int | None = None,
) -> str:
    """Run the honeypot prompt with substituted canary values.

    Args:
        text: The user input or context text to include in the honeypot interaction.
        session_context: Session context for logging/tracking.
        catalogue: The loaded canary catalogue (used only for value substitution).
        llm_session: The loaded LLM session. If None, returns a stub response.
        budget_ms: Optional budget override in milliseconds. If not provided, uses
                  llm_session.honeypot_budget_ms if available.

    Returns:
        The LLM's response text. On timeout or error, returns empty string.

    Raises:
        FileNotFoundError: If the honeypot prompt file is missing.
        Exception: Any error from LLM inference is logged and a stub response
                   is returned instead of raising.
    """
    if not text:
        logger.warning("Honeypot respond called with empty text")
        return ""

    if not llm_session:
        logger.warning("Honeypot respond called without LLM session")
        return ""

    # Determine budget to use
    if budget_ms is None or not isinstance(budget_ms, int):
        # Try to get from llm_session, fall back to default
        if llm_session and hasattr(llm_session, "honeypot_budget_ms"):
            val = getattr(llm_session, "honeypot_budget_ms", None)
            budget_ms = val if isinstance(val, int) else 12000
        else:
            budget_ms = 12000

    try:
        # Load the honeypot system prompt template
        prompt_template = _load_honeypot_prompt()

        # Substitute canary values from the catalogue
        system_prompt = _substitute_canary_values(prompt_template, catalogue)

        # Define the LLM call wrapped with deadline enforcement
        def _llm_call() -> Any:
            return llm_session.instance.create_chat_completion(
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": text},
                ],
                temperature=0.7,  # Higher temperature for more varied honeypot responses
                top_p=0.95,
                max_tokens=500,  # Longer responses to increase chance of canary inclusion
            )

        # Invoke with deadline
        response_obj = _invoke_with_deadline(_llm_call, (), budget_ms)

        # Check for timeout
        if response_obj is None:
            logger.warning(f"LLM honeypot timeout (budget: {budget_ms} ms)")
            return ""

        # Type guard: response_obj should be a dict, not an iterator (stream=False)
        if not isinstance(response_obj, dict):
            logger.error("LLM returned non-dict response (unexpected streaming mode)")
            return ""

        # Extract the response text
        if not response_obj or "choices" not in response_obj or not response_obj["choices"]:
            logger.error("LLM returned empty response")
            return ""

        response_text = response_obj["choices"][0]["message"]["content"]
        if not isinstance(response_text, str):
            logger.error(f"LLM returned non-string content: {type(response_text)}")
            return ""

        return response_text.strip()

    except Exception as e:
        logger.error(f"Honeypot LLM error: {e}", exc_info=True)
        return ""
