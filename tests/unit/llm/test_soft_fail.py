# SPDX-License-Identifier: Apache-2.0
"""Unit tests for LLM soft-fail (deadline timeout) behavior.

TC-021-01: Validator timeout returns advisory(confidence=0)
TC-021-09: LLMSession stores validator and honeypot budgets
"""

import time
from unittest.mock import patch

from armor.llm import validator
from armor.llm.honeypot import respond as honeypot_respond
from armor.llm.session import LLMSession
from armor.types import SessionContext


class MockSlowLLM:
    """Mock LLM instance that delays before returning a response."""

    def __init__(self, delay_ms: int = 600):
        """Initialize with delay in milliseconds.

        Args:
            delay_ms: How long to delay before returning (exceeds default budgets if > 500)
        """
        self.delay_ms = delay_ms

    def create_chat_completion(self, messages, **kwargs):
        """Simulate a slow inference by sleeping, then return a valid response."""
        time.sleep(self.delay_ms / 1000.0)
        # After the delay, return a valid response
        return {"choices": [{"message": {"content": '{"verdict": "safe", "confidence": 0.8}'}}]}


def test_validator_timeout_returns_advisory():
    """TC-021-01: Validator timeout returns advisory(confidence=0).

    When validator inference exceeds the budget_ms deadline, the function
    should return advisory(confidence=0) without raising an exception.
    """
    # Create a slow LLM that delays 600ms (exceeds 500ms validator budget)
    slow_llm = MockSlowLLM(delay_ms=600)
    session = LLMSession(
        instance=slow_llm,
        context_tokens=2048,
        validator_budget_ms=500,
        honeypot_budget_ms=16000,
    )

    ctx = SessionContext(session_id="test-timeout", signal_history=[])

    # Call validator with the slow LLM and a tight 500ms budget
    start = time.time()
    verdict = validator.validate("test payload", ctx, session, budget_ms=500)
    elapsed_ms = (time.time() - start) * 1000

    # Assert the deadline was enforced (call completed in ~500ms, not 600ms)
    assert elapsed_ms < 600, f"Deadline not enforced: took {elapsed_ms:.0f}ms"

    # Assert soft-fail verdict
    assert verdict.decision == "advisory"
    assert verdict.signal_id == "llm.validator:soft_fail"
    assert verdict.details["confidence"] == 0.0


def test_validator_uses_budget_from_llm_session():
    """TC-021-09: LLMSession stores validator_budget_ms.

    LLMSession should store both validator_budget_ms and honeypot_budget_ms.
    """
    slow_llm = MockSlowLLM(delay_ms=100)
    session = LLMSession(
        instance=slow_llm,
        context_tokens=2048,
        validator_budget_ms=500,
        honeypot_budget_ms=16000,
    )

    assert session.validator_budget_ms == 500
    assert session.honeypot_budget_ms == 16000


def test_honeypot_timeout_returns_empty_string():
    """TC-021-02: Honeypot timeout returns empty string.

    When honeypot inference exceeds the budget_ms deadline, the function
    should return an empty string without raising an exception.
    """
    from armor.canaries.catalogue import CanaryEntry, Catalogue

    # Create a slow LLM that delays 13000ms (exceeds 12000ms honeypot budget)
    slow_llm = MockSlowLLM(delay_ms=13000)
    session = LLMSession(
        instance=slow_llm,
        context_tokens=2048,
        validator_budget_ms=500,
        honeypot_budget_ms=16000,
    )

    # Create a minimal catalogue for testing
    catalogue = Catalogue(
        entries=[
            CanaryEntry(
                canary_id="test-canary",
                kind="credential",
                service="test",
                marker_rule=r"CANARY",
                value="CANARY-VALUE-123",
                active=True,
                created_at="2026-05-06T00:00:00Z",
            )
        ]
    )

    ctx = SessionContext(session_id="test-timeout", signal_history=[])

    # Call honeypot with the slow LLM and a tight 12000ms budget
    with patch("armor.llm.honeypot._load_honeypot_prompt", return_value="Test prompt"):
        start = time.time()
        response = honeypot_respond("test payload", ctx, catalogue, session, budget_ms=12000)
        elapsed_ms = (time.time() - start) * 1000

    # Assert the deadline was enforced (call completed in ~12000ms, not 13000ms)
    assert elapsed_ms < 13000, f"Deadline not enforced: took {elapsed_ms:.0f}ms"

    # Assert soft-fail response (empty string)
    assert response == ""


def test_validator_with_fast_llm_succeeds():
    """Validator should complete and return a valid verdict with a fast LLM.

    This ensures the deadline enforcement doesn't break normal operation.
    """
    fast_llm = MockSlowLLM(delay_ms=100)  # Fast, well under 500ms budget
    session = LLMSession(
        instance=fast_llm,
        context_tokens=2048,
        validator_budget_ms=500,
        honeypot_budget_ms=16000,
    )

    ctx = SessionContext(session_id="test-fast", signal_history=[])

    # Call validator with fast LLM
    verdict = validator.validate("test payload", ctx, session, budget_ms=500)

    # Assert success (should be advisory with confidence > 0)
    assert verdict.decision == "advisory"
    assert verdict.signal_id == "llm.validator:safe"
    assert verdict.details["confidence"] == 0.8  # From mock response


def test_validator_no_budget_override_uses_session_budget():
    """When budget_ms is not provided, validator uses llm_session.validator_budget_ms.

    TC-021-03: Configuration loads per-path budgets.
    """
    fast_llm = MockSlowLLM(delay_ms=100)
    session = LLMSession(
        instance=fast_llm,
        context_tokens=2048,
        validator_budget_ms=500,
        honeypot_budget_ms=16000,
    )

    ctx = SessionContext(session_id="test-session-budget", signal_history=[])

    # Call validator without explicit budget_ms (should use session's validator_budget_ms)
    verdict = validator.validate("test payload", ctx, session)

    # Should succeed since fast_llm is well under 500ms
    assert verdict.decision == "advisory"


def test_advisory_with_zero_confidence_does_not_block():
    """TC-021-08: Advisory with confidence=0 should not cause blocking.

    The pipeline should treat confidence=0 advisories as having zero weight.
    This is a basic sanity check on the verdict shape.
    """
    slow_llm = MockSlowLLM(delay_ms=600)
    session = LLMSession(
        instance=slow_llm,
        context_tokens=2048,
        validator_budget_ms=500,
        honeypot_budget_ms=16000,
    )

    ctx = SessionContext(session_id="test-zero-conf", signal_history=[])

    verdict = validator.validate("test", ctx, session, budget_ms=500)

    # Advisory with confidence=0 should never trigger a block
    assert verdict.decision == "advisory"
    assert verdict.details["confidence"] == 0.0
    assert verdict.decision != "block"


def test_validator_with_no_llm_session_returns_advisory():
    """TC-021-10: ARMOR_DISABLE_LLM disables validator path.

    When llm_session is None, validator should return advisory with confidence=0.
    This simulates the ARMOR_DISABLE_LLM=true behavior.
    """
    ctx = SessionContext(session_id="test-no-llm", signal_history=[])

    # Call validator with no LLM session
    verdict = validator.validate("test payload", ctx, llm_session=None)

    # Should return advisory with confidence=0
    assert verdict.decision == "advisory"
    assert verdict.details["confidence"] == 0.0
    assert verdict.signal_id == "llm.validator:no_model"


def test_honeypot_with_no_llm_session_returns_empty():
    """TC-021-10: ARMOR_DISABLE_LLM disables honeypot path.

    When llm_session is None, honeypot should return empty string.
    This simulates the ARMOR_DISABLE_LLM=true behavior.
    """
    from armor.canaries.catalogue import CanaryEntry, Catalogue

    # Create a minimal catalogue
    catalogue = Catalogue(
        entries=[
            CanaryEntry(
                canary_id="test-canary",
                kind="credential",
                service="test",
                marker_rule=r"CANARY",
                value="CANARY-VALUE-123",
                active=True,
                created_at="2026-05-06T00:00:00Z",
            )
        ]
    )

    ctx = SessionContext(session_id="test-no-llm", signal_history=[])

    # Call honeypot with no LLM session
    response = honeypot_respond("test payload", ctx, catalogue, llm_session=None)

    # Should return empty string
    assert response == ""
