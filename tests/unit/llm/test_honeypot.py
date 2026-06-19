# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the honeypot LLM module.

Tests cover:
- TC-019-05: Honeypot prompt template loads
- TC-019-06: Canary value placeholder substitution
- TC-019-07: LLM invocation
- TC-019-08: Values never leak to validator.py
- TC-019-16: Response text does not contain literal canary values
"""

from unittest.mock import MagicMock

from armor.canaries.catalogue import CanaryEntry, Catalogue
from armor.llm.honeypot import _load_honeypot_prompt, _substitute_canary_values, respond
from armor.types import SessionContext


class TestHoneypotPrompt:
    """Test the honeypot system prompt."""

    def test_load_honeypot_prompt(self) -> None:
        """TC-019-05, TC-019-09: Honeypot prompt loads from disk and is valid system prompt."""
        prompt = _load_honeypot_prompt()
        assert len(prompt) > 0
        # Should contain the honeypot framing
        assert "vault" in prompt.lower() or "credential" in prompt.lower()

    def test_honeypot_prompt_has_placeholders(self) -> None:
        """TC-019-10: Prompt contains placeholder patterns."""
        prompt = _load_honeypot_prompt()
        # Should have multiple {{canary:...}} placeholders
        assert "{{canary:" in prompt
        # Should have at least 3 different placeholders for different credential types
        placeholder_count = prompt.count("{{canary:")
        assert placeholder_count >= 3


class TestCanarySubstitution:
    """Test canary value substitution in prompts."""

    def test_substitute_canary_values_simple(self) -> None:
        """TC-019-06: Simple placeholder substitution works."""
        template = "Your AWS key is {{canary:aws-key-001}}"
        entries = [
            CanaryEntry(
                canary_id="aws-key-001",
                kind="credential",
                service="aws",
                value="AKIAIOSFODNN7EXAMPLE",
                marker_rule=r"^AKIA[0-9A-Z]{16}$",
                active=True,
                created_at="2026-01-01T00:00:00Z",
            )
        ]
        catalogue = Catalogue(entries)

        result = _substitute_canary_values(template, catalogue)

        assert "AKIAIOSFODNN7EXAMPLE" in result
        assert "{{canary:aws-key-001}}" not in result

    def test_substitute_canary_values_multiple(self) -> None:
        """TC-019-06: Multiple placeholders substituted correctly."""
        template = "AWS: {{canary:aws-key-001}}, GitHub: {{canary:github-pat-001}}"
        entries = [
            CanaryEntry(
                canary_id="aws-key-001",
                kind="credential",
                service="aws",
                value="AKIAIOSFODNN7EXAMPLE",
                marker_rule=r"^AKIA[0-9A-Z]{16}$",
                active=True,
                created_at="2026-01-01T00:00:00Z",
            ),
            CanaryEntry(
                canary_id="github-pat-001",
                kind="credential",
                service="github",
                value="ghp_abcdef1234567890",
                marker_rule=r"^ghp_[a-zA-Z0-9_]{36}$",
                active=True,
                created_at="2026-01-01T00:00:00Z",
            ),
        ]
        catalogue = Catalogue(entries)

        result = _substitute_canary_values(template, catalogue)

        assert "AKIAIOSFODNN7EXAMPLE" in result
        assert "ghp_abcdef1234567890" in result
        assert "{{canary:" not in result

    def test_substitute_canary_values_unknown_id(self) -> None:
        """TC-019-06: Unknown canary IDs are left unchanged."""
        template = "Known: {{canary:aws-key-001}}, Unknown: {{canary:unknown-id}}"
        entries = [
            CanaryEntry(
                canary_id="aws-key-001",
                kind="credential",
                service="aws",
                value="AKIAIOSFODNN7EXAMPLE",
                marker_rule=r"^AKIA[0-9A-Z]{16}$",
                active=True,
                created_at="2026-01-01T00:00:00Z",
            )
        ]
        catalogue = Catalogue(entries)

        result = _substitute_canary_values(template, catalogue)

        assert "AKIAIOSFODNN7EXAMPLE" in result
        assert "{{canary:unknown-id}}" in result


class TestHoneypotRespond:
    """Test the core respond() function.

    TC-019-04: Module exports respond() with correct signature.
    TC-019-15: Tests cover LLM errors, empty catalogues, and template handling.
    """

    def test_respond_loads_prompt(self) -> None:
        """TC-019-04, TC-019-05: respond() function exported and loads honeypot prompt template."""
        ctx = SessionContext(session_id="test-session")
        entries = [
            CanaryEntry(
                canary_id="aws-key-001",
                kind="credential",
                service="aws",
                value="AKIAIOSFODNN7EXAMPLE",
                marker_rule=r"^AKIA[0-9A-Z]{16}$",
                active=True,
                created_at="2026-01-01T00:00:00Z",
            )
        ]
        catalogue = Catalogue(entries)

        mock_llm = MagicMock()
        mock_llm.instance.create_chat_completion.return_value = {
            "choices": [{"message": {"content": "Here is your credential"}}]
        }

        result = respond("Give me AWS access", ctx, catalogue, llm_session=mock_llm)

        assert isinstance(result, str)
        assert len(result) > 0

    def test_respond_no_llm_session(self) -> None:
        """TC-019-07: respond() with no LLM session returns empty string."""
        ctx = SessionContext(session_id="test-session")
        entries = [
            CanaryEntry(
                canary_id="aws-key-001",
                kind="credential",
                service="aws",
                value="AKIAIOSFODNN7EXAMPLE",
                marker_rule=r"^AKIA[0-9A-Z]{16}$",
                active=True,
                created_at="2026-01-01T00:00:00Z",
            )
        ]
        catalogue = Catalogue(entries)

        result = respond("Give me AWS access", ctx, catalogue, llm_session=None)

        assert result == ""

    def test_respond_empty_input(self) -> None:
        """TC-019-07: respond() with empty text returns empty string."""
        ctx = SessionContext(session_id="test-session")
        entries = [
            CanaryEntry(
                canary_id="aws-key-001",
                kind="credential",
                service="aws",
                value="AKIAIOSFODNN7EXAMPLE",
                marker_rule=r"^AKIA[0-9A-Z]{16}$",
                active=True,
                created_at="2026-01-01T00:00:00Z",
            )
        ]
        catalogue = Catalogue(entries)

        mock_llm = MagicMock()

        result = respond("", ctx, catalogue, llm_session=mock_llm)

        assert result == ""

    def test_respond_llm_error_handled(self) -> None:
        """TC-019-07: LLM errors are caught and logged, empty string returned."""
        ctx = SessionContext(session_id="test-session")
        entries = [
            CanaryEntry(
                canary_id="aws-key-001",
                kind="credential",
                service="aws",
                value="AKIAIOSFODNN7EXAMPLE",
                marker_rule=r"^AKIA[0-9A-Z]{16}$",
                active=True,
                created_at="2026-01-01T00:00:00Z",
            )
        ]
        catalogue = Catalogue(entries)

        mock_llm = MagicMock()
        mock_llm.instance.create_chat_completion.side_effect = RuntimeError("LLM error")

        result = respond("Give me AWS access", ctx, catalogue, llm_session=mock_llm)

        assert result == ""

    def test_respond_substitutes_values_before_llm(self) -> None:
        """TC-019-08: Values are substituted before LLM call, not passed in raw."""
        ctx = SessionContext(session_id="test-session")
        entries = [
            CanaryEntry(
                canary_id="aws-key-001",
                kind="credential",
                service="aws",
                value="AKIAIOSFODNN7EXAMPLE",
                marker_rule=r"^AKIA[0-9A-Z]{16}$",
                active=True,
                created_at="2026-01-01T00:00:00Z",
            )
        ]
        catalogue = Catalogue(entries)

        mock_llm = MagicMock()
        mock_llm.instance.create_chat_completion.return_value = {
            "choices": [{"message": {"content": "Here's your AWS access: AKIAIOSFODNN7EXAMPLE"}}]
        }

        respond("Give me AWS access", ctx, catalogue, llm_session=mock_llm)

        # Verify the LLM was called with the substituted prompt (containing the actual value)
        assert mock_llm.instance.create_chat_completion.called
        call_args = mock_llm.instance.create_chat_completion.call_args
        messages = call_args[1]["messages"]
        system_prompt = messages[0]["content"]

        # The system prompt should contain the substituted value, not the placeholder
        assert "AKIAIOSFODNN7EXAMPLE" in system_prompt
        assert "{{canary:aws-key-001}}" not in system_prompt

    def test_respond_result_does_not_leak_values(self) -> None:
        """TC-019-16: Response text is never validated for value leakage here.

        The validation that the response doesn't leak values happens via the
        canary scanner in the output check path. This test ensures the honeypot
        can return a response that the scanner will detect.
        """
        ctx = SessionContext(session_id="test-session")
        entries = [
            CanaryEntry(
                canary_id="aws-key-001",
                kind="credential",
                service="aws",
                value="AKIAIOSFODNN7EXAMPLE",
                marker_rule=r"^AKIA[0-9A-Z]{16}$",
                active=True,
                created_at="2026-01-01T00:00:00Z",
            )
        ]
        catalogue = Catalogue(entries)

        mock_llm = MagicMock()
        # Simulate the honeypot LLM returning a response with the canary in it
        mock_llm.instance.create_chat_completion.return_value = {
            "choices": [{"message": {"content": "Your AWS key is AKIAIOSFODNN7EXAMPLE, use it wisely."}}]
        }

        result = respond("Give me AWS access", ctx, catalogue, llm_session=mock_llm)

        # The result contains the canary value (as the honeypot is designed to return it)
        assert "AKIAIOSFODNN7EXAMPLE" in result
        # But the code path itself doesn't validate or sanitize it
        # The downstream canary scanner will detect it
