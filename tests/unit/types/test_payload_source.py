# SPDX-License-Identifier: Apache-2.0
"""Unit tests for Payload.source field (per ADR-041, task 065)."""

import pytest

from armor.types import Payload, SessionContext, Source


class TestSourceEnum:
    """Test the Source enum."""

    def test_source_enum_values(self) -> None:
        """Test all Source enum values exist."""
        assert Source.USER_INPUT == "user_input"
        assert Source.MODEL_OUTPUT == "model_output"
        assert Source.TOOL_PARAMS == "tool_params"
        assert Source.TOOL_RESULT_TRUSTED == "tool_result_trusted"
        assert Source.TOOL_RESULT_UNTRUSTED == "tool_result_untrusted"

    def test_source_enum_membership(self) -> None:
        """Test Source enum membership."""
        all_sources = list(Source)
        assert len(all_sources) == 5
        assert Source.USER_INPUT in all_sources


class TestPayloadSource:
    """Test Payload.source field."""

    def test_payload_source_defaults_to_user_input(self) -> None:
        """Test that Payload.source defaults to USER_INPUT."""
        p = Payload(text="test")
        assert p.source == Source.USER_INPUT

    def test_payload_source_explicit_user_input(self) -> None:
        """Test Payload with explicit USER_INPUT source."""
        p = Payload(text="test", source=Source.USER_INPUT)
        assert p.source == Source.USER_INPUT

    def test_payload_source_model_output(self) -> None:
        """Test Payload with MODEL_OUTPUT source."""
        p = Payload(text="test", source=Source.MODEL_OUTPUT)
        assert p.source == Source.MODEL_OUTPUT

    def test_payload_source_tool_params(self) -> None:
        """Test Payload with TOOL_PARAMS source."""
        p = Payload(text="bash -c ls", tool="bash", source=Source.TOOL_PARAMS)
        assert p.source == Source.TOOL_PARAMS

    def test_payload_source_tool_result_trusted(self) -> None:
        """Test Payload with TOOL_RESULT_TRUSTED source."""
        p = Payload(text="file contents", source=Source.TOOL_RESULT_TRUSTED)
        assert p.source == Source.TOOL_RESULT_TRUSTED

    def test_payload_source_tool_result_untrusted(self) -> None:
        """Test Payload with TOOL_RESULT_UNTRUSTED source."""
        p = Payload(text="fetched content", source=Source.TOOL_RESULT_UNTRUSTED)
        assert p.source == Source.TOOL_RESULT_UNTRUSTED

    def test_payload_source_string_conversion(self) -> None:
        """Test Source enum converts to/from string."""
        source = Source("user_input")
        assert source == Source.USER_INPUT
        assert str(source) == "user_input"

    def test_payload_with_all_fields_and_source(self) -> None:
        """Test Payload with text, tool, params, and source."""
        p = Payload(
            text="result",
            tool="Read",
            params={"path": "/tmp/file"},
            source=Source.TOOL_RESULT_UNTRUSTED,
        )
        assert p.text == "result"
        assert p.tool == "Read"
        assert p.params == {"path": "/tmp/file"}
        assert p.source == Source.TOOL_RESULT_UNTRUSTED

    def test_payload_source_frozen(self) -> None:
        """Test that Payload with source is still frozen."""
        p = Payload(text="test", source=Source.TOOL_RESULT_UNTRUSTED)
        with pytest.raises((AttributeError, TypeError)):
            p.source = Source.USER_INPUT  # type: ignore


class TestSessionContextNoPayloadSource:
    """Test that SessionContext does NOT have a payload_source field (regression, per ADR-041).

    ADR-041 supersedes ADR-033's proposal to put payload_source on SessionContext.
    This test ensures we didn't accidentally add it there.
    """

    def test_session_context_has_no_payload_source(self) -> None:
        """Explicitly test that SessionContext does not have payload_source field."""
        ctx = SessionContext(session_id="test-session")

        # Check that the attribute doesn't exist
        assert not hasattr(ctx, "payload_source"), (
            "SessionContext must NOT have payload_source field per ADR-041. "
            "Payload.source lives on Payload, not SessionContext."
        )

    def test_session_context_dataclass_fields(self) -> None:
        """Test SessionContext has the expected fields only."""
        ctx = SessionContext(session_id="test-session")

        # Check expected fields
        assert hasattr(ctx, "session_id")
        assert hasattr(ctx, "signal_history")
        assert hasattr(ctx, "state")
        assert hasattr(ctx, "rolling_buffer")
        assert hasattr(ctx, "turn_count")

        # Explicitly verify payload_source is NOT a field
        ctx_dict = ctx.__dict__
        assert "payload_source" not in ctx_dict
