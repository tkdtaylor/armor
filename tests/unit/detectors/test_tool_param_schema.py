"""Unit tests for the tool_param_schema detector."""

import pytest

from armor.detectors.tool_param_schema import ToolParamSchema
from armor.types import Payload, SessionContext


class TestToolParamSchemaAttributes:
    """Tests for detector attributes. (TC-126-01)"""

    def test_detector_id(self) -> None:
        """Test detector has correct ID. (TC-126-01)"""
        detector = ToolParamSchema()
        assert detector.id == "tool_param.schema"

    def test_detector_category(self) -> None:
        """Test detector has correct category. (TC-126-01)"""
        detector = ToolParamSchema()
        assert detector.category == "tool_abuse"

    def test_detector_cost_tier(self) -> None:
        """Test detector has correct cost tier. (TC-126-01)"""
        detector = ToolParamSchema()
        assert detector.cost_tier == "static"


class TestToolParamSchemaShapeValidation:
    """Tests for parameter shape validation (required, type, extra fields). (TC-126-02, TC-126-03, TC-126-04)"""

    @pytest.fixture
    def detector(self) -> ToolParamSchema:
        """Create a detector instance."""
        return ToolParamSchema()

    @pytest.fixture
    def context(self) -> SessionContext:
        """Create a session context."""
        return SessionContext(session_id="test-session")

    # TC-126-02: Missing required field
    def test_tp_shape_missing_required(self, detector: ToolParamSchema, context: SessionContext) -> None:
        """Block when required param (file_path) is missing from Read tool. (TC-126-02)"""
        payload = Payload(tool="Read", params={"offset": 0})
        verdict = detector.check(payload, context)
        assert verdict.blocked, "Should block when required field is missing"
        assert "shape" in verdict.signal_id
        assert "Missing required field" in verdict.details.get("error", "")

    # TC-126-03: Type mismatch
    def test_tp_shape_wrong_type(self, detector: ToolParamSchema, context: SessionContext) -> None:
        """Block on type mismatch: file_path should be string, not int. (TC-126-03)"""
        payload = Payload(tool="Read", params={"file_path": 12345})
        verdict = detector.check(payload, context)
        assert verdict.blocked, "Should block on type mismatch"
        assert "shape" in verdict.signal_id
        assert "must be string" in verdict.details.get("error", "")

    # TC-126-04: Extra field
    def test_tp_shape_extra_field(self, detector: ToolParamSchema, context: SessionContext) -> None:
        """Block on unexpected field in parameters. (TC-126-04)"""
        payload = Payload(
            tool="Read",
            params={"file_path": "/home/file.txt", "extra_field": "should_not_be_here"},
        )
        verdict = detector.check(payload, context)
        assert verdict.blocked, "Should block on extra field"
        assert "shape" in verdict.signal_id
        assert "Unexpected field" in verdict.details.get("error", "")


class TestToolParamSchemaRiskRulesPathPattern:
    """Tests for path_pattern risk rules. (TC-126-05)"""

    @pytest.fixture
    def detector(self) -> ToolParamSchema:
        """Create a detector instance."""
        return ToolParamSchema()

    @pytest.fixture
    def context(self) -> SessionContext:
        """Create a session context."""
        return SessionContext(session_id="test-session")

    # TC-126-05: /etc/shadow pattern
    def test_tp_risk_path_pattern_shadow(self, detector: ToolParamSchema, context: SessionContext) -> None:
        """Block read of /etc/shadow. (TC-126-05)"""
        payload = Payload(tool="Read", params={"file_path": "/etc/shadow"})
        verdict = detector.check(payload, context)
        assert verdict.blocked, "Should block read of /etc/shadow"
        assert "dangerous-file" in verdict.details.get("rule_id", "")

    # TC-126-05: SSH key wildcard pattern
    def test_tp_risk_path_pattern_ssh_wildcard(self, detector: ToolParamSchema, context: SessionContext) -> None:
        """Block read of ~/.ssh/id_rsa. (TC-126-05)"""
        payload = Payload(tool="Read", params={"file_path": "~/.ssh/id_rsa"})
        verdict = detector.check(payload, context)
        assert verdict.blocked, "Should block read of SSH private key"

    # TC-126-05: /proc/*/environ pattern
    def test_tp_risk_path_pattern_proc(self, detector: ToolParamSchema, context: SessionContext) -> None:
        """Block read of /proc/*/environ. (TC-126-05)"""
        payload = Payload(tool="Read", params={"file_path": "/proc/1234/environ"})
        verdict = detector.check(payload, context)
        assert verdict.blocked, "Should block read of /proc/*/environ"


class TestToolParamSchemaRiskRulesPathWithReplaceAll:
    """Tests for path_pattern_with_replace_all risk rules. (TC-126-06)"""

    @pytest.fixture
    def detector(self) -> ToolParamSchema:
        """Create a detector instance."""
        return ToolParamSchema()

    @pytest.fixture
    def context(self) -> SessionContext:
        """Create a session context."""
        return SessionContext(session_id="test-session")

    # TC-126-06: Block with replace_all=true
    def test_tp_risk_path_with_replace_all_true(self, detector: ToolParamSchema, context: SessionContext) -> None:
        """Block Edit with replace_all=true on dangerous path. (TC-126-06)"""
        payload = Payload(
            tool="Edit",
            params={
                "file_path": "/etc/passwd",
                "old_string": "old",
                "new_string": "new",
                "replace_all": True,
            },
        )
        verdict = detector.check(payload, context)
        assert verdict.blocked, "Should block Edit with replace_all=true on /etc/passwd"
        assert "replace_all=true" in verdict.details.get("reason", "")

    # TC-126-06: Pass with replace_all=false
    def test_tn_risk_path_with_replace_all_false(self, detector: ToolParamSchema, context: SessionContext) -> None:
        """Pass Edit with replace_all=false on dangerous path. (TC-126-06)"""
        payload = Payload(
            tool="Edit",
            params={
                "file_path": "/etc/shadow",
                "old_string": "old",
                "new_string": "new",
                "replace_all": False,
            },
        )
        verdict = detector.check(payload, context)
        assert verdict.passed, "Should pass Edit with replace_all=false"

    # TC-126-06: Pass when replace_all not set
    def test_tn_risk_path_with_replace_all_absent(self, detector: ToolParamSchema, context: SessionContext) -> None:
        """Pass Edit when replace_all not set. (TC-126-06)"""
        payload = Payload(
            tool="Edit",
            params={"file_path": "/etc/shadow", "old_string": "old", "new_string": "new"},
        )
        verdict = detector.check(payload, context)
        assert verdict.passed, "Should pass when replace_all is not set"


class TestToolParamSchemaRiskRulesCommandPattern:
    """Tests for command_pattern risk rules. (TC-126-07)"""

    @pytest.fixture
    def detector(self) -> ToolParamSchema:
        """Create a detector instance."""
        return ToolParamSchema()

    @pytest.fixture
    def context(self) -> SessionContext:
        """Create a session context."""
        return SessionContext(session_id="test-session")

    # TC-126-07: Command pattern detection (Bash has no risk rules, so we just test it passes)
    def test_tn_command_pattern_normal(self, detector: ToolParamSchema, context: SessionContext) -> None:
        """Pass normal bash command. (TC-126-07)"""
        payload = Payload(tool="Bash", params={"command": "ls -la /home"})
        verdict = detector.check(payload, context)
        assert verdict.passed, "Should pass normal bash command"


class TestToolParamSchemaTextAndUnknownTools:
    """Tests for text-only payloads and unknown tools. (TC-126-08)"""

    @pytest.fixture
    def detector(self) -> ToolParamSchema:
        """Create a detector instance."""
        return ToolParamSchema()

    @pytest.fixture
    def context(self) -> SessionContext:
        """Create a session context."""
        return SessionContext(session_id="test-session")

    # TC-126-08: Text-only payload
    def test_tn_text_only_payload(self, detector: ToolParamSchema, context: SessionContext) -> None:
        """Pass when payload has no tool. (TC-126-08)"""
        payload = Payload(text="This is just text, no tool call")
        verdict = detector.check(payload, context)
        assert verdict.passed, "Should pass text-only payload"
        assert verdict.details.get("unknown_tool") is None

    # TC-126-08: Unknown tool
    def test_tn_unknown_tool(self, detector: ToolParamSchema, context: SessionContext) -> None:
        """Pass with details['unknown_tool'] = True for unknown tool. (TC-126-08)"""
        payload = Payload(tool="UnknownTool", params={"param": "value"})
        verdict = detector.check(payload, context)
        assert verdict.passed, "Should pass unknown tool"
        assert verdict.details.get("unknown_tool") is True


class TestToolParamSchemaValidParams:
    """Tests for valid parameter combinations. (TC-126-09, TC-126-11)"""

    @pytest.fixture
    def detector(self) -> ToolParamSchema:
        """Create a detector instance."""
        return ToolParamSchema()

    @pytest.fixture
    def context(self) -> SessionContext:
        """Create a session context."""
        return SessionContext(session_id="test-session")

    # TC-126-09: Valid Read call
    def test_tn_valid_read_params(self, detector: ToolParamSchema, context: SessionContext) -> None:
        """Pass clean Read tool call. (TC-126-09)"""
        payload = Payload(
            tool="Read",
            params={"file_path": "/home/user/file.txt", "offset": 0, "limit": 100},
        )
        verdict = detector.check(payload, context)
        assert verdict.passed, "Should pass valid Read parameters"

    # TC-126-09: Valid Write call
    def test_tn_valid_write_params(self, detector: ToolParamSchema, context: SessionContext) -> None:
        """Pass Write with valid params. (TC-126-09)"""
        payload = Payload(
            tool="Write",
            params={"file_path": "/tmp/safe.txt", "content": "Hello, World!"},
        )
        verdict = detector.check(payload, context)
        assert verdict.passed, "Should pass valid Write parameters"

    # TC-126-11: Read with optional offset
    def test_tn_read_with_optional_offset(self, detector: ToolParamSchema, context: SessionContext) -> None:
        """Pass Read with optional offset parameter. (TC-126-11)"""
        payload = Payload(
            tool="Read",
            params={"file_path": "/home/file.txt", "offset": 100},
        )
        verdict = detector.check(payload, context)
        assert verdict.passed, "Should pass Read with optional offset"

    # TC-126-11: Read with required params only
    def test_tn_read_without_optional(self, detector: ToolParamSchema, context: SessionContext) -> None:
        """Pass Read with required params only. (TC-126-11)"""
        payload = Payload(tool="Read", params={"file_path": "/home/file.txt"})
        verdict = detector.check(payload, context)
        assert verdict.passed, "Should pass Read with required params only"


class TestToolParamSchemaWildcardMatching:
    """Tests for wildcard matching edge cases. (TC-126-10)"""

    @pytest.fixture
    def detector(self) -> ToolParamSchema:
        """Create a detector instance."""
        return ToolParamSchema()

    @pytest.fixture
    def context(self) -> SessionContext:
        """Create a session context."""
        return SessionContext(session_id="test-session")

    # TC-126-10: Tilde expansion
    def test_tilde_expansion(self, detector: ToolParamSchema, context: SessionContext) -> None:
        """Home-dir wildcard (~/.ssh/id_*) expands correctly. (TC-126-10)"""
        payload = Payload(tool="Read", params={"file_path": "~/.ssh/id_ed25519"})
        verdict = detector.check(payload, context)
        assert verdict.blocked, "Should block SSH key with tilde expansion"

    # TC-126-10: Single-segment wildcard
    def test_wildcard_single_segment(self, detector: ToolParamSchema, context: SessionContext) -> None:
        """Wildcard /etc/* matches single-level paths only. (TC-126-10)"""
        # Should block /etc/shadow (single level)
        payload_block = Payload(tool="Write", params={"file_path": "/etc/shadow", "content": "data"})
        verdict_block = detector.check(payload_block, context)
        assert verdict_block.blocked, "Should block /etc/shadow with /etc/* pattern"

        # Should pass /etc/foo/bar (multi-level) — but only if schema supports it
        # The current schema has /etc/* which is designed to match single level only
        payload_pass = Payload(tool="Write", params={"file_path": "/etc/foo/bar", "content": "data"})
        verdict_pass = detector.check(payload_pass, context)
        # This should pass because /etc/* doesn't match multi-level paths
        assert verdict_pass.passed, "Should pass /etc/foo/bar which doesn't match /etc/* pattern"

    # TC-126-10: Suffix wildcard
    def test_wildcard_suffix(self, detector: ToolParamSchema, context: SessionContext) -> None:
        """id_* suffix matches id_rsa and id_ed25519. (TC-126-10)"""
        # id_rsa via ~/.ssh/id_rsa pattern
        payload_rsa = Payload(tool="Read", params={"file_path": "~/.ssh/id_rsa"})
        verdict_rsa = detector.check(payload_rsa, context)
        assert verdict_rsa.blocked, "Should block id_rsa with suffix pattern"

        # id_ed25519 via ~/.ssh/id_ed25519 pattern
        payload_ed = Payload(tool="Read", params={"file_path": "~/.ssh/id_ed25519"})
        verdict_ed = detector.check(payload_ed, context)
        assert verdict_ed.blocked, "Should block id_ed25519 with suffix pattern"

    # TC-126-10: /proc/*/environ pattern
    def test_wildcard_proc_pattern(self, detector: ToolParamSchema, context: SessionContext) -> None:
        """Wildcard /proc/*/environ matches numeric segments. (TC-126-10)"""
        # Should block /proc/1/environ
        payload_1 = Payload(tool="Read", params={"file_path": "/proc/1/environ"})
        verdict_1 = detector.check(payload_1, context)
        assert verdict_1.blocked, "Should block /proc/1/environ"

        # Should block /proc/123/environ
        payload_123 = Payload(tool="Read", params={"file_path": "/proc/123/environ"})
        verdict_123 = detector.check(payload_123, context)
        assert verdict_123.blocked, "Should block /proc/123/environ"

        # Should pass /proc/1/subdir/environ (different segment count)
        payload_subdir = Payload(tool="Read", params={"file_path": "/proc/1/subdir/environ"})
        verdict_subdir = detector.check(payload_subdir, context)
        assert verdict_subdir.passed, "Should pass /proc/1/subdir/environ (doesn't match /proc/*/environ)"


class TestToolParamSchemaBooleanTypeValidation:
    """Tests for boolean type validation. (TC-126-12)"""

    @pytest.fixture
    def detector(self) -> ToolParamSchema:
        """Create a detector instance."""
        return ToolParamSchema()

    @pytest.fixture
    def context(self) -> SessionContext:
        """Create a session context."""
        return SessionContext(session_id="test-session")

    # TC-126-12: replace_all wrong type
    def test_tp_replace_all_wrong_type(self, detector: ToolParamSchema, context: SessionContext) -> None:
        """Block when replace_all is not boolean. (TC-126-12)"""
        payload = Payload(
            tool="Edit",
            params={
                "file_path": "/tmp/safe.txt",
                "old_string": "a",
                "new_string": "b",
                "replace_all": "true",  # String instead of bool
            },
        )
        verdict = detector.check(payload, context)
        assert verdict.blocked, "Should block on type mismatch for replace_all"
        assert "shape" in verdict.signal_id
        assert "must be boolean" in verdict.details.get("error", "")
