"""Detector for tool-call parameter validation against per-tool schemas.

Validates that tool-call parameters conform to expected schemas and enforces
per-tool risk rules for dangerous file paths, system directories, and other
parameter-level attacks.

Schemas and risk rules are loaded from tool_schemas.json at detector initialization.
"""

import json
import logging
from importlib import resources
from pathlib import Path

from armor.types import Payload, SessionContext, Verdict

logger = logging.getLogger(__name__)


class ToolParamSchema:
    """Detector for tool-call parameter validation.

    Validates parameters against per-tool schemas (shape validation) and
    enforces risk rules (content validation) to block dangerous parameter values.

    Operates only on tool-call payloads (Payload.tool is set). Returns pass for
    text-only payloads.

    Schemas and risk rules are loaded from tool_schemas.json and frozen at init.
    """

    id: str = "tool_param.schema"
    category: str = "tool_abuse"
    cost_tier: str = "static"

    def __init__(self) -> None:
        """Initialize the detector and load tool schemas."""
        self.schemas: dict[str, object] = {}
        self._load_schemas()

    def _load_schemas(self) -> None:
        """Load tool schemas from tool_schemas.json.

        Raises:
            (Does not raise; logs error and continues with empty schemas dict.)
        """
        try:
            # Try to load from package resources (installed package)
            schema_data = resources.files("armor").joinpath("detectors/tool_schemas.json").read_text(encoding="utf-8")
        except (AttributeError, TypeError, FileNotFoundError):
            # Fallback: try to load directly from filesystem (development)
            schema_file = Path(__file__).parent / "tool_schemas.json"
            try:
                with open(schema_file, encoding="utf-8") as f:
                    schema_data = f.read()
            except FileNotFoundError:
                logger.error(f"Tool schemas file not found: {schema_file}")
                return

        # Parse JSON
        try:
            schemas_dict = json.loads(schema_data)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse tool_schemas.json: {e}")
            return

        # Validate structure: expect {"tools": {...}}
        if not isinstance(schemas_dict, dict) or "tools" not in schemas_dict:
            logger.error("tool_schemas.json must have a 'tools' key")
            return

        tools = schemas_dict.get("tools")
        if not isinstance(tools, dict):
            logger.error("tool_schemas.json 'tools' value must be a dict")
            return

        self.schemas = tools

    def check(self, payload: Payload, ctx: SessionContext) -> Verdict:
        """Check a tool-call payload against schemas and risk rules.

        Args:
            payload: The payload being checked (should have tool and params).
            ctx: Session context (unused for static detector).

        Returns:
            Block verdict if validation fails or risk rule matches.
            Pass verdict if validation passes and no risk rules match.
            Pass with unknown_tool=True if tool is not in the schema.
        """
        try:
            # Only check tool-call payloads
            if payload.tool is None:
                return Verdict.pass_verdict()

            # Check for unknown tool
            if payload.tool not in self.schemas:
                return Verdict.pass_verdict(message="Tool not in schema registry", details={"unknown_tool": True})

            tool_name = payload.tool
            tool_spec = self.schemas[tool_name]

            # Ensure tool_spec is a dict with params_schema and risk_rules
            if not isinstance(tool_spec, dict):
                return Verdict.error_verdict(
                    reason=f"Tool spec for {tool_name} is malformed", details={"tool": tool_name}
                )

            params_schema = tool_spec.get("params_schema", {})
            risk_rules = tool_spec.get("risk_rules", [])

            # Step 1: Shape validation
            shape_error = self._validate_shape(payload.params, params_schema, tool_name)
            if shape_error:
                return Verdict.block_verdict(
                    signal_id=f"{self.id}:{tool_name}:shape",
                    message="Input blocked by armor.",
                    severity="high",
                    details={"error": shape_error, "tool": tool_name},
                )

            # Step 2: Risk rule validation
            if isinstance(risk_rules, list):
                for rule in risk_rules:
                    if not isinstance(rule, dict):
                        continue
                    rule_id = rule.get("id", "unknown")
                    rule_match = self._check_risk_rule(rule, payload.params, tool_name)
                    if rule_match:
                        return Verdict.block_verdict(
                            signal_id=f"{self.id}:{tool_name}:{rule_id}",
                            message="Input blocked by armor.",
                            severity="high",
                            details={"tool": tool_name, "rule_id": rule_id, "reason": rule_match},
                        )

            return Verdict.pass_verdict()

        except Exception as e:
            return Verdict.error_verdict(
                reason=f"Detector error: {e!s}", details={"detector_id": self.id, "error": str(e)}
            )

    @staticmethod
    def _validate_shape(params: dict[str, object] | None, params_schema: object, tool_name: str) -> str | None:
        """Validate parameter shape against schema.

        Args:
            params: The parameter dict from the payload.
            params_schema: The schema dict with field definitions.
            tool_name: Tool name (for error messages).

        Returns:
            Error message if validation fails, None if validation passes.
        """
        if not isinstance(params_schema, dict):
            return f"Invalid schema for {tool_name}"

        if params is None:
            params_dict: dict[str, object] = {}
        else:
            params_dict = params

        # Check required fields
        for field_name, field_spec in params_schema.items():
            if not isinstance(field_spec, dict):
                continue

            is_required = field_spec.get("required", False)
            if is_required and field_name not in params_dict:
                return f"Missing required field: {field_name}"

        # Check field types and disallow extra fields
        for field_name, field_value in params_dict.items():
            if field_name not in params_schema:
                return f"Unexpected field: {field_name}"

            field_spec = params_schema[field_name]
            if not isinstance(field_spec, dict):
                continue

            expected_type = field_spec.get("type", "string")

            # Type check
            if expected_type == "string" and not isinstance(field_value, str):
                return f"Field {field_name} must be string, got {type(field_value).__name__}"
            elif expected_type == "integer" and not isinstance(field_value, int):
                return f"Field {field_name} must be integer, got {type(field_value).__name__}"
            elif expected_type == "boolean" and not isinstance(field_value, bool):
                return f"Field {field_name} must be boolean, got {type(field_value).__name__}"

        return None

    @staticmethod
    def _check_risk_rule(rule: dict[str, object], params: dict[str, object] | None, tool_name: str) -> str | None:
        """Check if a parameter matches a risk rule.

        Args:
            rule: The risk rule dict.
            params: The parameter dict.
            tool_name: Tool name (for error messages).

        Returns:
            Description of the match if rule matches, None otherwise.
        """
        if params is None:
            params = {}

        rule_type = rule.get("type", "")
        patterns = rule.get("patterns", [])

        if not isinstance(patterns, list):
            return None

        if rule_type == "path_pattern":
            return ToolParamSchema._match_path_pattern(params, patterns)
        elif rule_type == "path_pattern_with_replace_all":
            return ToolParamSchema._match_path_pattern_with_replace_all(params, patterns)
        elif rule_type == "command_pattern":
            return ToolParamSchema._match_command_pattern(params, patterns)

        return None

    @staticmethod
    def _match_path_pattern(params: dict[str, object], patterns: list[object]) -> str | None:
        """Match file_path parameter against path patterns.

        Supports literal patterns and wildcards:
        - `/etc/shadow` matches exactly `/etc/shadow`
        - `/etc/*` matches any file under `/etc/`
        - `~/.ssh/id_*` matches any file matching the pattern under `~/.ssh/`

        Args:
            params: Parameter dict (may have file_path key).
            patterns: List of patterns to match against.

        Returns:
            Description if match found, None otherwise.
        """
        file_path = params.get("file_path")
        if not isinstance(file_path, str):
            return None

        # Expand ~ for matching
        expanded_path = file_path.replace("~", "/home/*")

        for pattern in patterns:
            if not isinstance(pattern, str):
                continue

            expanded_pattern = pattern.replace("~", "/home/*")

            # Simple wildcard matching
            if ToolParamSchema._wildcard_match(expanded_path, expanded_pattern):
                return f"Dangerous file path matches pattern: {pattern}"

        return None

    @staticmethod
    def _match_path_pattern_with_replace_all(params: dict[str, object], patterns: list[object]) -> str | None:
        """Match file_path parameter with replace_all consideration.

        For Edit tool: block if replace_all=true and path matches pattern.

        Args:
            params: Parameter dict.
            patterns: List of patterns to match against.

        Returns:
            Description if match found, None otherwise.
        """
        file_path = params.get("file_path")
        replace_all = params.get("replace_all", False)

        if not isinstance(file_path, str):
            return None

        # Only block if replace_all is True
        if not replace_all:
            return None

        # Expand ~ for matching
        expanded_path = file_path.replace("~", "/home/*")

        for pattern in patterns:
            if not isinstance(pattern, str):
                continue

            expanded_pattern = pattern.replace("~", "/home/*")

            # Simple wildcard matching
            if ToolParamSchema._wildcard_match(expanded_path, expanded_pattern):
                return f"Dangerous file path with replace_all=true matches pattern: {pattern}"

        return None

    @staticmethod
    def _match_command_pattern(params: dict[str, object], patterns: list[object]) -> str | None:
        """Match command parameter against command patterns.

        Args:
            params: Parameter dict (may have command key).
            patterns: List of literal strings to search for in command.

        Returns:
            Description if match found, None otherwise.
        """
        command = params.get("command")
        if not isinstance(command, str):
            return None

        for pattern in patterns:
            if not isinstance(pattern, str):
                continue

            if pattern in command:
                return f"Dangerous command pattern detected: {pattern}"

        return None

    @staticmethod
    def _wildcard_match(text: str, pattern: str) -> bool:
        """Simple wildcard matching for patterns like /etc/* or ~/.ssh/id_*.

        Supports:
        - `*` matches any sequence of characters except `/`
        - `/*/` and similar match any directory level

        Args:
            text: The text to match.
            pattern: The pattern to match against.

        Returns:
            True if text matches pattern, False otherwise.
        """
        # Convert pattern to a simple wildcard matcher
        # This is a minimal implementation; does not use full glob semantics

        # Handle exact match first
        if text == pattern:
            return True

        # Handle simple wildcard: /etc/* matches /etc/anything
        if pattern.endswith("/*"):
            prefix = pattern[:-2]
            if text.startswith(prefix + "/"):
                # Ensure no further slashes (i.e., /etc/* matches /etc/shadow, not /etc/sub/shadow)
                remainder = text[len(prefix) + 1 :]
                if "/" not in remainder:
                    return True

        # Handle wildcard in middle: /proc/*/environ matches /proc/1/environ, /proc/2/environ
        if "*" in pattern and "/" in pattern:
            # Simple segment-by-segment matching
            pattern_parts = pattern.split("/")
            text_parts = text.split("/")

            if len(pattern_parts) != len(text_parts):
                return False

            for pattern_part, text_part in zip(pattern_parts, text_parts, strict=False):
                if pattern_part == "*":
                    continue
                elif pattern_part.startswith("*"):
                    # Suffix match: id_* matches id_rsa, id_ed25519
                    suffix = pattern_part[1:]
                    if not text_part.endswith(suffix):
                        return False
                elif pattern_part.endswith("*"):
                    # Prefix match
                    prefix = pattern_part[:-1]
                    if not text_part.startswith(prefix):
                        return False
                elif pattern_part != text_part:
                    return False

            return True

        # Prefix match: /etc/* prefix
        if pattern.endswith("*") and not pattern.endswith("/*"):
            prefix = pattern[:-1]
            return text.startswith(prefix)

        return False
