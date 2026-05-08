"""Detector for Bash command injection via denylist patterns.

Detects Bash tool calls that match known dangerous patterns:
- Filesystem destruction (rm -rf /, fork bombs, etc.)
- Credential file reads (/etc/shadow, SSH keys, etc.)
- Container escape attempts (mount cgroup, nsenter, etc.)
- Privilege escalation (sudo -i with stdin, chmod u+s, chmod 777, etc.)
- Persistence (chown root, passwd root, crontab -e, etc.)

Patterns are loaded from cmd_injection_patterns.yaml at detector initialization.
"""

import re
from importlib import resources
from pathlib import Path

import yaml

from armor.types import Payload, SessionContext, Verdict

# Type alias for pattern dict
PatternDict = dict[str, object]


class CmdInjectionBash:
    """Detects Bash command-injection patterns matching a denylist.

    Operates only on Payload.tool == "Bash". Returns pass for other tools.
    Patterns are loaded from cmd_injection_patterns.yaml and compiled at init.
    Supports five pattern families: filesystem_destruction, credential_read,
    container_escape, privilege_escalation, and persistence.
    """

    id: str = "cmd_injection.bash"
    category: str = "tool_abuse"
    cost_tier: str = "static"

    # Compiled patterns — shared across all instances
    _patterns: list[PatternDict] | None = None

    def __init__(self) -> None:
        """Initialize the detector and load patterns."""
        # Lazy-load patterns on first instantiation
        if CmdInjectionBash._patterns is None:
            CmdInjectionBash._patterns = self._load_patterns()
        self.patterns = CmdInjectionBash._patterns

    @staticmethod
    def _load_patterns() -> list[PatternDict]:
        """Load and parse patterns from cmd_injection_patterns.yaml.

        Returns:
            List of pattern dicts with 'id', 'pattern' (compiled regex), 'family',
            'severity', and 'description' keys.

        Raises:
            FileNotFoundError: If pattern file is not found.
            ValueError: If pattern file is malformed or pattern regex is invalid.
        """
        # Load the YAML pattern file
        try:
            # Try to load from the package resources (installed package)
            pattern_data = resources.files("armor").joinpath("detectors/cmd_injection_patterns.yaml").read_text()
        except (AttributeError, TypeError, FileNotFoundError):
            # Fallback: try to load directly from filesystem (development)
            pattern_file = Path(__file__).parent / "cmd_injection_patterns.yaml"
            try:
                with open(pattern_file) as f:
                    pattern_data = f.read()
            except FileNotFoundError as e:
                raise FileNotFoundError(f"Pattern file not found: {pattern_file}") from e

        # Parse YAML
        try:
            patterns_raw = yaml.safe_load(pattern_data)
        except yaml.YAMLError as e:
            raise ValueError(f"Malformed YAML in cmd_injection_patterns.yaml: {e}") from e

        if not isinstance(patterns_raw, list):
            raise ValueError("Pattern file must be a YAML list of pattern dicts")

        # Compile patterns and validate schema
        patterns: list[PatternDict] = []
        for idx, pattern_dict in enumerate(patterns_raw):
            if not isinstance(pattern_dict, dict):
                raise ValueError(f"Pattern {idx} is not a dict: {type(pattern_dict)}")

            # Validate required keys
            required_keys = ["id", "pattern", "family", "severity", "description"]
            for key in required_keys:
                if key not in pattern_dict:
                    raise ValueError(f"Pattern {idx} missing required key '{key}': {pattern_dict}")

            pattern_id = pattern_dict["id"]
            pattern_str = pattern_dict["pattern"]
            family = pattern_dict["family"]
            severity = pattern_dict["severity"]
            description = pattern_dict["description"]

            # Validate family
            valid_families = [
                "filesystem_destruction",
                "credential_read",
                "container_escape",
                "privilege_escalation",
                "persistence",
            ]
            if family not in valid_families:
                raise ValueError(
                    f"Pattern {pattern_id} has invalid family '{family}', expected one of {valid_families}"
                )

            # Compile regex pattern
            try:
                compiled_pattern = re.compile(pattern_str, re.MULTILINE | re.IGNORECASE)
            except re.error as e:
                raise ValueError(f"Pattern {pattern_id} has invalid regex: {e}") from e

            patterns.append(
                {
                    "id": pattern_id,
                    "compiled_pattern": compiled_pattern,
                    "family": family,
                    "severity": severity,
                    "description": description,
                }
            )

        if not patterns:
            raise ValueError("Pattern file is empty")

        return patterns

    def check(self, payload: Payload, ctx: SessionContext) -> Verdict:
        """Check a Bash command against the denylist.

        Args:
            payload: The payload being checked (should have tool="Bash", params["command"]).
            ctx: Session context (unused for static detector).

        Returns:
            Block verdict if command matches a pattern, pass otherwise.
            Returns pass if tool is not Bash, or command is missing/empty.
        """
        try:
            # Only check Bash tool calls
            if payload.tool != "Bash":
                return Verdict.pass_verdict()

            # Extract command from params
            if not payload.params:
                return Verdict.pass_verdict()

            command = payload.params.get("command", "")
            if not isinstance(command, str) or not command:
                return Verdict.pass_verdict()

            # Test against each pattern
            for pattern_dict in self.patterns:
                compiled_pattern = pattern_dict["compiled_pattern"]
                assert isinstance(compiled_pattern, re.Pattern)
                match = compiled_pattern.search(command)
                if match:
                    pattern_id = pattern_dict["id"]
                    signal_id = f"{self.id}:{pattern_id}"
                    severity = pattern_dict["severity"]
                    description = pattern_dict["description"]

                    return Verdict.block_verdict(
                        signal_id=signal_id,
                        message="Input blocked by armor.",
                        severity=severity,  # type: ignore
                        details={
                            "pattern_id": pattern_id,
                            "family": pattern_dict["family"],
                            "description": description,
                            "matched_offset": match.start(),
                            "matched_length": match.end() - match.start(),
                        },
                    )

            return Verdict.pass_verdict()

        except Exception as e:
            return Verdict.error_verdict(
                reason=f"Detector error: {e!s}",
                details={"detector_id": self.id, "error": str(e)},
            )
