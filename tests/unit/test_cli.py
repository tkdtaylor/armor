"""Unit tests for the armor CLI."""

import json
import tempfile
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from armor.cli import _install_hooks, main


class TestHealthCommand:
    """Tests for the health subcommand."""

    def test_health_daemon_not_running(self) -> None:
        """Test health check when daemon is not running."""
        output = StringIO()
        with patch("sys.stdout", output):
            exit_code = main(["health", "--json"])

        assert exit_code == 2  # Critical when daemon unreachable
        data = json.loads(output.getvalue().strip())
        assert data["status"] == "unreachable"

    def test_health_with_custom_socket_path(self) -> None:
        """Test health check with custom socket path."""
        output = StringIO()
        with patch("sys.stdout", output):
            exit_code = main(["--socket", "/tmp/nonexistent.sock", "health", "--json"])

        assert exit_code == 2  # Critical when daemon unreachable
        data = json.loads(output.getvalue().strip())
        assert data["status"] == "unreachable"


class TestHooksInstall:
    """Tests for the hooks install functionality."""

    def test_pretooluse_mapping(self) -> None:
        """TC-079-01: PreToolUse maps to 'armor check tool'."""
        with tempfile.TemporaryDirectory() as tmpdir:
            settings_path = Path(tmpdir) / "settings.json"

            # Call _install_hooks
            exit_code = _install_hooks(str(settings_path))
            assert exit_code == 0

            # Parse the written file
            with open(settings_path) as f:
                settings = json.load(f)

            # Verify PreToolUse hook
            assert "hooks" in settings
            assert "PreToolUse" in settings["hooks"]
            pre_tool_hooks = settings["hooks"]["PreToolUse"]
            assert len(pre_tool_hooks) > 0

            # The hook should contain armor check tool command
            hook_cmd = pre_tool_hooks[0]["hooks"][0]["command"]
            assert "armor check tool" in hook_cmd
            assert "armor check output" not in hook_cmd

    def test_posttooluse_generic_matcher(self) -> None:
        """TC-079-02: PostToolUse generic matcher runs 'armor check output'."""
        with tempfile.TemporaryDirectory() as tmpdir:
            settings_path = Path(tmpdir) / "settings.json"

            # Call _install_hooks
            exit_code = _install_hooks(str(settings_path))
            assert exit_code == 0

            # Parse the written file
            with open(settings_path) as f:
                settings = json.load(f)

            # Verify PostToolUse hooks
            assert "hooks" in settings
            assert "PostToolUse" in settings["hooks"]
            post_tool_hooks = settings["hooks"]["PostToolUse"]

            # Should have at least 2 PostToolUse entries
            assert len(post_tool_hooks) >= 2, f"Expected >= 2 PostToolUse entries, got {len(post_tool_hooks)}"

            # Find the generic matcher entry (no matcher or matcher "*")
            generic_entry = None
            for entry in post_tool_hooks:
                if "matcher" not in entry or entry.get("matcher") == "*":
                    generic_entry = entry
                    break

            assert generic_entry is not None, "No generic PostToolUse entry found"
            hook_cmd = generic_entry["hooks"][0]["command"]
            assert "armor check output" in hook_cmd

    def test_posttooluse_read_tool_matcher(self) -> None:
        """TC-079-03: PostToolUse with read-tool matcher runs 'armor check fetched'."""
        with tempfile.TemporaryDirectory() as tmpdir:
            settings_path = Path(tmpdir) / "settings.json"

            # Call _install_hooks
            exit_code = _install_hooks(str(settings_path))
            assert exit_code == 0

            # Parse the written file
            with open(settings_path) as f:
                settings = json.load(f)

            # Verify PostToolUse hooks
            assert "hooks" in settings
            assert "PostToolUse" in settings["hooks"]
            post_tool_hooks = settings["hooks"]["PostToolUse"]

            # Find the read-tool matcher entry
            read_entry = None
            for entry in post_tool_hooks:
                matcher = entry.get("matcher")
                if matcher and "Read" in matcher and "WebFetch" in matcher:
                    read_entry = entry
                    break

            assert read_entry is not None, "No read-tool PostToolUse entry found"
            assert "matcher" in read_entry

            # Check matcher contains expected pattern
            matcher = read_entry["matcher"]
            assert "Read" in matcher
            assert "WebFetch" in matcher
            assert "Grep" in matcher
            assert "Glob" in matcher
            assert "mcp__" in matcher

            # Check command
            hook_cmd = read_entry["hooks"][0]["command"]
            assert "armor check fetched" in hook_cmd

    def test_userpromptsubmit_and_stop_unchanged(self) -> None:
        """TC-079-04: UserPromptSubmit and Stop hooks are correct."""
        with tempfile.TemporaryDirectory() as tmpdir:
            settings_path = Path(tmpdir) / "settings.json"

            # Call _install_hooks
            exit_code = _install_hooks(str(settings_path))
            assert exit_code == 0

            # Parse the written file
            with open(settings_path) as f:
                settings = json.load(f)

            # Verify UserPromptSubmit
            assert "hooks" in settings
            assert "UserPromptSubmit" in settings["hooks"]
            user_hooks = settings["hooks"]["UserPromptSubmit"]
            assert len(user_hooks) > 0
            user_cmd = user_hooks[0]["hooks"][0]["command"]
            assert "armor check input" in user_cmd

            # Verify Stop
            assert "Stop" in settings["hooks"]
            stop_hooks = settings["hooks"]["Stop"]
            assert len(stop_hooks) > 0
            stop_cmd = stop_hooks[0]["hooks"][0]["command"]
            assert "armor session close" in stop_cmd

    def test_example_file_parity(self) -> None:
        """TC-079-05: Example file structural equivalence to install output."""
        # Read the example file
        repo_root = Path(__file__).resolve().parents[2]
        example_path = repo_root / "examples/claude_code/settings.json"
        with open(example_path) as f:
            example_settings = json.load(f)

        with tempfile.TemporaryDirectory() as tmpdir:
            settings_path = Path(tmpdir) / "settings.json"

            # Call _install_hooks
            exit_code = _install_hooks(str(settings_path))
            assert exit_code == 0

            # Parse the written file
            with open(settings_path) as f:
                installed_settings = json.load(f)

            # Extract event names and matcher tuples from both
            def get_hooks_signature(settings: dict) -> set:
                """Return set of (event, matcher, command_stem) tuples."""
                sig = set()
                for event, hooks_list in settings["hooks"].items():
                    for hook_config in hooks_list:
                        matcher = hook_config.get("matcher")
                        for hook_def in hook_config["hooks"]:
                            cmd = hook_def["command"]
                            # Extract the armor check subcommand (input/tool/output/fetched/etc)
                            command_stem = ""
                            if "armor check input" in cmd:
                                command_stem = "check input"
                            elif "armor check tool" in cmd:
                                command_stem = "check tool"
                            elif "armor check output" in cmd:
                                command_stem = "check output"
                            elif "armor check fetched" in cmd:
                                command_stem = "check fetched"
                            elif "armor session close" in cmd:
                                command_stem = "session close"
                            sig.add((event, matcher, command_stem))
                return sig

            example_sig = get_hooks_signature(example_settings)
            installed_sig = get_hooks_signature(installed_settings)

            # Both should have the same event/matcher/command structure
            assert example_sig == installed_sig, f"Example: {example_sig} vs Installed: {installed_sig}"

    def test_idempotent_install(self) -> None:
        """TC-079-06: Running install twice produces the same file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            settings_path = Path(tmpdir) / "settings.json"

            # First install
            exit_code1 = _install_hooks(str(settings_path))
            assert exit_code1 == 0
            with open(settings_path) as f:
                first_install = json.load(f)

            # Second install
            exit_code2 = _install_hooks(str(settings_path))
            assert exit_code2 == 0
            with open(settings_path) as f:
                second_install = json.load(f)

            # Should be identical
            assert first_install == second_install
