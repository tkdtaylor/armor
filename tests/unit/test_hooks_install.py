"""Unit tests for the hooks installer."""

import json
import os
import shutil
import tempfile

from armor.cli import _install_hooks


class TestHooksInstaller:
    """Tests for the hooks installer function."""

    def test_install_hooks_creates_file_with_hooks(self) -> None:
        """Test that install_hooks creates a file with five hooks (PostToolUse split into two matchers)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            settings_path = os.path.join(tmpdir, "settings.json")

            result = _install_hooks(settings_path)
            assert result == 0

            # Verify file exists
            assert os.path.exists(settings_path)

            # Load and verify content
            with open(settings_path) as f:
                data = json.load(f)

            assert "hooks" in data
            hooks = data["hooks"]
            # Should have 5 hooks: UserPromptSubmit, PreToolUse, PostToolUse (2), Stop
            assert isinstance(hooks, dict), "hooks should be a dict organized by event"
            assert set(hooks.keys()) == {"UserPromptSubmit", "PreToolUse", "PostToolUse", "Stop"}

            # PostToolUse should have 2 entries (one with matcher, one without)
            assert len(hooks["PostToolUse"]) == 2

    def test_install_hooks_adds_to_existing_hooks(self) -> None:
        """Test that install_hooks handles existing non-armor hooks."""
        with tempfile.TemporaryDirectory() as tmpdir:
            settings_path = os.path.join(tmpdir, "settings.json")

            # Create existing settings with a different hook event
            existing_data = {
                "hooks": {"CustomEvent": [{"hooks": [{"type": "command", "command": "existing command"}]}]}
            }

            with open(settings_path, "w") as f:
                json.dump(existing_data, f)

            # Run installer
            result = _install_hooks(settings_path)
            assert result == 0

            # Verify both hooks exist
            with open(settings_path) as f:
                data = json.load(f)

            hooks = data["hooks"]
            assert "CustomEvent" in hooks
            user_prompt_cmd = hooks["UserPromptSubmit"][0]["hooks"][0]["command"]
            assert "armor check input" in user_prompt_cmd

    def test_install_hooks_idempotent_no_duplicates(self) -> None:
        """Test that running install twice doesn't create duplicates."""
        with tempfile.TemporaryDirectory() as tmpdir:
            settings_path = os.path.join(tmpdir, "settings.json")

            # First install
            result1 = _install_hooks(settings_path)
            assert result1 == 0

            # Get first content
            with open(settings_path) as f:
                data1 = json.load(f)
            first_content = json.dumps(data1, sort_keys=True)

            # Second install
            result2 = _install_hooks(settings_path)
            assert result2 == 0

            # Verify identical
            with open(settings_path) as f:
                data2 = json.load(f)
            second_content = json.dumps(data2, sort_keys=True)

            assert first_content == second_content

    def test_install_hooks_updates_existing_armor_hooks(self) -> None:
        """Test that re-installing updates existing armor hooks."""
        with tempfile.TemporaryDirectory() as tmpdir:
            settings_path = os.path.join(tmpdir, "settings.json")

            # Create settings with old-format armor hook
            old_data = {
                "hooks": {
                    "UserPromptSubmit": [
                        {
                            "hooks": [
                                {
                                    "type": "command",
                                    "command": "old command",
                                }
                            ]
                        }
                    ]
                }
            }

            with open(settings_path, "w") as f:
                json.dump(old_data, f)

            # Install (should replace)
            result = _install_hooks(settings_path)
            assert result == 0

            # Verify hook was replaced with new handler
            with open(settings_path) as f:
                data = json.load(f)

            user_prompt_hooks = data["hooks"]["UserPromptSubmit"]
            hook_cmd = user_prompt_hooks[0]["hooks"][0]["command"]
            assert "armor check input" in hook_cmd
            assert "--hook-mode" in hook_cmd

    def test_install_hooks_creates_parent_directory_not_needed(self) -> None:
        """Test that install_hooks works with existing directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            settings_path = os.path.join(tmpdir, "nested", "settings.json")
            # Create parent directory
            os.makedirs(os.path.dirname(settings_path), exist_ok=True)

            result = _install_hooks(settings_path)
            assert result == 0
            assert os.path.exists(settings_path)

    def test_install_hooks_default_path(self) -> None:
        """Test that install_hooks uses default path when None provided."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Change to temp directory so relative path works
            old_cwd = os.getcwd()
            try:
                os.chdir(tmpdir)
                # Create the .claude directory
                os.makedirs(".claude", exist_ok=True)

                result = _install_hooks(None)
                assert result == 0

                # Verify file created at default location
                assert os.path.exists("./.claude/settings.json")

                with open("./.claude/settings.json") as f:
                    data = json.load(f)
                assert "hooks" in data
            finally:
                os.chdir(old_cwd)

    def test_install_hooks_preserves_other_settings(self) -> None:
        """Test that install_hooks preserves non-hook settings."""
        with tempfile.TemporaryDirectory() as tmpdir:
            settings_path = os.path.join(tmpdir, "settings.json")

            # Create settings with other config
            existing_data = {
                "hooks": {},
                "other_setting": "value",
                "nested": {"key": "value"},
            }

            with open(settings_path, "w") as f:
                json.dump(existing_data, f)

            # Install hooks
            result = _install_hooks(settings_path)
            assert result == 0

            # Verify other settings preserved
            with open(settings_path) as f:
                data = json.load(f)

            assert data["other_setting"] == "value"
            assert data["nested"]["key"] == "value"
            assert "hooks" in data

    def test_install_hooks_hook_handlers_have_hook_mode(self) -> None:
        """Test that installed hook handlers include --hook-mode flag."""
        with tempfile.TemporaryDirectory() as tmpdir:
            settings_path = os.path.join(tmpdir, "settings.json")

            result = _install_hooks(settings_path)
            assert result == 0

            with open(settings_path) as f:
                data = json.load(f)

            # Find check input hook
            user_prompt_hooks = data["hooks"]["UserPromptSubmit"]
            hook_cmd = user_prompt_hooks[0]["hooks"][0]["command"]
            assert "--hook-mode" in hook_cmd
            assert "armor check input" in hook_cmd
            assert "--session-id" in hook_cmd

    def test_install_hooks_malformed_json_error(self) -> None:
        """Test that install_hooks returns error on malformed JSON."""
        with tempfile.TemporaryDirectory() as tmpdir:
            settings_path = os.path.join(tmpdir, "settings.json")

            # Create malformed JSON
            with open(settings_path, "w") as f:
                f.write("{invalid json")

            result = _install_hooks(settings_path)
            assert result == 1

    def test_install_hooks_preserves_malformed_file(self) -> None:
        """Test that install_hooks doesn't overwrite malformed file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            settings_path = os.path.join(tmpdir, "settings.json")

            # Create malformed JSON
            original_content = "{invalid json"
            with open(settings_path, "w") as f:
                f.write(original_content)

            # Try to install
            result = _install_hooks(settings_path)
            assert result == 1

            # Verify file content unchanged
            with open(settings_path) as f:
                content = f.read()
            assert content == original_content

    def test_install_hooks_event_mappings(self) -> None:
        """TC-096-01: hooks have correct event mappings per spec (B-017)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            settings_path = os.path.join(tmpdir, "settings.json")

            result = _install_hooks(settings_path)
            assert result == 0

            with open(settings_path) as f:
                data = json.load(f)

            hooks = data["hooks"]

            # Verify event structure
            assert "UserPromptSubmit" in hooks
            assert "PreToolUse" in hooks
            assert "PostToolUse" in hooks
            assert "Stop" in hooks

            # Verify UserPromptSubmit has "armor check input"
            user_prompt_cmd = hooks["UserPromptSubmit"][0]["hooks"][0]["command"]
            assert "armor check input" in user_prompt_cmd

            # Verify PreToolUse has "armor check tool"
            pre_tool_cmd = hooks["PreToolUse"][0]["hooks"][0]["command"]
            assert "armor check tool" in pre_tool_cmd

            # Verify PostToolUse has two entries
            assert len(hooks["PostToolUse"]) == 2

            # Verify Stop has "armor session close"
            stop_cmd = hooks["Stop"][0]["hooks"][0]["command"]
            assert "armor session close" in stop_cmd

    def test_install_hooks_commands_resolve_to_armor_cli(self) -> None:
        """TC-096-01: installed hook commands resolve to the armor CLI."""
        with tempfile.TemporaryDirectory() as tmpdir:
            settings_path = os.path.join(tmpdir, "settings.json")

            result = _install_hooks(settings_path)
            assert result == 0

            with open(settings_path) as f:
                data = json.load(f)

            assert shutil.which("armor") or shutil.which("uv"), "neither armor nor uv is available on PATH"
            for entries in data["hooks"].values():
                for entry in entries:
                    for hook in entry["hooks"]:
                        command = hook["command"]
                        assert command.startswith("armor "), command
                        if "check fetched" in command:
                            assert "--hook-mode" in command
