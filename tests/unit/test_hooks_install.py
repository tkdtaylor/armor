"""Unit tests for the hooks installer."""

import json
import os
import tempfile

from armor.cli import _install_hooks


class TestHooksInstaller:
    """Tests for the hooks installer function."""

    def test_install_hooks_creates_file_with_hooks(self) -> None:
        """Test that install_hooks creates a file with all four hooks."""
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
            assert len(hooks) == 4

            # Verify all four hooks are present
            hook_names = {h["name"] for h in hooks}
            assert hook_names == {
                "armor-check-input",
                "armor-check-output",
                "armor-check-tool",
                "armor-session-close",
            }

            # Verify hooks have correct structure
            for hook in hooks:
                assert "name" in hook
                assert "event" in hook
                assert "handler" in hook

    def test_install_hooks_adds_to_existing_hooks(self) -> None:
        """Test that install_hooks adds armor hooks to existing hooks."""
        with tempfile.TemporaryDirectory() as tmpdir:
            settings_path = os.path.join(tmpdir, "settings.json")

            # Create existing settings with a different hook
            existing_data = {
                "hooks": [
                    {
                        "name": "existing-hook",
                        "event": "CustomEvent",
                        "handler": "existing command",
                    }
                ]
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
            assert len(hooks) == 5

            hook_names = {h["name"] for h in hooks}
            assert "existing-hook" in hook_names
            assert "armor-check-input" in hook_names

    def test_install_hooks_idempotent_no_duplicates(self) -> None:
        """Test that running install twice doesn't create duplicates."""
        with tempfile.TemporaryDirectory() as tmpdir:
            settings_path = os.path.join(tmpdir, "settings.json")

            # First install
            result1 = _install_hooks(settings_path)
            assert result1 == 0

            # Get first count
            with open(settings_path) as f:
                data1 = json.load(f)
            first_count = len(data1["hooks"])

            # Second install
            result2 = _install_hooks(settings_path)
            assert result2 == 0

            # Verify no new hooks added
            with open(settings_path) as f:
                data2 = json.load(f)
            second_count = len(data2["hooks"])

            assert first_count == second_count == 4

    def test_install_hooks_updates_existing_armor_hooks(self) -> None:
        """Test that re-installing updates existing armor hooks."""
        with tempfile.TemporaryDirectory() as tmpdir:
            settings_path = os.path.join(tmpdir, "settings.json")

            # Create settings with old armor hook (different handler)
            old_data = {
                "hooks": [
                    {
                        "name": "armor-check-input",
                        "event": "UserPromptSubmit",
                        "handler": "old command",
                    }
                ]
            }

            with open(settings_path, "w") as f:
                json.dump(old_data, f)

            # Install (should replace)
            result = _install_hooks(settings_path)
            assert result == 0

            # Verify hook was replaced with new handler
            with open(settings_path) as f:
                data = json.load(f)

            armor_input_hooks = [h for h in data["hooks"] if h["name"] == "armor-check-input"]
            assert len(armor_input_hooks) == 1
            assert "old command" not in armor_input_hooks[0]["handler"]
            assert "--hook-mode" in armor_input_hooks[0]["handler"]

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
                "hooks": [],
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
            assert len(data["hooks"]) == 4

    def test_install_hooks_hook_handlers_have_hook_mode(self) -> None:
        """Test that installed hook handlers include --hook-mode flag."""
        with tempfile.TemporaryDirectory() as tmpdir:
            settings_path = os.path.join(tmpdir, "settings.json")

            result = _install_hooks(settings_path)
            assert result == 0

            with open(settings_path) as f:
                data = json.load(f)

            # Find check input hook
            input_hook = next(h for h in data["hooks"] if h["name"] == "armor-check-input")
            assert "--hook-mode" in input_hook["handler"]
            assert "armor check input" in input_hook["handler"]
            assert "--session-id" in input_hook["handler"]
            assert "$CLAUDE_SESSION_ID" in input_hook["handler"]

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
        """Test that hooks have correct event mappings per spec."""
        with tempfile.TemporaryDirectory() as tmpdir:
            settings_path = os.path.join(tmpdir, "settings.json")

            result = _install_hooks(settings_path)
            assert result == 0

            with open(settings_path) as f:
                data = json.load(f)

            hooks_by_name = {h["name"]: h for h in data["hooks"]}

            # Verify event mappings per spec
            assert hooks_by_name["armor-check-input"]["event"] == "UserPromptSubmit"
            assert hooks_by_name["armor-check-output"]["event"] == "PreToolUse"
            assert hooks_by_name["armor-check-tool"]["event"] == "PostToolUse"
            assert hooks_by_name["armor-session-close"]["event"] == "Stop"
