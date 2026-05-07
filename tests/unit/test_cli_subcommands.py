"""Unit tests for CLI subcommands."""

import json
import os
import tempfile
from io import StringIO
from unittest.mock import Mock, patch

import pytest

from armor.cli import main
from armor.client import DaemonUnreachableError


class TestCheckInputCommand:
    """Tests for 'armor check input' command."""

    def test_check_input_benign_pass(self) -> None:
        """Test benign input returns exit 0."""
        mock_response = {"v": 1, "verdict": "pass", "signal_id": None, "message": ""}

        with patch("armor.cli.DaemonClient") as mock_client_class:
            mock_client = Mock()
            mock_client_class.return_value = mock_client
            mock_client.request.return_value = mock_response

            exit_code = main(["check", "input", "hello world"])
            assert exit_code == 0
            mock_client.request.assert_called_once()

    def test_check_input_blocking_exit_100(self) -> None:
        """Test blocking input returns exit 100."""
        mock_response = {
            "v": 1,
            "verdict": "block",
            "signal_id": "regex:override-001",
            "message": "Instruction override pattern detected",
        }

        with patch("armor.cli.DaemonClient") as mock_client_class:
            mock_client = Mock()
            mock_client_class.return_value = mock_client
            mock_client.request.return_value = mock_response

            with patch("sys.stderr", new_callable=StringIO) as mock_stderr:
                exit_code = main(["check", "input", "ignore previous instructions"])
                assert exit_code == 100
                # Should write safe message to stderr
                assert "Input blocked by armor" in mock_stderr.getvalue()

    def test_check_input_with_hook_mode_block_to_exit_2(self) -> None:
        """Test --hook-mode translates block (100) to exit 2."""
        mock_response = {
            "v": 1,
            "verdict": "block",
            "signal_id": "regex:override-001",
            "message": "Instruction override pattern detected",
        }

        with patch("armor.cli.DaemonClient") as mock_client_class:
            mock_client = Mock()
            mock_client_class.return_value = mock_client
            mock_client.request.return_value = mock_response

            with patch("sys.stderr", new_callable=StringIO) as mock_stderr:
                exit_code = main(["check", "input", "ignore previous instructions", "--hook-mode"])
                assert exit_code == 2
                # Should write safe message to stderr
                stderr_text = mock_stderr.getvalue()
                assert "Input blocked by armor" in stderr_text
                # Should NOT include signal details
                assert "regex:override" not in stderr_text

    def test_check_input_with_hook_mode_advisory_to_exit_0(self) -> None:
        """Test --hook-mode translates advisory (101) to exit 0."""
        mock_response = {
            "v": 1,
            "verdict": "advisory",
            "signal_id": None,
            "message": "Potential injection detected",
        }

        with patch("armor.cli.DaemonClient") as mock_client_class:
            mock_client = Mock()
            mock_client_class.return_value = mock_client
            mock_client.request.return_value = mock_response

            exit_code = main(["check", "input", "test", "--hook-mode"])
            assert exit_code == 0

    def test_check_input_from_stdin(self) -> None:
        """Test reading input from stdin."""
        mock_response = {"v": 1, "verdict": "pass", "signal_id": None, "message": ""}

        with patch("armor.cli.DaemonClient") as mock_client_class:
            mock_client = Mock()
            mock_client_class.return_value = mock_client
            mock_client.request.return_value = mock_response

            with patch("sys.stdin", StringIO("hello from stdin")):
                exit_code = main(["check", "input"])
                assert exit_code == 0
                # Verify payload was sent with stdin text
                call_args = mock_client.request.call_args
                assert call_args[0][0] == "check.input"
                assert call_args[1]["payload"]["text"] == "hello from stdin"

    def test_check_input_with_session_id(self) -> None:
        """Test --session-id flag."""
        mock_response = {"v": 1, "verdict": "pass", "signal_id": None, "message": ""}

        with patch("armor.cli.DaemonClient") as mock_client_class:
            mock_client = Mock()
            mock_client_class.return_value = mock_client
            mock_client.request.return_value = mock_response

            exit_code = main(["check", "input", "test", "--session-id", "custom-123"])
            assert exit_code == 0
            # Verify session_id was passed
            call_args = mock_client.request.call_args
            assert call_args[1]["session_id"] == "custom-123"

    def test_check_input_with_json_output(self) -> None:
        """Test --json flag produces JSON output."""
        mock_response = {
            "v": 1,
            "verdict": "pass",
            "signal_id": None,
            "message": "",
        }

        with patch("armor.cli.DaemonClient") as mock_client_class:
            mock_client = Mock()
            mock_client_class.return_value = mock_client
            mock_client.request.return_value = mock_response

            with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
                exit_code = main(["check", "input", "test", "--json"])
                assert exit_code == 0
                output = json.loads(mock_stdout.getvalue())
                assert output["verdict"] == "pass"
                assert output["exit_code"] == 0

    def test_check_input_daemon_unreachable_exit_1(self) -> None:
        """Test daemon unreachable returns exit 1."""
        with patch("armor.cli.DaemonClient") as mock_client_class:
            mock_client = Mock()
            mock_client_class.return_value = mock_client
            mock_client.request.side_effect = DaemonUnreachableError("Socket not found")

            exit_code = main(["check", "input", "test"])
            assert exit_code == 1

    def test_check_input_with_armor_socket_env(self) -> None:
        """Test ARMOR_SOCKET env var is honored."""
        mock_response = {"v": 1, "verdict": "pass", "signal_id": None, "message": ""}

        with (
            patch.dict(os.environ, {"ARMOR_SOCKET": "/tmp/custom.sock"}),
            patch("armor.cli.DaemonClient") as mock_client_class,
        ):
            mock_client = Mock()
            mock_client_class.return_value = mock_client
            mock_client.request.return_value = mock_response

            exit_code = main(["check", "input", "test"])
            assert exit_code == 0
            # Verify socket path was passed to client
            call_args = mock_client_class.call_args
            assert call_args[1]["socket_path"] == "/tmp/custom.sock"

    def test_check_input_with_armor_session_id_env(self) -> None:
        """Test ARMOR_SESSION_ID env var is honored."""
        mock_response = {"v": 1, "verdict": "pass", "signal_id": None, "message": ""}

        with (
            patch.dict(os.environ, {"ARMOR_SESSION_ID": "env-session-id"}),
            patch("armor.cli.DaemonClient") as mock_client_class,
        ):
            mock_client = Mock()
            mock_client_class.return_value = mock_client
            mock_client.request.return_value = mock_response

            exit_code = main(["check", "input", "test"])
            assert exit_code == 0
            # Verify session_id was passed
            call_args = mock_client.request.call_args
            assert call_args[1]["session_id"] == "env-session-id"


class TestCheckOutputCommand:
    """Tests for 'armor check output' command."""

    def test_check_output_benign_pass(self) -> None:
        """Test benign output returns exit 0."""
        mock_response = {"v": 1, "verdict": "pass", "signal_id": None, "message": ""}

        with patch("armor.cli.DaemonClient") as mock_client_class:
            mock_client = Mock()
            mock_client_class.return_value = mock_client
            mock_client.request.return_value = mock_response

            exit_code = main(["check", "output", "model response"])
            assert exit_code == 0

    def test_check_output_block(self) -> None:
        """Test blocking output returns exit 100."""
        mock_response = {
            "v": 1,
            "verdict": "block",
            "signal_id": "canary:aws-key-001",
            "message": "Canary detected",
        }

        with patch("armor.cli.DaemonClient") as mock_client_class:
            mock_client = Mock()
            mock_client_class.return_value = mock_client
            mock_client.request.return_value = mock_response

            with patch("sys.stderr", new_callable=StringIO) as mock_stderr:
                exit_code = main(["check", "output", "aws key detected"])
                assert exit_code == 100
                # Should write safe message to stderr
                assert "Output suppressed by armor" in mock_stderr.getvalue()


class TestCheckToolCommand:
    """Tests for 'armor check tool' command."""

    def test_check_tool_safe_call(self) -> None:
        """Test safe tool call returns exit 0."""
        mock_response = {"v": 1, "verdict": "pass", "signal_id": None, "message": ""}

        with patch("armor.cli.DaemonClient") as mock_client_class:
            mock_client = Mock()
            mock_client_class.return_value = mock_client
            mock_client.request.return_value = mock_response

            exit_code = main(["check", "tool", "--name", "bash", "--params", '{"command": "echo hello"}'])
            assert exit_code == 0
            # Verify payload format
            call_args = mock_client.request.call_args
            assert call_args[0][0] == "check.tool"
            assert call_args[1]["payload"]["tool"] == "bash"
            assert call_args[1]["payload"]["params"] == {"command": "echo hello"}

    def test_check_tool_missing_name_exit_2(self) -> None:
        """Test missing --name flag returns exit 2."""
        with pytest.raises(SystemExit) as exc_info:
            main(["check", "tool", "--params", "{}"])
        assert exc_info.value.code == 2

    def test_check_tool_bad_json_params_exit_2(self) -> None:
        """Test invalid JSON params returns exit 2."""
        # When params are bad JSON, the CLI should catch and return 2
        mock_response = {"v": 1, "verdict": "pass", "signal_id": None, "message": ""}

        with patch("armor.cli.DaemonClient") as mock_client_class:
            mock_client = Mock()
            mock_client_class.return_value = mock_client
            mock_client.request.return_value = mock_response

            exit_code = main(["check", "tool", "--name", "bash", "--params", "not valid json"])
            assert exit_code == 2


class TestSessionCloseCommand:
    """Tests for 'armor session close' command."""

    def test_session_close_success(self) -> None:
        """Test session close returns exit 0."""
        mock_response = {"v": 1, "verdict": "pass"}

        with patch("armor.cli.DaemonClient") as mock_client_class:
            mock_client = Mock()
            mock_client_class.return_value = mock_client
            mock_client.request.return_value = mock_response

            exit_code = main(["session", "close", "--session-id", "test-123"])
            assert exit_code == 0
            # Verify session.close was called
            call_args = mock_client.request.call_args
            assert call_args[0][0] == "session.close"
            assert call_args[1]["session_id"] == "test-123"


class TestCanaryListCommand:
    """Tests for 'armor canary list' command."""

    def test_canary_list_json_no_values(self) -> None:
        """Test --json returns array with no value field."""
        mock_canaries = [
            {
                "canary_id": "aws-key-001",
                "kind": "credential",
                "service": "aws",
                "active": True,
            },
        ]
        mock_response = {"v": 1, "verdict": "pass", "canaries": mock_canaries}

        with patch("armor.cli.DaemonClient") as mock_client_class:
            mock_client = Mock()
            mock_client_class.return_value = mock_client
            mock_client.request.return_value = mock_response

            with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
                exit_code = main(["canary", "list", "--json"])
                assert exit_code == 0
                output = json.loads(mock_stdout.getvalue())
                assert isinstance(output, list)
                assert output[0]["canary_id"] == "aws-key-001"
                assert "value" not in output[0]

    def test_canary_list_human_readable(self) -> None:
        """Test human-readable output (no --json)."""
        mock_canaries = [
            {
                "canary_id": "aws-key-001",
                "kind": "credential",
                "service": "aws",
                "active": True,
            },
        ]
        mock_response = {"v": 1, "verdict": "pass", "canaries": mock_canaries}

        with patch("armor.cli.DaemonClient") as mock_client_class:
            mock_client = Mock()
            mock_client_class.return_value = mock_client
            mock_client.request.return_value = mock_response

            with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
                exit_code = main(["canary", "list"])
                assert exit_code == 0
                output = mock_stdout.getvalue()
                assert "aws-key-001" in output
                assert "credential" in output
                # Should not include value
                assert "value" not in output.lower()

    def test_canary_list_empty(self) -> None:
        """Test with no canaries."""
        mock_response = {"v": 1, "verdict": "pass", "canaries": []}

        with patch("armor.cli.DaemonClient") as mock_client_class:
            mock_client = Mock()
            mock_client_class.return_value = mock_client
            mock_client.request.return_value = mock_response

            with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
                exit_code = main(["canary", "list"])
                assert exit_code == 0
                output = mock_stdout.getvalue()
                assert "No active canaries" in output


class TestHealthCommand:
    """Tests for 'armor health' command."""

    def test_health_daemon_running(self) -> None:
        """Test health check with running daemon."""
        mock_response = {
            "v": 1,
            "verdict": "pass",
            "health": {
                "socket_reachable": True,
                "db_reachable": True,
                "model_loaded": True,
                "db_capacity_percent": 45.0,
                "uptime_seconds": 3600,
                "total_checks": 100,
                "p95_input_latency_ms": 50.5,
                "p95_output_latency_ms": 75.3,
            },
        }

        with patch("armor.cli.DaemonClient") as mock_client_class:
            mock_client = Mock()
            mock_client_class.return_value = mock_client
            mock_client.request.return_value = mock_response

            with patch("sys.stdout", new_callable=StringIO):
                exit_code = main(["health"])
                assert exit_code == 0

    def test_health_daemon_unreachable(self) -> None:
        """Test health check with unreachable daemon."""
        with patch("armor.cli.DaemonClient") as mock_client_class:
            mock_client = Mock()
            mock_client_class.return_value = mock_client
            mock_client.request.side_effect = DaemonUnreachableError("Socket not found")

            with patch("sys.stdout", new_callable=StringIO):
                exit_code = main(["health"])
                assert exit_code == 2


class TestHooksInstallCommand:
    """Tests for 'armor hooks install' command."""

    def test_hooks_install_creates_file(self) -> None:
        """Test hooks install creates settings file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            settings_path = os.path.join(tmpdir, "settings.json")

            exit_code = main(["hooks", "install", "--settings", settings_path])
            assert exit_code == 0

            # Verify file was created
            assert os.path.exists(settings_path)

            # Verify structure
            with open(settings_path) as f:
                settings = json.load(f)
            assert "hooks" in settings
            assert len(settings["hooks"]) == 4

            # Verify hook names
            hook_names = {h["name"] for h in settings["hooks"]}
            assert hook_names == {
                "armor-check-input",
                "armor-check-output",
                "armor-check-tool",
                "armor-session-close",
            }

    def test_hooks_install_idempotent(self) -> None:
        """Test hooks install is idempotent."""
        with tempfile.TemporaryDirectory() as tmpdir:
            settings_path = os.path.join(tmpdir, "settings.json")

            # First install
            exit_code1 = main(["hooks", "install", "--settings", settings_path])
            assert exit_code1 == 0

            # Second install
            exit_code2 = main(["hooks", "install", "--settings", settings_path])
            assert exit_code2 == 0

            # Verify no duplicates
            with open(settings_path) as f:
                settings = json.load(f)
            assert len(settings["hooks"]) == 4

    def test_hooks_install_preserves_existing_hooks(self) -> None:
        """Test hooks install preserves existing unrelated hooks."""
        with tempfile.TemporaryDirectory() as tmpdir:
            settings_path = os.path.join(tmpdir, "settings.json")

            # Create existing settings with custom hook
            existing = {
                "hooks": [
                    {
                        "name": "my-custom-hook",
                        "event": "SomeEvent",
                        "handler": "some command",
                    }
                ]
            }
            with open(settings_path, "w") as f:
                json.dump(existing, f)

            # Install armor hooks
            exit_code = main(["hooks", "install", "--settings", settings_path])
            assert exit_code == 0

            # Verify both old and new hooks exist
            with open(settings_path) as f:
                settings = json.load(f)
            hook_names = {h["name"] for h in settings["hooks"]}
            assert "my-custom-hook" in hook_names
            assert "armor-check-input" in hook_names
            assert len(settings["hooks"]) == 5

    def test_hooks_install_malformed_json_error(self) -> None:
        """Test hooks install handles malformed JSON gracefully."""
        with tempfile.TemporaryDirectory() as tmpdir:
            settings_path = os.path.join(tmpdir, "settings.json")

            # Create malformed JSON
            with open(settings_path, "w") as f:
                f.write("{invalid json")

            with patch("sys.stderr", new_callable=StringIO) as mock_stderr:
                exit_code = main(["hooks", "install", "--settings", settings_path])
                assert exit_code == 1
                assert "Malformed JSON" in mock_stderr.getvalue() or "Error" in mock_stderr.getvalue()

            # Verify file not corrupted (still contains original content)
            with open(settings_path) as f:
                content = f.read()
            assert "{invalid json" in content

    def test_hooks_install_default_path(self) -> None:
        """Test hooks install uses default path (./.claude/settings.json)."""
        # This is tested implicitly by test_install_hooks_default_path in test_hooks_install.py
        # which verifies the default path behavior directly
        pass
