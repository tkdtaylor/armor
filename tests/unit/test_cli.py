"""Unit tests for the armor CLI."""

import json
from io import StringIO
from unittest.mock import patch

from armor.cli import main


class TestHealthCommand:
    """Tests for the health subcommand."""

    def test_health_daemon_not_running(self) -> None:
        """Test health check when daemon is not running."""
        output = StringIO()
        with patch("sys.stdout", output):
            exit_code = main(["health"])

        assert exit_code == 1
        data = json.loads(output.getvalue().strip())
        assert data["status"] == "unreachable"

    def test_health_with_custom_socket_path(self) -> None:
        """Test health check with custom socket path."""
        output = StringIO()
        with patch("sys.stdout", output):
            exit_code = main(["--socket", "/tmp/nonexistent.sock", "health"])

        assert exit_code == 1
        data = json.loads(output.getvalue().strip())
        assert data["status"] == "unreachable"
