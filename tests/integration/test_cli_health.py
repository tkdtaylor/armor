"""Integration tests for expanded health CLI command."""

import json
from unittest.mock import Mock, patch

from armor.cli import main


class TestHealthCommand:
    """Tests for the expanded 'armor health' command."""

    def test_health_exit_0_when_healthy(self) -> None:
        """TC-028-07: armor health exits 0 when all systems are up."""
        mock_response = {
            "verdict": "pass",
            "health": {
                "socket_reachable": True,
                "db_reachable": True,
                "model_loaded": True,
                "uptime_seconds": 3600,
                "total_checks": 100,
                "p95_input_latency_ms": 50.5,
                "p95_output_latency_ms": 75.3,
                "last_incident_ts": "2026-05-06T14:00:00Z",
            },
        }

        with patch("armor.cli.DaemonClient") as mock_client_class:
            mock_client = Mock()
            mock_client_class.return_value = mock_client
            mock_client.request.return_value = mock_response

            exit_code = main(["health"])

            assert exit_code == 0

    def test_health_exit_1_when_degraded(self) -> None:
        """TC-028-07: armor health exits 1 when degraded (DB unreachable)."""
        mock_response = {
            "verdict": "pass",
            "health": {
                "socket_reachable": True,
                "db_reachable": False,
                "model_loaded": True,
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

            exit_code = main(["health"])

            assert exit_code == 1

    def test_health_exit_2_when_critical(self) -> None:
        """TC-028-07: armor health exits 2 when critical (model not loaded)."""
        mock_response = {
            "verdict": "pass",
            "health": {
                "socket_reachable": True,
                "db_reachable": True,
                "model_loaded": False,  # Critical
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

            exit_code = main(["health"])

            assert exit_code == 2

    def test_health_exit_2_unreachable(self) -> None:
        """Test armor health exits 2 when daemon is unreachable."""
        with patch("armor.cli.DaemonClient") as mock_client_class:
            mock_client = Mock()
            mock_client_class.return_value = mock_client
            mock_client.request.side_effect = Exception("Connection refused")

            exit_code = main(["health"])

            assert exit_code == 2

    def test_health_json_output(self) -> None:
        """Test armor health outputs JSON when --json is specified."""
        mock_response = {
            "verdict": "pass",
            "health": {
                "socket_reachable": True,
                "db_reachable": True,
                "model_loaded": True,
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

            with patch("sys.stdout") as mock_stdout:
                output_lines = []

                def capture_write(text: str) -> None:
                    output_lines.append(text)

                mock_stdout.write = capture_write

                exit_code = main(["health", "--json"])

                output = "".join(output_lines)
                parsed = json.loads(output)
                assert parsed["socket_reachable"] is True
                assert parsed["model_loaded"] is True
                assert exit_code == 0

    def test_health_plain_text_no_tty(self) -> None:
        """TC-028-09: armor health outputs plain text on non-TTY."""
        mock_response = {
            "verdict": "pass",
            "health": {
                "socket_reachable": True,
                "db_reachable": True,
                "model_loaded": True,
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

            with patch("sys.stdout") as mock_stdout:
                output_lines = []

                def capture_write(text: str) -> None:
                    output_lines.append(text)

                def capture_print(text: str) -> None:
                    output_lines.append(text)

                mock_stdout.write = capture_write
                mock_stdout.isatty.return_value = False

                with patch("builtins.print", capture_print):
                    exit_code = main(["health"])

                output = "\n".join(output_lines)
                # Check for plain text indicators, no ANSI sequences
                assert "\x1b[" not in output  # No ANSI escape sequences
                assert exit_code == 0
