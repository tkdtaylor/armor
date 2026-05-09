"""Integration tests for incidents CLI commands.

Covers task 036 spec markers:
- TC-036-01: incidents.list IPC op returns paginated rows (round-trip).
- TC-036-02: incidents.show <id> IPC op returns full record.
- TC-036-12: --limit default matches spec (50).
"""

import json
from unittest.mock import Mock, patch

import pytest

from armor.cli import main


class TestIncidentsCommands:
    """Tests for 'armor incidents' command family."""

    def test_incidents_list_returns_table(self) -> None:
        """TC-028-01: armor incidents list returns rows from a populated daemon."""
        mock_response = {
            "verdict": "pass",
            "incidents": [
                {
                    "id": 1,
                    "session_id": "sess-001",
                    "attack_category": "direct_injection",
                    "action": "blocked",
                    "ts": "2026-05-06T14:00:00Z",
                },
                {
                    "id": 2,
                    "session_id": "sess-001",
                    "attack_category": "exfiltration",
                    "action": "advisory_only",
                    "ts": "2026-05-06T14:01:00Z",
                },
                {
                    "id": 3,
                    "session_id": "sess-002",
                    "attack_category": "tool_abuse",
                    "action": "blocked",
                    "ts": "2026-05-06T14:02:00Z",
                },
                {
                    "id": 4,
                    "session_id": "sess-002",
                    "attack_category": "direct_injection",
                    "action": "passed_with_warning",
                    "ts": "2026-05-06T14:03:00Z",
                },
                {
                    "id": 5,
                    "session_id": "sess-003",
                    "attack_category": "exfiltration",
                    "action": "blocked",
                    "ts": "2026-05-06T14:04:00Z",
                },
            ],
        }

        with patch("armor.cli.DaemonClient") as mock_client_class:
            mock_client = Mock()
            mock_client_class.return_value = mock_client
            mock_client.request.return_value = mock_response

            with patch("sys.stdout") as mock_stdout:
                # Capture output
                output_lines = []

                def capture_write(text: str) -> None:
                    output_lines.append(text)

                mock_stdout.write = capture_write
                mock_stdout.isatty.return_value = False  # Non-TTY, plain text

                exit_code = main(["incidents", "list", "--limit", "10"])

                # Verify all 5 incident IDs are in the output
                output = "\n".join(output_lines)
                assert "1" in output
                assert "2" in output
                assert "3" in output
                assert "4" in output
                assert "5" in output

                # Verify no canary values appear (if there were any)
                # This is checked via absence assertion in real test
                assert exit_code == 0

    def test_incidents_list_json_output(self) -> None:
        """Test incidents list outputs JSON when --json is specified."""
        mock_response = {
            "verdict": "pass",
            "incidents": [
                {
                    "id": 1,
                    "session_id": "sess-001",
                    "attack_category": "direct_injection",
                    "action": "blocked",
                    "ts": "2026-05-06T14:00:00Z",
                }
            ],
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

                main(["incidents", "list", "--json"])

                output = "".join(output_lines)
                # Should be valid JSON
                parsed = json.loads(output)
                assert isinstance(parsed, list)
                assert len(parsed) == 1
                assert parsed[0]["id"] == 1

    def test_incidents_show_full_record(self) -> None:
        """TC-028-02: armor incidents show <id> returns full record."""
        mock_response = {
            "verdict": "pass",
            "incident": {
                "id": 1,
                "session_id": "sess-001",
                "attack_category": "direct_injection",
                "signal_id": "regex:override-001",
                "action": "blocked",
                "risk_score": 5,
                "ts": "2026-05-06T14:00:00Z",
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

                exit_code = main(["incidents", "show", "1"])

                output = "\n".join(output_lines)
                assert "sess-001" in output
                assert "direct_injection" in output
                assert "blocked" in output
                assert exit_code == 0

    def test_incidents_show_not_found(self) -> None:
        """Test incidents show returns error for missing incident."""
        mock_response = {
            "verdict": "pass",
            "incident": None,
        }

        with patch("armor.cli.DaemonClient") as mock_client_class:
            mock_client = Mock()
            mock_client_class.return_value = mock_client
            mock_client.request.return_value = mock_response

            with patch("sys.stderr") as mock_stderr:
                output_lines = []

                def capture_write(text: str) -> None:
                    output_lines.append(text)

                mock_stderr.write = capture_write

                exit_code = main(["incidents", "show", "999"])

                assert exit_code == 1

    def test_incidents_list_default_limit_is_50(self) -> None:
        """TC-036-12: --limit default matches spec (50, not 100)."""
        mock_response = {"verdict": "pass", "incidents": []}

        with patch("armor.cli.DaemonClient") as mock_client_class:
            mock_client = Mock()
            mock_client_class.return_value = mock_client
            mock_client.request.return_value = mock_response

            main(["incidents", "list"])

            mock_client.request.assert_called_once()
            call = mock_client.request.call_args
            # Verify the request payload was sent with limit=50.
            assert call[0][0] == "incidents.list"
            assert call[1]["payload"]["limit"] == 50

    def test_incidents_list_sends_since_filter(self) -> None:
        """TC-107-06: incidents list --since is sent to the daemon."""
        mock_response = {"verdict": "pass", "incidents": []}

        with patch("armor.cli.DaemonClient") as mock_client_class:
            mock_client = Mock()
            mock_client_class.return_value = mock_client
            mock_client.request.return_value = mock_response

            main(["incidents", "list", "--since", "1h"])

            call = mock_client.request.call_args
            assert call[0][0] == "incidents.list"
            assert call[1]["payload"]["since"] == "1h"

    def test_incidents_tail_streams_new_incidents(self) -> None:
        """TC-028-03: armor incidents tail streams new incidents."""
        # Test that tail returns 0 on KeyboardInterrupt (successful termination)
        mock_responses = [
            {
                "verdict": "pass",
                "incidents": [
                    {
                        "id": 1,
                        "session_id": "sess-001",
                        "attack_category": "direct_injection",
                        "action": "blocked",
                    },
                    {
                        "id": 2,
                        "session_id": "sess-001",
                        "attack_category": "exfiltration",
                        "action": "advisory_only",
                    },
                    {
                        "id": 3,
                        "session_id": "sess-002",
                        "attack_category": "tool_abuse",
                        "action": "blocked",
                    },
                ],
            },
        ]

        with patch("armor.cli.DaemonClient") as mock_client_class:
            mock_client = Mock()
            mock_client_class.return_value = mock_client

            # Set up side effect to raise KeyboardInterrupt after first call
            mock_client.request.side_effect = [
                mock_responses[0],
                KeyboardInterrupt(),
            ]

            with patch("armor.cli.time.sleep"):  # Skip the sleep
                exit_code = main(["incidents", "tail"])

                # Should exit cleanly on KeyboardInterrupt
                assert exit_code == 0

    def test_incidents_tail_parses_filter_expression(self) -> None:
        """TC-107-07: incidents tail --filter becomes concrete daemon filters."""
        with patch("armor.cli.DaemonClient") as mock_client_class:
            mock_client = Mock()
            mock_client_class.return_value = mock_client
            mock_client.request.side_effect = [
                {"verdict": "pass", "incidents": []},
                KeyboardInterrupt(),
            ]

            with patch("armor.cli.time.sleep"):
                exit_code = main(
                    [
                        "incidents",
                        "tail",
                        "--filter",
                        "session=tail-session,category=direct_injection.*,severity=critical",
                    ]
                )

            assert exit_code == 0
            call = mock_client.request.call_args_list[0]
            assert call[0][0] == "incidents.list"
            assert call[1]["payload"]["session_id"] == "tail-session"
            assert call[1]["payload"]["category"] == "direct_injection.*"
            assert call[1]["payload"]["severity"] == "critical"

    def test_incidents_export_ndjson_output(self) -> None:
        """TC-049-03: incidents export writes NDJSON with documented schema."""
        mock_response = {
            "verdict": "pass",
            "incidents": [
                {
                    "ts": "2026-05-05T18:30:01Z",
                    "session_id": "claude-code-12345-abc",
                    "attack_category": "exfiltration.canary_leak",
                    "signal_id": "canary:aws-key-001",
                    "input_hash": "abc123",
                    "output_hash": "def456",
                    "triggered_canary": "aws-key-001",
                    "destinations": ["webhook.site"],
                    "encoding_flag": False,
                    "risk_score": 85,
                    "action": "blocked",
                },
                {
                    "ts": "2026-05-05T18:31:02Z",
                    "session_id": "claude-code-12345-abc",
                    "attack_category": "direct_injection",
                    "signal_id": "regex:override-001",
                    "input_hash": "ghi789",
                    "output_hash": None,
                    "triggered_canary": None,
                    "destinations": [],
                    "encoding_flag": False,
                    "risk_score": 10,
                    "action": "advisory_only",
                },
            ],
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

                exit_code = main(["incidents", "export"])

                output = "".join(output_lines)
                lines = output.strip().split("\n")

                # Verify we have 2 NDJSON lines
                assert len(lines) == 2, f"Expected 2 lines, got {len(lines)}"

                # Parse each line as JSON
                obj1 = json.loads(lines[0])
                obj2 = json.loads(lines[1])

                # Verify schema fields are present
                assert obj1["ts"] == "2026-05-05T18:30:01Z"
                assert obj1["session_id"] == "claude-code-12345-abc"
                assert obj1["attack_category"] == "exfiltration.canary_leak"
                assert obj1["action"] == "blocked"

                assert obj2["ts"] == "2026-05-05T18:31:02Z"
                assert obj2["action"] == "advisory_only"

                assert exit_code == 0

    def test_incidents_export_to_file(self) -> None:
        """TC-049-03: incidents export writes to file with --output flag."""
        import tempfile

        mock_response = {
            "verdict": "pass",
            "incidents": [
                {
                    "ts": "2026-05-05T18:30:01Z",
                    "session_id": "claude-code-12345-abc",
                    "attack_category": "exfiltration.canary_leak",
                    "signal_id": "canary:aws-key-001",
                    "input_hash": "abc123",
                    "output_hash": "def456",
                    "triggered_canary": "aws-key-001",
                    "destinations": ["webhook.site"],
                    "encoding_flag": False,
                    "risk_score": 85,
                    "action": "blocked",
                },
            ],
        }

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".ndjson") as tf:
            temp_path = tf.name

        try:
            with patch("armor.cli.DaemonClient") as mock_client_class:
                mock_client = Mock()
                mock_client_class.return_value = mock_client
                mock_client.request.return_value = mock_response

                exit_code = main(["incidents", "export", "--output", temp_path])

                # Read back the file
                with open(temp_path) as f:
                    lines = f.read().strip().split("\n")

                assert len(lines) == 1
                obj = json.loads(lines[0])
                assert obj["action"] == "blocked"
                assert exit_code == 0
        finally:
            import os

            if os.path.exists(temp_path):
                os.unlink(temp_path)

    def test_incidents_export_with_filters(self) -> None:
        """TC-049-03: incidents export respects --session and --since filters."""
        mock_response = {
            "verdict": "pass",
            "incidents": [
                {
                    "ts": "2026-05-05T18:30:01Z",
                    "session_id": "filtered-session",
                    "attack_category": "exfiltration",
                    "signal_id": "canary:key-001",
                    "input_hash": "abc",
                    "output_hash": "def",
                    "triggered_canary": "key-001",
                    "destinations": [],
                    "encoding_flag": False,
                    "risk_score": 50,
                    "action": "blocked",
                },
            ],
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

                exit_code = main(
                    [
                        "incidents",
                        "export",
                        "--session",
                        "filtered-session",
                        "--since",
                        "1h",
                        "--severity",
                        "critical",
                    ]
                )

                # Verify the request was made with correct filters
                mock_client.request.assert_called_once()
                call = mock_client.request.call_args
                assert call[0][0] == "incidents.export"
                assert call[1]["payload"]["session_id"] == "filtered-session"
                assert call[1]["payload"]["since"] == "1h"
                assert call[1]["payload"]["severity"] == "critical"

                assert exit_code == 0

    def test_incidents_export_help(self) -> None:
        """TC-049-02: armor incidents export --help exits 0.

        TC-107-08: The help check is an executable assertion, not a placeholder.
        """
        with pytest.raises(SystemExit) as exc_info:
            main(["incidents", "export", "--help"])

        assert exc_info.value.code == 0

    def test_incidents_export_help_includes_severity_filter(self, capsys) -> None:
        """TC-107-09: export still exposes the documented severity filter."""
        with pytest.raises(SystemExit) as exc_info:
            main(["incidents", "export", "--help"])

        assert exc_info.value.code == 0
        assert "--severity" in capsys.readouterr().out
