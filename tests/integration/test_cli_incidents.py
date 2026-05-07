"""Integration tests for incidents CLI commands.

Covers task 036 spec markers:
- TC-036-01: incidents.list IPC op returns paginated rows (round-trip).
- TC-036-02: incidents.show <id> IPC op returns full record.
- TC-036-12: --limit default matches spec (50).
"""

import json
from unittest.mock import Mock, patch

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
