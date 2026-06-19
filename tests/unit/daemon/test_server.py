# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the daemon server."""

import asyncio
import os
import sqlite3
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from armor.daemon.server import DaemonServer
from armor.db.forensic import ForensicLogger
from armor.db.migrations import run_migrations
from armor.types import Verdict


@pytest.fixture
def temp_socket(tmp_path: Path) -> str:
    """Create a temporary socket path."""
    return str(tmp_path / "armor.sock")


@pytest.fixture
def temp_db(tmp_path: Path) -> str:
    """Create a temporary database path."""
    return str(tmp_path / "test.db")


@pytest.fixture(autouse=True)
def disable_llm_for_tests(monkeypatch) -> None:
    """Disable LLM for all daemon tests to avoid exit 78 on missing LLM.

    Tests that specifically need an LLM should mock it separately.
    """
    monkeypatch.setenv("ARMOR_DISABLE_LLM", "true")


def _fake_detector(detector_id: str, category: str) -> SimpleNamespace:
    return SimpleNamespace(
        id=detector_id,
        category=category,
        cost_tier="static",
        check=lambda _payload, _ctx: Verdict.pass_verdict(),
    )


class TestDaemonServer:
    """Tests for the daemon server."""

    @pytest.mark.asyncio
    async def test_start_and_stop(self, temp_socket: str, temp_db: str) -> None:
        """Test basic daemon startup and shutdown."""
        server = DaemonServer(socket_path=temp_socket, db_path=temp_db)

        # Start the server
        await server.start()
        assert Path(temp_socket).exists()

        # Stop the server
        await server.stop()
        assert not Path(temp_socket).exists()

    @pytest.mark.asyncio
    async def test_socket_recreated_on_start(self, temp_socket: str, temp_db: str) -> None:
        """Test that existing socket is removed and recreated."""
        # Create first server and start it
        server1 = DaemonServer(socket_path=temp_socket, db_path=temp_db)
        await server1.start()
        assert Path(temp_socket).exists()

        # Stop it
        await server1.stop()
        assert not Path(temp_socket).exists()

        # Start a new server on the same path
        server2 = DaemonServer(socket_path=temp_socket, db_path=temp_db)
        await server2.start()
        assert Path(temp_socket).exists()

        await server2.stop()

    @pytest.mark.asyncio
    async def test_handle_request_check_input(self, temp_socket: str) -> None:
        """Test handling check.input operation."""
        server = DaemonServer(socket_path=temp_socket)
        request = {"v": 1, "op": "check.input", "payload": {"text": "hello"}}
        response = await server._handle_request(request)

        assert response["v"] == 1
        assert response["verdict"] == "pass"

    @pytest.mark.asyncio
    async def test_handle_request_check_output(self, temp_socket: str) -> None:
        """Test handling check.output operation."""
        server = DaemonServer(socket_path=temp_socket)
        request = {"v": 1, "op": "check.output", "payload": {"text": "safe"}}
        response = await server._handle_request(request)

        assert response["v"] == 1
        assert response["verdict"] == "pass"

    @pytest.mark.asyncio
    async def test_handle_request_check_tool(self, temp_socket: str) -> None:
        """Test handling check.tool operation."""
        server = DaemonServer(socket_path=temp_socket)
        request = {
            "v": 1,
            "op": "check.tool",
            "payload": {"tool": "bash", "params": {"command": "echo hello"}},
        }
        response = await server._handle_request(request)

        assert response["v"] == 1
        assert response["verdict"] == "pass"

    @pytest.mark.asyncio
    async def test_handle_request_session_close(self, temp_socket: str) -> None:
        """Test handling session.close operation."""
        server = DaemonServer(socket_path=temp_socket)
        request = {"v": 1, "op": "session.close", "session_id": "test-session"}
        response = await server._handle_request(request)

        assert response["v"] == 1
        assert response["verdict"] == "pass"

    @pytest.mark.asyncio
    async def test_handle_request_canary_list(self, temp_socket: str) -> None:
        """Test handling canary.list operation."""
        server = DaemonServer(socket_path=temp_socket)
        request = {"v": 1, "op": "canary.list"}
        response = await server._handle_request(request)

        assert response["v"] == 1
        assert response["verdict"] == "pass"
        assert response["canaries"] == []

    @pytest.mark.asyncio
    async def test_handle_request_unknown_op(self, temp_socket: str) -> None:
        """Test handling unknown operation."""
        server = DaemonServer(socket_path=temp_socket)
        request = {"v": 1, "op": "unknown.operation"}
        response = await server._handle_request(request)

        assert response["v"] == 1
        assert response["verdict"] == "error"
        assert "unknown op" in response["message"]

    def test_detector_filter_config_for_input_output_and_tool(self, temp_socket: str, tmp_path: Path) -> None:
        """TC-108-01/02/03: per-operation detector allowlists select matching detectors."""
        config_path = tmp_path / "armor.toml"
        config_path.write_text(
            "\n".join(
                [
                    "[pipeline]",
                    'input_detectors = ["meta.*"]',
                    'output_detectors = ["canary.scanner"]',
                    'tool_detectors = ["tool_abuse"]',
                ]
            )
        )
        server = DaemonServer(socket_path=temp_socket, config_path=str(config_path))
        server.registry.detectors = {
            "meta.memory_planting": _fake_detector("meta.memory_planting", "context_window"),
            "canary.scanner": _fake_detector("canary.scanner", "exfiltration"),
            "cmd_injection.bash": _fake_detector("cmd_injection.bash", "tool_abuse"),
            "regex.instruction_override": _fake_detector("regex.instruction_override", "direct_injection"),
        }

        assert [detector.id for detector in server._detectors_for_operation("check.input")] == ["meta.memory_planting"]
        assert [detector.id for detector in server._detectors_for_operation("check.output")] == ["canary.scanner"]
        assert [detector.id for detector in server._detectors_for_operation("check.tool")] == ["cmd_injection.bash"]

    def test_detector_filter_star_preserves_all_detectors(self, temp_socket: str, tmp_path: Path) -> None:
        """TC-108-04: `*` keeps all detectors enabled for an operation."""
        config_path = tmp_path / "armor.toml"
        config_path.write_text("[pipeline]\ninput_detectors = ['*']\n")
        server = DaemonServer(socket_path=temp_socket, config_path=str(config_path))
        server.registry.detectors = {
            "meta.memory_planting": _fake_detector("meta.memory_planting", "context_window"),
            "regex.instruction_override": _fake_detector("regex.instruction_override", "direct_injection"),
        }

        assert [detector.id for detector in server._detectors_for_operation("check.input")] == [
            "meta.memory_planting",
            "regex.instruction_override",
        ]

    def test_invalid_detector_filter_config_uses_defaults(self, temp_socket: str, tmp_path: Path) -> None:
        """TC-108-05: invalid allowlist config falls back to safe defaults."""
        config_path = tmp_path / "armor.toml"
        config_path.write_text("[pipeline]\ntool_detectors = [123]\n")
        server = DaemonServer(socket_path=temp_socket, config_path=str(config_path))
        server.registry.detectors = {
            "cmd_injection.bash": _fake_detector("cmd_injection.bash", "tool_abuse"),
            "tool_param.schema": _fake_detector("tool_param.schema", "tool_abuse"),
            "tool_rate.anomaly": _fake_detector("tool_rate.anomaly", "tool_abuse"),
            "tool_chain": _fake_detector("tool_chain", "tool_abuse"),
            "regex.instruction_override": _fake_detector("regex.instruction_override", "direct_injection"),
        }

        assert [detector.id for detector in server._detectors_for_operation("check.tool")] == [
            "cmd_injection.bash",
            "tool_param.schema",
            "tool_rate.anomaly",
            "tool_chain",
        ]

    @pytest.mark.asyncio
    async def test_incidents_list_applies_payload_filters(self, temp_socket: str, temp_db: str) -> None:
        """TC-107-04: incidents.list applies age, session, category, and since_id filters."""
        run_migrations(temp_db)
        conn = sqlite3.connect(temp_db)
        try:
            conn.executemany(
                "INSERT INTO Incident (id, ts, session_id, attack_category, signal_id, input_hash, severity) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                [
                    (1, "2020-01-01 00:00:00", "target", "direct_injection.old", "old", "h1", "high"),
                    (
                        2,
                        "2099-05-09 12:00:00",
                        "target",
                        "direct_injection.new",
                        "new",
                        "h2",
                        "critical",
                    ),
                    (3, "2099-05-09 12:00:00", "other", "direct_injection.new", "other", "h3", "critical"),
                ],
            )
            conn.commit()
        finally:
            conn.close()

        server = DaemonServer(socket_path=temp_socket, db_path=temp_db)
        server.forensic_logger = ForensicLogger(temp_db)
        response = await server._handle_incidents_list(
            {
                "payload": {
                    "limit": 10,
                    "session_id": "target",
                    "category": "direct_injection.*",
                    "since": "30d",
                    "since_id": 1,
                    "severity": "critical",
                }
            }
        )

        assert response["verdict"] == "pass"
        assert [row["id"] for row in response["incidents"]] == [2]

    @pytest.mark.asyncio
    async def test_incidents_export_applies_payload_filters(self, temp_socket: str, temp_db: str) -> None:
        """TC-107-05: incidents.export applies since, session, and severity filters."""
        run_migrations(temp_db)
        conn = sqlite3.connect(temp_db)
        try:
            conn.executemany(
                "INSERT INTO Incident (ts, session_id, attack_category, signal_id, input_hash, severity) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                [
                    ("2020-01-01 00:00:00", "target", "direct_injection.old", "old", "h1", "critical"),
                    ("2099-05-09 12:00:00", "target", "direct_injection.new", "new", "h2", "critical"),
                    ("2099-05-09 12:00:00", "target", "direct_injection.low", "low", "h3", "low"),
                    ("2099-05-09 12:00:00", "other", "direct_injection.new", "other", "h4", "critical"),
                ],
            )
            conn.commit()
        finally:
            conn.close()

        server = DaemonServer(socket_path=temp_socket, db_path=temp_db)
        server.forensic_logger = ForensicLogger(temp_db)
        response = await server._handle_incidents_export(
            {"payload": {"session_id": "target", "since": "30d", "severity": "critical"}}
        )

        assert response["verdict"] == "pass"
        assert [row["signal_id"] for row in response["incidents"]] == ["new"]

    @pytest.mark.asyncio
    async def test_handle_request_unsupported_version(self, temp_socket: str) -> None:
        """Test handling unsupported protocol version."""
        server = DaemonServer(socket_path=temp_socket)
        request = {"v": 2, "op": "check.input"}
        response = await server._handle_request(request)

        assert response["v"] == 1
        assert response["verdict"] == "error"
        assert "version" in response["message"].lower()

    @pytest.mark.asyncio
    async def test_handle_request_invalid_request(self, temp_socket: str) -> None:
        """Test handling invalid requests gracefully."""
        server = DaemonServer(socket_path=temp_socket)
        response = await server._handle_request({})

        assert response["v"] == 1
        assert response["verdict"] == "error"

    def test_socket_dir_not_writable(self, temp_socket: str) -> None:
        """Test that daemon refuses to start if socket dir is not writable."""
        # Create a read-only directory
        with tempfile.TemporaryDirectory() as tmpdir:
            socket_path = os.path.join(tmpdir, "armor.sock")

            # Make the directory read-only
            os.chmod(tmpdir, 0o555)

            server = DaemonServer(socket_path=socket_path)

            try:
                with pytest.raises(OSError, match="not writable"):
                    asyncio.run(server.start())
            finally:
                # Restore permissions for cleanup
                os.chmod(tmpdir, 0o755)

    def test_session_state_enum_coercion(self) -> None:
        """TC-087-11: SessionState enum coercion from persisted strings.

        Verifies that state strings from SQLite ("Elevated", "Normal", etc.)
        can be converted to SessionState enums, and that invalid strings raise ValueError.
        """
        from armor.session.state_machine import SessionState

        # Valid state strings should convert to enums
        assert SessionState("Elevated") == SessionState.ELEVATED
        assert SessionState("Normal") == SessionState.NORMAL
        assert SessionState("Watching") == SessionState.WATCHING
        assert SessionState("High") == SessionState.HIGH
        assert SessionState("Blocked") == SessionState.BLOCKED

        # Invalid state should raise ValueError (fail loudly)
        with pytest.raises(ValueError):
            SessionState("InvalidState")  # type: ignore
