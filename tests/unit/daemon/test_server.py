"""Unit tests for the daemon server."""

import asyncio
import os
import tempfile
from pathlib import Path

import pytest

from armor.daemon.server import DaemonServer


@pytest.fixture
def temp_socket(tmp_path: Path) -> str:
    """Create a temporary socket path."""
    return str(tmp_path / "armor.sock")


@pytest.fixture
def temp_db(tmp_path: Path) -> str:
    """Create a temporary database path."""
    return str(tmp_path / "test.db")


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
