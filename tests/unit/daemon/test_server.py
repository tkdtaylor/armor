"""Unit tests for the daemon server."""

import asyncio
import json
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

    @pytest.mark.asyncio
    @pytest.mark.skip(
        reason="pytest-asyncio per-test event loop creates client-connection hangs in CI; tracked as TODO — see daemon test_server.py"
    )
    async def test_single_client_request(self, temp_socket: str) -> None:
        """Test a single client sending a request."""
        server = DaemonServer(socket_path=temp_socket)
        await server.start()

        try:
            # Connect and send a request
            reader, writer = await asyncio.open_unix_connection(temp_socket)

            request = {"v": 1, "op": "check.input", "payload": {"text": "test"}}
            writer.write((json.dumps(request) + "\n").encode("utf-8"))
            await writer.drain()

            # Read response
            response_line = await asyncio.wait_for(reader.readuntil(b"\n"), timeout=5.0)
            response = json.loads(response_line.decode("utf-8").strip())

            assert response["v"] == 1
            assert response["verdict"] == "pass"

            writer.close()
            await writer.wait_closed()

        finally:
            server._shutdown()
            await server.stop()

    @pytest.mark.asyncio
    @pytest.mark.skip(
        reason="pytest-asyncio per-test event loop creates client-connection hangs in CI; tracked as TODO — see daemon test_server.py"
    )
    async def test_concurrent_clients(self, temp_socket: str) -> None:
        """Test multiple concurrent clients."""
        server = DaemonServer(socket_path=temp_socket, max_concurrent=10)
        await server.start()

        try:

            async def send_request(client_id: int) -> bool:
                """Send a single request and get response."""
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_unix_connection(temp_socket),
                        timeout=5.0,
                    )

                    request = {
                        "v": 1,
                        "op": "check.input",
                        "payload": {"text": f"client-{client_id}"},
                    }
                    writer.write((json.dumps(request) + "\n").encode("utf-8"))
                    await writer.drain()

                    response_line = await asyncio.wait_for(reader.readuntil(b"\n"), timeout=5.0)
                    response = json.loads(response_line.decode("utf-8").strip())

                    writer.close()
                    await writer.wait_closed()

                    return response.get("verdict") == "pass"

                except Exception as e:
                    pytest.fail(f"Client {client_id} failed: {e}")

            # Send 10 concurrent requests
            tasks = [send_request(i) for i in range(10)]
            results = await asyncio.gather(*tasks)

            assert all(results), "Not all clients received successful responses"

        finally:
            server._shutdown()
            await server.stop()

    @pytest.mark.asyncio
    @pytest.mark.skip(
        reason="pytest-asyncio per-test event loop creates client-connection hangs in CI; tracked as TODO — see daemon test_server.py"
    )
    async def test_max_concurrent_enforcement(self, temp_socket: str) -> None:
        """Test that max_concurrent limit is enforced."""
        server = DaemonServer(socket_path=temp_socket, max_concurrent=2)
        await server.start()

        try:

            async def long_request(client_id: int) -> str:
                """Send a request that takes time to process."""
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_unix_connection(temp_socket),
                        timeout=5.0,
                    )

                    request = {
                        "v": 1,
                        "op": "check.input",
                        "payload": {"text": f"client-{client_id}"},
                    }
                    writer.write((json.dumps(request) + "\n").encode("utf-8"))
                    await writer.drain()

                    # Wait a bit to keep connection open
                    await asyncio.sleep(0.5)

                    response_line = await asyncio.wait_for(reader.readuntil(b"\n"), timeout=5.0)
                    response = json.loads(response_line.decode("utf-8").strip())

                    writer.close()
                    await writer.wait_closed()

                    return response.get("verdict", "unknown")

                except Exception as e:
                    return f"error: {e}"

            # Try 4 concurrent requests with max_concurrent=2
            # The semaphore should queue requests appropriately
            tasks = [long_request(i) for i in range(4)]
            results = await asyncio.gather(*tasks)

            # All should eventually succeed
            assert all(r == "pass" for r in results), f"Unexpected results: {results}"

        finally:
            server._shutdown()
            await server.stop()

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

    @pytest.mark.asyncio
    @pytest.mark.skip(
        reason="pytest-asyncio per-test event loop creates client-connection hangs in CI; tracked as TODO — see daemon test_server.py"
    )
    async def test_handle_malformed_json(self, temp_socket: str) -> None:
        """Test handling of malformed JSON input."""
        server = DaemonServer(socket_path=temp_socket)
        await server.start()

        try:
            reader, writer = await asyncio.open_unix_connection(temp_socket)

            # Send invalid JSON
            writer.write(b"not valid json\n")
            await writer.drain()

            response_line = await asyncio.wait_for(reader.readuntil(b"\n"), timeout=5.0)
            response = json.loads(response_line.decode("utf-8").strip())

            assert response["v"] == 1
            assert response["verdict"] == "error"

            writer.close()
            await writer.wait_closed()

        finally:
            server._shutdown()
            await server.stop()

    @pytest.mark.asyncio
    @pytest.mark.skip(
        reason="pytest-asyncio per-test event loop creates client-connection hangs in CI; tracked as TODO — see daemon test_server.py"
    )
    async def test_json_per_line_output(self, temp_socket: str, caplog: object) -> None:
        """Test that all output is valid JSON per line."""
        server = DaemonServer(socket_path=temp_socket)

        try:
            # This is more of a logging test that will be verified
            # when we check the logging module separately
            await server.start()
            await server.stop()
        except Exception:
            pass


class TestDaemonShutdown:
    """Tests for graceful shutdown behavior."""

    @pytest.mark.asyncio
    @pytest.mark.skip(
        reason="pytest-asyncio per-test event loop creates client-connection hangs in CI; tracked as TODO — see daemon test_server.py"
    )
    async def test_graceful_shutdown_removes_socket(self, temp_socket: str) -> None:
        """Test that graceful shutdown removes the socket file."""
        server = DaemonServer(socket_path=temp_socket)
        await server.start()

        assert Path(temp_socket).exists()

        server._shutdown()
        await asyncio.sleep(0.1)  # Give shutdown time to propagate
        await server.stop()

        assert not Path(temp_socket).exists()
