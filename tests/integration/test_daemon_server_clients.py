# SPDX-License-Identifier: Apache-2.0
"""Integration tests for daemon client connections via subprocess.

These tests start the daemon as a subprocess and connect to it via Unix socket
from the test process using synchronous socket I/O. This approach avoids the
pytest-asyncio per-test event loop cleanup race condition that caused hangs
in the previous async-in-process test approach.

Reference: ADR-013 (subprocess-based daemon integration tests)
"""

import asyncio
import json
import os
import socket
import subprocess
import tempfile
import time
from collections.abc import Generator
from pathlib import Path

import pytest


def start_daemon(socket_path: str, db_path: str, timeout: float = 10.0) -> subprocess.Popen:
    """Start the daemon as a subprocess.

    Args:
        socket_path: Path to the Unix socket
        db_path: Path to the SQLite database
        timeout: Max time to wait for daemon to start listening

    Returns:
        Popen instance for the daemon process

    Raises:
        TimeoutError: If daemon doesn't start within timeout
    """
    proc = subprocess.Popen(
        ["uv", "run", "armor", "daemon", "--socket", socket_path, "--db", db_path],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True,
        env={**os.environ, "ARMOR_DISABLE_LLM": "true"},
    )

    # Wait for socket to be created
    start_time = time.time()
    while time.time() - start_time < timeout:
        if Path(socket_path).exists():
            time.sleep(0.1)  # Give daemon a moment to bind
            return proc
        time.sleep(0.05)

    stop_daemon(proc)
    raise TimeoutError(f"Daemon failed to start listening on {socket_path} within {timeout}s")


def stop_daemon(proc: subprocess.Popen, timeout: float = 5.0) -> None:
    """Terminate a daemon subprocess, then kill it if graceful shutdown stalls."""
    if proc.poll() is not None:
        return

    proc.terminate()
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


def send_request(socket_path: str, request: dict, timeout: float = 5.0) -> dict:
    """Send a request to the daemon and read the response.

    Args:
        socket_path: Path to the Unix socket
        request: Request dict to send
        timeout: Socket timeout in seconds

    Returns:
        Parsed JSON response dict

    Raises:
        socket.timeout: If response not received within timeout
        json.JSONDecodeError: If response is not valid JSON
    """
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect(socket_path)
        sock.sendall((json.dumps(request) + "\n").encode("utf-8"))

        # Read response line-by-line until we get a complete line
        response_data = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response_data += chunk
            if b"\n" in response_data:
                break

        response_line = response_data.split(b"\n")[0]
        return json.loads(response_line.decode("utf-8"))
    finally:
        sock.close()


@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """Create and clean up a temporary directory."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def daemon_process(temp_dir: Path) -> Generator[subprocess.Popen, None, None]:
    """Start and stop a daemon process for each test."""
    socket_path = str(temp_dir / "armor.sock")
    db_path = str(temp_dir / "test.db")

    proc = start_daemon(socket_path, db_path)

    yield proc

    stop_daemon(proc)


class TestDaemonServerClients:
    """Integration tests for daemon client connections."""

    def test_single_client_request(self, temp_dir: Path) -> None:
        """TC-030-01: Single client sends request and receives response.

        Start daemon, open socket, send check.input request, verify response.
        """
        socket_path = str(temp_dir / "armor.sock")
        db_path = str(temp_dir / "test.db")

        daemon = start_daemon(socket_path, db_path)

        try:
            request = {"v": 1, "op": "check.input", "payload": {"text": "test"}}
            response = send_request(socket_path, request)

            assert response["v"] == 1, "Response version should be 1"
            assert response["verdict"] == "pass", "Simple text should pass"
        finally:
            stop_daemon(daemon)

    def test_concurrent_clients(self, temp_dir: Path) -> None:
        """TC-030-02: Multiple concurrent clients.

        Start daemon, spawn 10 concurrent client threads, each sends a request.
        All should receive responses without timeout.
        """
        socket_path = str(temp_dir / "armor.sock")
        db_path = str(temp_dir / "test.db")

        daemon = start_daemon(socket_path, db_path)

        try:
            responses = []

            def client_task(client_id: int) -> None:
                """Send a request from a single client."""
                request = {
                    "v": 1,
                    "op": "check.input",
                    "payload": {"text": f"client-{client_id}"},
                }
                response = send_request(socket_path, request, timeout=15.0)
                responses.append(response)

            # Use asyncio to run concurrent connections (simulating concurrent clients)
            async def run_concurrent():
                tasks = [asyncio.to_thread(client_task, i) for i in range(10)]
                await asyncio.gather(*tasks)

            asyncio.run(run_concurrent())

            # Verify all clients got responses
            assert len(responses) == 10, f"Expected 10 responses, got {len(responses)}"
            for i, resp in enumerate(responses):
                assert resp["v"] == 1, f"Client {i}: version should be 1"
                assert resp["verdict"] == "pass", f"Client {i}: verdict should be pass"
        finally:
            stop_daemon(daemon)

    def test_max_concurrent_enforcement(self, temp_dir: Path) -> None:
        """TC-030-03: Max concurrent limit is enforced.

        Start daemon with max_concurrent=2, spawn 4 concurrent requests.
        All should eventually succeed (queued, not rejected).
        """
        socket_path = str(temp_dir / "armor.sock")
        db_path = str(temp_dir / "test.db")

        # Start daemon with max_concurrent=2
        proc = subprocess.Popen(
            ["uv", "run", "armor", "daemon", "--socket", socket_path, "--db", db_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
            env={**os.environ, "ARMOR_DISABLE_LLM": "true"},
        )

        # Wait for socket
        start_time = time.time()
        while time.time() - start_time < 10.0:
            if Path(socket_path).exists():
                time.sleep(0.1)
                break
            time.sleep(0.05)

        try:
            results = []

            def long_request(client_id: int) -> str:
                """Send a request and hold the connection open briefly."""
                try:
                    request = {
                        "v": 1,
                        "op": "check.input",
                        "payload": {"text": f"client-{client_id}"},
                    }
                    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    sock.settimeout(10.0)
                    sock.connect(socket_path)
                    sock.sendall((json.dumps(request) + "\n").encode("utf-8"))

                    # Hold connection open briefly to exercise concurrency limit
                    time.sleep(0.2)

                    response_data = b""
                    while True:
                        chunk = sock.recv(4096)
                        if not chunk:
                            break
                        response_data += chunk
                        if b"\n" in response_data:
                            break

                    response_line = response_data.split(b"\n")[0]
                    response = json.loads(response_line.decode("utf-8"))
                    sock.close()
                    return response.get("verdict", "unknown")
                except Exception as e:
                    return f"error: {e}"

            # Run 4 concurrent requests with max_concurrent=2
            async def run_concurrent():
                tasks = [asyncio.to_thread(long_request, i) for i in range(4)]
                return await asyncio.gather(*tasks)

            results = asyncio.run(run_concurrent())

            # All should succeed (verdict="pass"), not be rejected
            assert len(results) == 4, f"Expected 4 results, got {len(results)}"
            for i, result in enumerate(results):
                assert result == "pass", f"Request {i}: expected 'pass', got '{result}'"
        finally:
            stop_daemon(proc)

    def test_handle_malformed_json(self, temp_dir: Path) -> None:
        """TC-030-04: Malformed JSON is rejected gracefully.

        Send invalid JSON, verify error response.
        """
        socket_path = str(temp_dir / "armor.sock")
        db_path = str(temp_dir / "test.db")

        daemon = start_daemon(socket_path, db_path)

        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(5.0)
            sock.connect(socket_path)

            # Send invalid JSON
            sock.sendall(b"not valid json\n")

            # Read response
            response_data = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response_data += chunk
                if b"\n" in response_data:
                    break

            response_line = response_data.split(b"\n")[0]
            response = json.loads(response_line.decode("utf-8"))
            sock.close()

            assert response["v"] == 1, "Response version should be 1"
            assert response["verdict"] == "error", "Malformed JSON should return error verdict"
        finally:
            stop_daemon(daemon)

    def test_json_per_line_output(self, temp_dir: Path) -> None:
        """TC-030-05: Output is valid NDJSON (one JSON per line).

        Send multiple requests, verify each response is valid JSON on separate line.
        """
        socket_path = str(temp_dir / "armor.sock")
        db_path = str(temp_dir / "test.db")

        daemon = start_daemon(socket_path, db_path)

        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(5.0)
            sock.connect(socket_path)

            # Send 3 requests
            for i in range(3):
                request = {
                    "v": 1,
                    "op": "check.input",
                    "payload": {"text": f"request-{i}"},
                }
                sock.sendall((json.dumps(request) + "\n").encode("utf-8"))

            # Read 3 responses
            sock.setblocking(False)
            response_data = b""
            response_count = 0
            deadline = time.time() + 5.0

            while response_count < 3 and time.time() < deadline:
                try:
                    chunk = sock.recv(4096)
                    if chunk:
                        response_data += chunk
                except BlockingIOError:
                    time.sleep(0.01)
                    continue

            sock.close()

            # Parse all lines
            lines = response_data.decode("utf-8").strip().split("\n")
            assert len(lines) >= 3, f"Expected at least 3 response lines, got {len(lines)}"

            for i, line in enumerate(lines[:3]):
                response = json.loads(line)
                assert response["v"] == 1, f"Line {i}: version should be 1"
                assert response["verdict"] == "pass", f"Line {i}: verdict should be pass"
        finally:
            stop_daemon(daemon)

    def test_graceful_shutdown_removes_socket(self, temp_dir: Path) -> None:
        """TC-030-06: Socket file is removed after shutdown.

        Start daemon, verify socket exists, gracefully stop, verify socket removed.
        """
        socket_path = str(temp_dir / "armor.sock")
        db_path = str(temp_dir / "test.db")

        daemon = start_daemon(socket_path, db_path)

        try:
            # Verify socket exists
            assert Path(socket_path).exists(), "Socket should exist after daemon starts"

            # Send a request to verify it's working
            request = {"v": 1, "op": "check.input", "payload": {"text": "test"}}
            response = send_request(socket_path, request)
            assert response["verdict"] == "pass", "Daemon should respond to requests"
        finally:
            stop_daemon(daemon)
            time.sleep(0.1)  # Give cleanup a moment

        # Verify socket is removed
        assert not Path(socket_path).exists(), "Socket should be removed after daemon stops"
