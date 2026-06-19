# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the DaemonClient."""

import json
import os
import socket
import tempfile
from unittest.mock import Mock, patch

import pytest

from armor.client import DaemonClient, DaemonUnreachableError


class TestDaemonClientInit:
    """Tests for DaemonClient initialization."""

    def test_init_default_socket_path(self) -> None:
        """Test default socket path."""
        client = DaemonClient()
        assert client.socket_path == "/var/run/armor.sock"

    def test_init_custom_socket_path(self) -> None:
        """Test custom socket path."""
        client = DaemonClient(socket_path="/tmp/custom.sock")
        assert client.socket_path == "/tmp/custom.sock"

    def test_init_from_env_var(self) -> None:
        """Test socket path from ARMOR_SOCKET env var."""
        with patch.dict(os.environ, {"ARMOR_SOCKET": "/tmp/env.sock"}):
            client = DaemonClient()
            assert client.socket_path == "/tmp/env.sock"

    def test_init_explicit_path_overrides_env(self) -> None:
        """Test that explicit path overrides env var."""
        with patch.dict(os.environ, {"ARMOR_SOCKET": "/tmp/env.sock"}):
            client = DaemonClient(socket_path="/tmp/explicit.sock")
            assert client.socket_path == "/tmp/explicit.sock"


class TestDaemonClientRequest:
    """Tests for DaemonClient.request method."""

    def test_request_socket_not_exists(self) -> None:
        """Test that requesting raises DaemonUnreachableError if socket doesn't exist."""
        client = DaemonClient(socket_path="/tmp/nonexistent.sock")

        with pytest.raises(DaemonUnreachableError, match="Socket does not exist"):
            client.request("check.input", payload={"text": "test"})

    def test_request_valid_response(self) -> None:
        """Test successful request/response."""
        with tempfile.TemporaryDirectory() as tmpdir:
            socket_path = os.path.join(tmpdir, "test.sock")

            # Create a simple socket server that responds
            server_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            server_sock.bind(socket_path)
            server_sock.listen(1)

            # Send request in a separate context
            client = DaemonClient(socket_path=socket_path)

            # Mock the socket.socket to return a mock that behaves correctly
            mock_response = {"v": 1, "verdict": "pass"}

            with patch("socket.socket") as mock_socket_class:
                mock_sock = Mock()
                mock_socket_class.return_value = mock_sock
                mock_sock.recv.return_value = json.dumps(mock_response).encode("utf-8") + b"\n"

                result = client.request("check.input", payload={"text": "test"})
                assert result == mock_response
                mock_sock.connect.assert_called_once_with(socket_path)
                mock_sock.close.assert_called_once()

    def test_request_with_session_id(self) -> None:
        """Test that session_id is included in request."""
        client = DaemonClient(socket_path="/tmp/test.sock")
        mock_response = {"v": 1, "verdict": "pass"}

        with patch("socket.socket") as mock_socket_class:
            mock_sock = Mock()
            mock_socket_class.return_value = mock_sock
            mock_sock.recv.return_value = json.dumps(mock_response).encode("utf-8") + b"\n"

            with patch("os.path.exists", return_value=True):
                result = client.request(
                    "check.input",
                    payload={"text": "test"},
                    session_id="test-session",
                )

                # Verify the request was sent with session_id
                sent_data = mock_sock.sendall.call_args[0][0]
                sent_json = json.loads(sent_data.decode("utf-8").strip())
                assert sent_json["session_id"] == "test-session"
                assert result == mock_response

    def test_request_without_session_id(self) -> None:
        """Test that request works without session_id."""
        client = DaemonClient(socket_path="/tmp/test.sock")
        mock_response = {"v": 1, "verdict": "pass"}

        with patch("socket.socket") as mock_socket_class:
            mock_sock = Mock()
            mock_socket_class.return_value = mock_sock
            mock_sock.recv.return_value = json.dumps(mock_response).encode("utf-8") + b"\n"

            with patch("os.path.exists", return_value=True):
                result = client.request(
                    "check.input",
                    payload={"text": "test"},
                )

                # Verify session_id not in request
                sent_data = mock_sock.sendall.call_args[0][0]
                sent_json = json.loads(sent_data.decode("utf-8").strip())
                assert "session_id" not in sent_json
                assert result == mock_response

    def test_request_without_payload(self) -> None:
        """Test request without payload (e.g. for canary.list)."""
        client = DaemonClient(socket_path="/tmp/test.sock")
        mock_response = {"v": 1, "verdict": "pass", "canaries": []}

        with patch("socket.socket") as mock_socket_class:
            mock_sock = Mock()
            mock_socket_class.return_value = mock_sock
            mock_sock.recv.return_value = json.dumps(mock_response).encode("utf-8") + b"\n"

            with patch("os.path.exists", return_value=True):
                result = client.request("canary.list")

                sent_data = mock_sock.sendall.call_args[0][0]
                sent_json = json.loads(sent_data.decode("utf-8").strip())
                assert "payload" not in sent_json
                assert result == mock_response

    def test_request_malformed_response(self) -> None:
        """Test handling of malformed JSON response."""
        client = DaemonClient(socket_path="/tmp/test.sock")

        with patch("socket.socket") as mock_socket_class:
            mock_sock = Mock()
            mock_socket_class.return_value = mock_sock
            mock_sock.recv.return_value = b"not valid json\n"

            with patch("os.path.exists", return_value=True), pytest.raises(json.JSONDecodeError):
                client.request("check.input", payload={"text": "test"})

    def test_request_connection_refused(self) -> None:
        """Test handling of connection refused."""
        client = DaemonClient(socket_path="/tmp/test.sock")

        with (
            patch("socket.socket") as mock_socket_class,
            patch("os.path.exists", return_value=True),
            pytest.raises(DaemonUnreachableError, match="Connection refused"),
        ):
            mock_sock = Mock()
            mock_socket_class.return_value = mock_sock
            mock_sock.connect.side_effect = ConnectionRefusedError("Connection refused")
            client.request("check.input", payload={"text": "test"})

    def test_request_socket_error(self) -> None:
        """Test handling of socket errors."""
        client = DaemonClient(socket_path="/tmp/test.sock")

        with (
            patch("socket.socket") as mock_socket_class,
            patch("os.path.exists", return_value=True),
            pytest.raises(DaemonUnreachableError, match="Socket error"),
        ):
            mock_sock = Mock()
            mock_socket_class.return_value = mock_sock
            mock_sock.connect.side_effect = OSError("Socket error")
            client.request("check.input", payload={"text": "test"})

    def test_request_empty_response(self) -> None:
        """Test handling of empty response."""
        client = DaemonClient(socket_path="/tmp/test.sock")

        with (
            patch("socket.socket") as mock_socket_class,
            patch("os.path.exists", return_value=True),
            pytest.raises(DaemonUnreachableError, match="Empty response"),
        ):
            mock_sock = Mock()
            mock_socket_class.return_value = mock_sock
            mock_sock.recv.return_value = b"\n"
            client.request("check.input", payload={"text": "test"})
