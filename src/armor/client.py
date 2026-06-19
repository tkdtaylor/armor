# SPDX-License-Identifier: Apache-2.0
"""Sync IPC client for the armor daemon.

Used by the CLI and other tools to communicate with the daemon over Unix socket.
"""

import json
import logging
import os
import socket
from typing import Any

logger = logging.getLogger(__name__)


class DaemonUnreachableError(Exception):
    """Raised when the daemon cannot be reached."""

    pass


class DaemonClient:
    """Sync Unix socket client for the armor daemon.

    This is a minimal, blocking IPC client used by the CLI and other tools.
    It sends NDJSON requests and reads NDJSON responses from the daemon.
    """

    def __init__(self, socket_path: str | None = None) -> None:
        """Initialize the client.

        Args:
            socket_path: Path to the daemon socket. Defaults to ARMOR_SOCKET env var
                        or /var/run/armor.sock.

        Raises:
            DaemonUnreachableError: If the socket path is invalid or doesn't exist.
        """
        if socket_path is None:
            socket_path = os.environ.get("ARMOR_SOCKET", "/var/run/armor.sock")

        self.socket_path = socket_path

    def request(self, op: str, payload: dict[str, Any] | None = None, session_id: str | None = None) -> dict[str, Any]:
        """Send a request to the daemon and get the response.

        Args:
            op: Operation type (e.g., "check.input", "session.close", "canary.list").
            payload: Optional payload dict (specific to the operation).
            session_id: Optional session ID. If not provided, daemon assigns one.

        Returns:
            Response dict from the daemon.

        Raises:
            DaemonUnreachableError: If connection fails or socket doesn't exist.
            json.JSONDecodeError: If response is malformed JSON.
            Exception: For any other I/O error.
        """
        # Check if socket exists first
        if not os.path.exists(self.socket_path):
            raise DaemonUnreachableError(f"Socket does not exist: {self.socket_path}")

        # Build request
        request_dict: dict[str, Any] = {
            "v": 1,
            "op": op,
        }

        if session_id is not None:
            request_dict["session_id"] = session_id

        if payload is not None:
            request_dict["payload"] = payload

        # Send request and read response
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.connect(self.socket_path)

            # Send request as NDJSON
            request_json = json.dumps(request_dict)
            sock.sendall((request_json + "\n").encode("utf-8"))

            # Read response (one line of NDJSON)
            response_data = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response_data += chunk
                if b"\n" in response_data:
                    break

            sock.close()

            # Parse response
            response_line = response_data.split(b"\n")[0]
            if not response_line:
                raise DaemonUnreachableError("Empty response from daemon")

            response_dict: dict[str, Any] = json.loads(response_line.decode("utf-8"))
            return response_dict

        except FileNotFoundError as e:
            raise DaemonUnreachableError(f"Socket not found: {self.socket_path}") from e
        except ConnectionRefusedError as e:
            raise DaemonUnreachableError(f"Connection refused: {self.socket_path}") from e
        except OSError as e:
            raise DaemonUnreachableError(f"Socket error: {e}") from e
