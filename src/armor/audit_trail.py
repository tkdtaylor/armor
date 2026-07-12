# SPDX-License-Identifier: Apache-2.0
"""Emit blocking incidents to the sibling audit-trail block's forensic log (task 134).

`AuditTrailEmitter` is the only place in armor that opens a socket to the
ecosystem's audit-trail block. It deliberately lives OUTSIDE `src/armor/daemon/`:
`tests/fitness/test_no_outbound_network.py` (TC-091-14) bans `socket` imports
under the daemon tree, and this module's whole job is to hold that one `socket`
import so the daemon package itself stays clean. See ADR-045 for why a Unix
domain socket does not count as "outbound network" under that invariant.

Fail-safe is the load-bearing property: armor's own blocking behavior must
never depend on the audit-trail socket being reachable. `emit()` never raises;
on any transport failure it logs, buffers the event (bounded, oldest dropped),
and returns `None`.
"""

from __future__ import annotations

import json
import logging
import socket
from collections import deque
from typing import Any

logger = logging.getLogger(__name__)

# audit-trail's frozen v1 contract context allowlist (docs/CONTRACT.md, sibling repo).
_CONTEXT_KEYS = ("signal_id", "attack_category", "severity", "source", "source_tool")


class AuditTrailEmitter:
    """Emits blocking-verdict events to an audit-trail daemon over AF_UNIX.

    Attributes:
        socket_path: Path to the audit-trail daemon's Unix socket.
        timeout_ms: Connect/read timeout in milliseconds (default 250).
        retry_buffer: Bounded deque of events that failed to send due to a
            transport failure (socket absent, refused, or timed out). Exposed
            for tests and for operator visibility; not persisted across restarts.
    """

    def __init__(self, socket_path: str, timeout_ms: int = 250, retry_buffer_size: int = 256) -> None:
        """Initialize the emitter.

        Args:
            socket_path: Path to the audit-trail daemon's Unix socket.
            timeout_ms: Connect/read timeout in milliseconds.
            retry_buffer_size: Max number of buffered events kept on transport
                failure; oldest is dropped first once full.
        """
        self.socket_path = socket_path
        self.timeout_ms = timeout_ms
        self.retry_buffer: deque[dict[str, Any]] = deque(maxlen=retry_buffer_size)

    @staticmethod
    def build_event(
        ts: int,
        operation: str,
        session_id: str,
        incident_id: int,
        signal_id: str,
        attack_category: str,
        severity: str,
        source: str,
        source_tool: str | None = None,
        context_extras: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Build a contract-v1 event dict for a blocked incident. Pure, no I/O.

        Args:
            ts: Unix seconds (caller passes `int(time.time())`; injectable for tests).
            operation: The check operation, e.g. `"check.input"`.
            session_id: The session id (becomes `target`).
            incident_id: The SQLite `Incident` row id just written (becomes `refs[0].id`).
            signal_id: The detector signal id that tripped.
            attack_category: The inferred attack category (same value the SQLite
                row gets, via `ForensicLogger.infer_category`).
            severity: The verdict severity.
            source: The payload source (`str(Payload.source)`).
            source_tool: For `check.fetched`, the originating tool name, when present.
            context_extras: Optional additional context values. Floats are
                stringified with `str()`; bools are dropped (contract allows
                string/int values only).

        Returns:
            An event dict matching audit-trail's frozen v1 contract shape.
        """
        context: dict[str, Any] = {
            "signal_id": signal_id,
            "attack_category": attack_category,
            "severity": severity,
            "source": source,
        }
        if source_tool is not None:
            context["source_tool"] = source_tool

        if context_extras:
            for key, value in context_extras.items():
                if isinstance(value, bool):
                    # Bools are excluded entirely (contract allows string/int only).
                    continue
                if isinstance(value, float):
                    context[key] = str(value)
                else:
                    context[key] = value

        return {
            "ts": ts,
            "actor": "armor",
            "action": operation.replace(".", "_"),
            "target": session_id,
            "decision": "block",
            "refs": [{"type": "incident", "id": str(incident_id)}],
            "context": context,
        }

    def emit(self, event: dict[str, Any]) -> dict[str, Any] | None:
        """Send `event` to the audit-trail daemon, flushing any buffered backlog first.

        Synchronous by design; the daemon calls this via `asyncio.to_thread`,
        mirroring `ForensicLogger.write_incident`.

        Never raises. On transport failure (socket path absent, connection
        refused, timed out, or any other `OSError`) logs a warning, buffers the
        event (and any unflushed backlog), and returns `None`. On a contract
        error response (`{"error": {...}}`), logs at ERROR and drops the event
        without buffering it (a rejected event is permanently invalid).

        Args:
            event: An event dict, typically from `build_event`.

        Returns:
            The parsed success response (contains `seq`/`hash`) on success, else `None`.
        """
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(self.timeout_ms / 1000.0)
            sock.connect(self.socket_path)
        except OSError as exc:
            logger.warning("audit-trail emit: connect to %s failed (%s); buffering event", self.socket_path, exc)
            self.retry_buffer.append(event)
            return None

        try:
            # Flush the backlog oldest-first before sending the new event. If a
            # buffered event hits a transport failure partway through, stop:
            # the unsent buffered events and the new event all remain buffered.
            while self.retry_buffer:
                buffered_event = self.retry_buffer[0]
                status, _ = self._send_one(sock, buffered_event)
                if status == "transport_fail":
                    self.retry_buffer.append(event)
                    return None
                # "success" or "error" both consume this buffered slot: a
                # successfully-flushed event is done, and a rejected one is
                # permanently invalid either way.
                self.retry_buffer.popleft()

            status, response = self._send_one(sock, event)
            if status == "success":
                return response
            if status == "transport_fail":
                self.retry_buffer.append(event)
                return None
            # status == "error": logged inside _send_one; drop, do not buffer.
            return None
        finally:
            sock.close()

    def _send_one(self, sock: socket.socket, event: dict[str, Any]) -> tuple[str, dict[str, Any] | None]:
        """Send one NDJSON emit line on `sock` and read one response line.

        Returns:
            `("success", response)`, `("error", None)`, or `("transport_fail", None)`.
        """
        line = json.dumps({"op": "emit", "event": event}) + "\n"
        try:
            sock.sendall(line.encode("utf-8"))
            raw = self._recv_line(sock)
        except OSError as exc:
            logger.warning("audit-trail emit: transport failure sending event (%s)", exc)
            return "transport_fail", None

        if raw is None:
            logger.warning("audit-trail emit: connection closed before a response was received")
            return "transport_fail", None

        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as exc:
            logger.warning("audit-trail emit: malformed response (%s)", exc)
            return "transport_fail", None

        if isinstance(parsed, dict) and "error" in parsed:
            error = parsed["error"] or {}
            code = error.get("code") if isinstance(error, dict) else error
            message = error.get("message") if isinstance(error, dict) else ""
            logger.error("audit-trail emit: rejected by contract (code=%s): %s", code, message)
            return "error", None

        return "success", parsed

    @staticmethod
    def _recv_line(sock: socket.socket) -> str | None:
        """Read bytes from `sock` until a newline is seen; return the line (no trailing `\\n`).

        Returns `None` if the connection closes before a newline arrives.
        Raises `socket.timeout`/`OSError` on transport failure (handled by the caller).
        """
        buf = b""
        while b"\n" not in buf:
            chunk = sock.recv(4096)
            if not chunk:
                return None
            buf += chunk
        return buf.split(b"\n", 1)[0].decode("utf-8")
