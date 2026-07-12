# SPDX-License-Identifier: Apache-2.0
"""Unit tests for `AuditTrailEmitter` (task 134, ADR-045).

TC-134-01 through TC-134-08, the unit half of TC-134-12, and TC-134-13.
"""

from __future__ import annotations

import json
import logging
import socket
import threading
import time
from pathlib import Path
from typing import Any

import pytest

from armor.audit_trail import AuditTrailEmitter

SAMPLE_EVENT_KWARGS: dict[str, Any] = {
    "ts": 1752192000,
    "operation": "check.input",
    "session_id": "sess-42",
    "incident_id": 17,
    "signal_id": "regex.instruction_override:imperative",
    "attack_category": "direct_injection.instruction_override",
    "severity": "high",
    "source": "user_input",
}

EXPECTED_EVENT: dict[str, Any] = {
    "ts": 1752192000,
    "actor": "armor",
    "action": "check_input",
    "target": "sess-42",
    "decision": "block",
    "refs": [{"type": "incident", "id": "17"}],
    "context": {
        "signal_id": "regex.instruction_override:imperative",
        "attack_category": "direct_injection.instruction_override",
        "severity": "high",
        "source": "user_input",
    },
}


class _FakeAuditTrailServer:
    """A minimal AF_UNIX server that reads NDJSON lines and replies per a script.

    `responses` is a callable: given the decoded request dict, returns the
    response dict to send back. The server accepts exactly one connection and
    reads lines from it until the client closes or `max_lines` is reached.
    """

    def __init__(self, socket_path: str, respond: Any, max_lines: int = 1) -> None:
        self.socket_path = socket_path
        self.respond = respond
        self.max_lines = max_lines
        self.received: list[dict[str, Any]] = []
        self._thread: threading.Thread | None = None
        self._server_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._server_sock.bind(socket_path)
        self._server_sock.listen(1)

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        conn, _ = self._server_sock.accept()
        try:
            buf = b""
            while len(self.received) < self.max_lines:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    req = json.loads(line.decode("utf-8"))
                    self.received.append(req)
                    resp = self.respond(req)
                    conn.sendall((json.dumps(resp) + "\n").encode("utf-8"))
        finally:
            conn.close()
            self._server_sock.close()

    def join(self, timeout: float = 5.0) -> None:
        if self._thread is not None:
            self._thread.join(timeout=timeout)


class _HangingServer:
    """Accepts a connection and never responds (for timeout testing)."""

    def __init__(self, socket_path: str) -> None:
        self.socket_path = socket_path
        self._server_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._server_sock.bind(socket_path)
        self._server_sock.listen(1)
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def _run(self) -> None:
        conn, _ = self._server_sock.accept()
        # Never respond; keep the connection open briefly then close.
        time.sleep(2.0)
        conn.close()
        self._server_sock.close()


@pytest.fixture
def sample_event() -> dict[str, Any]:
    return AuditTrailEmitter.build_event(**SAMPLE_EVENT_KWARGS)


class TestBuildEvent:
    def test_tc_134_01_exact_contract_event(self, sample_event: dict[str, Any]) -> None:
        assert sample_event == EXPECTED_EVENT
        assert isinstance(sample_event["ts"], int)
        assert sample_event["refs"][0]["id"] == "17"
        assert isinstance(sample_event["refs"][0]["id"], str)

    def test_tc_134_02_floats_stringified(self) -> None:
        event = AuditTrailEmitter.build_event(**SAMPLE_EVENT_KWARGS, context_extras={"confidence": 0.7})
        assert event["context"]["confidence"] == "0.7"
        assert not any(isinstance(v, float) for v in event["context"].values())

    def test_bools_dropped_from_context_extras(self) -> None:
        event = AuditTrailEmitter.build_event(**SAMPLE_EVENT_KWARGS, context_extras={"is_retry": True, "n": 3})
        assert "is_retry" not in event["context"]
        assert event["context"]["n"] == 3

    def test_source_tool_included_when_present(self) -> None:
        kwargs = dict(SAMPLE_EVENT_KWARGS)
        kwargs["operation"] = "check.fetched"
        event = AuditTrailEmitter.build_event(**kwargs, source_tool="WebFetch")
        assert event["context"]["source_tool"] == "WebFetch"

    def test_tc_134_12_context_is_an_allowlist(self, sample_event: dict[str, Any]) -> None:
        assert set(sample_event["context"].keys()) <= {
            "signal_id",
            "attack_category",
            "severity",
            "source",
            "source_tool",
        }


class TestEmitSuccess:
    def test_tc_134_03_success_sends_one_line_returns_seq_hash(
        self, tmp_path: Path, sample_event: dict[str, Any]
    ) -> None:
        socket_path = str(tmp_path / "at.sock")
        server = _FakeAuditTrailServer(socket_path, respond=lambda req: {"seq": 1, "hash": "ab" * 32}, max_lines=1)
        server.start()

        emitter = AuditTrailEmitter(socket_path=socket_path)
        result = emitter.emit(sample_event)
        server.join()

        assert len(server.received) == 1
        assert server.received[0] == {"op": "emit", "event": sample_event}
        assert result == {"seq": 1, "hash": "ab" * 32}

    def test_tc_134_12_no_payload_text_or_canary_leak(self, tmp_path: Path, sample_event: dict[str, Any]) -> None:
        socket_path = str(tmp_path / "at.sock")
        server = _FakeAuditTrailServer(socket_path, respond=lambda req: {"seq": 1, "hash": "ab" * 32}, max_lines=1)
        server.start()

        emitter = AuditTrailEmitter(socket_path=socket_path)
        emitter.emit(sample_event)
        server.join()

        line = json.dumps(server.received[0])
        assert "Ignore previous instructions" not in line


class TestEmitTransportFailure:
    def test_tc_134_04_absent_socket_buffers_never_raises(self, tmp_path: Path, sample_event: dict[str, Any]) -> None:
        emitter = AuditTrailEmitter(socket_path=str(tmp_path / "missing.sock"))
        result = emitter.emit(sample_event)
        assert result is None
        assert len(emitter.retry_buffer) == 1
        assert emitter.retry_buffer[0] == sample_event

    def test_tc_134_05_retry_buffer_bounded_oldest_dropped(self, tmp_path: Path) -> None:
        emitter = AuditTrailEmitter(socket_path=str(tmp_path / "missing.sock"), retry_buffer_size=4)
        for i in range(6):
            kwargs = dict(SAMPLE_EVENT_KWARGS)
            kwargs["session_id"] = f"s{i}"
            event = AuditTrailEmitter.build_event(**kwargs)
            emitter.emit(event)

        assert len(emitter.retry_buffer) == 4
        assert [e["target"] for e in emitter.retry_buffer] == ["s2", "s3", "s4", "s5"]

    def test_tc_134_06_unresponsive_socket_timeout_honored(self, tmp_path: Path, sample_event: dict[str, Any]) -> None:
        socket_path = str(tmp_path / "hanging.sock")
        server = _HangingServer(socket_path)
        server.start()

        emitter = AuditTrailEmitter(socket_path=socket_path, timeout_ms=200)
        start = time.monotonic()
        result = emitter.emit(sample_event)
        elapsed = time.monotonic() - start

        assert result is None
        assert elapsed < 1.0
        assert len(emitter.retry_buffer) == 1


class TestEmitFlush:
    def test_tc_134_07_buffered_events_flush_oldest_first(self, tmp_path: Path) -> None:
        socket_path = str(tmp_path / "at.sock")

        def build(session_id: str) -> dict[str, Any]:
            kwargs = dict(SAMPLE_EVENT_KWARGS)
            kwargs["session_id"] = session_id
            return AuditTrailEmitter.build_event(**kwargs)

        event_a = build("s-a")
        event_b = build("s-b")
        event_c = build("s-c")

        # Socket absent: A and B get buffered.
        emitter = AuditTrailEmitter(socket_path=socket_path)
        emitter.emit(event_a)
        emitter.emit(event_b)
        assert len(emitter.retry_buffer) == 2

        # Now start the server and emit C: expect A, B, C flushed in order.
        server = _FakeAuditTrailServer(socket_path, respond=lambda req: {"seq": 1, "hash": "cd" * 32}, max_lines=3)
        server.start()

        result = emitter.emit(event_c)
        server.join()

        assert len(server.received) == 3
        assert [r["event"]["target"] for r in server.received] == ["s-a", "s-b", "s-c"]
        assert len(emitter.retry_buffer) == 0
        assert result == {"seq": 1, "hash": "cd" * 32}


class TestEmitContractError:
    def test_tc_134_08_error_response_dropped_not_buffered(
        self, tmp_path: Path, sample_event: dict[str, Any], caplog: pytest.LogCaptureFixture
    ) -> None:
        socket_path = str(tmp_path / "at.sock")
        server = _FakeAuditTrailServer(
            socket_path,
            respond=lambda req: {"error": {"code": "invalid_event", "message": "floats are not allowed"}},
            max_lines=1,
        )
        server.start()

        emitter = AuditTrailEmitter(socket_path=socket_path)
        with caplog.at_level(logging.ERROR):
            result = emitter.emit(sample_event)
        server.join()

        assert result is None
        assert len(emitter.retry_buffer) == 0
        assert any("invalid_event" in record.message for record in caplog.records)


class TestBundledConfig:
    def test_tc_134_13_armor_toml_has_audit_trail_block(self) -> None:
        import tomllib

        repo_root = Path(__file__).resolve().parents[2]
        with (repo_root / "armor.toml").open("rb") as f:
            config = tomllib.load(f)

        assert config["audit_trail"]["enabled"] is False
        assert config["audit_trail"]["socket"] == "/var/run/audit-trail.sock"
        assert config["audit_trail"]["timeout_ms"] == 250
        assert config["audit_trail"]["retry_buffer_size"] == 256
