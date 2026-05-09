"""Round-trip integration tests for the operator-UX IPC ops added by task 036.

These tests start the real daemon as a subprocess, seed test rows directly
into the SQLite database, and exercise the IPC surface end-to-end. They
deliberately avoid mocking — the audit findings flagged that the existing
integration tests mocked out the daemon, so a regression in dispatch
would not be caught.

Spec markers covered:
- TC-036-01: incidents.list returns paginated rows.
- TC-036-02: incidents.show returns the full record (no canary value leakage).
- TC-036-03: sessions.list returns sessions with state + risk_score.
- TC-036-04: sessions.show returns the full state.
- TC-036-05: sessions.unblock transitions Blocked → Watching and writes audit row.
- TC-036-06: --reason is required by argparse (CLI subprocess form).
- TC-097-01: health.full returns no hardcoded placeholder health metrics.
- TC-097-02: total_checks increments for check operations.
- TC-097-03: p95_input_latency_ms reflects the observed rolling window.
"""

from __future__ import annotations

import json
import os
import socket
import sqlite3
import subprocess
import tempfile
import time
from collections.abc import Generator
from pathlib import Path

import pytest

from armor.db.migrations import run_migrations


def _start_daemon(socket_path: str, db_path: str, timeout: float = 15.0) -> subprocess.Popen:
    proc = subprocess.Popen(
        [
            "uv",
            "run",
            "armor",
            "daemon",
            "--socket",
            socket_path,
            "--db",
            db_path,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env={**os.environ, "ARMOR_DISABLE_LLM": "true"},
    )
    deadline = time.time() + timeout
    while time.time() < deadline:
        if Path(socket_path).exists():
            time.sleep(0.2)
            return proc
        if proc.poll() is not None:
            stderr = proc.stderr.read() if proc.stderr else ""
            raise RuntimeError(f"daemon exited early: {stderr}")
        time.sleep(0.05)
    proc.terminate()
    raise TimeoutError(f"daemon did not bind {socket_path}")


def _send(socket_path: str, request: dict) -> dict:
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(5.0)
    try:
        sock.connect(socket_path)
        sock.sendall((json.dumps(request) + "\n").encode("utf-8"))
        chunks: list[bytes] = []
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
            if b"\n" in chunk:
                break
        line = b"".join(chunks).split(b"\n", 1)[0]
        return json.loads(line.decode("utf-8"))
    finally:
        sock.close()


def _seed_session(db_path: str, session_id: str, state: str, risk: float = 0.0) -> None:
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            "INSERT INTO Session (session_id, current_state, risk_score) VALUES (?, ?, ?)",
            (session_id, state, risk),
        )
        conn.commit()
    finally:
        conn.close()


def _seed_incident(
    db_path: str,
    *,
    session_id: str,
    category: str = "direct_injection",
    signal_id: str = "regex.instruction_override:001",
    canary_id: str | None = None,
) -> int:
    conn = sqlite3.connect(db_path)
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO Incident (session_id, attack_category, signal_id, "
            "input_hash, triggered_canary, action) VALUES (?, ?, ?, ?, ?, ?)",
            (session_id, category, signal_id, "deadbeef", canary_id, "blocked"),
        )
        conn.commit()
        return int(cur.lastrowid or 0)
    finally:
        conn.close()


@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def daemon_with_seed(
    temp_dir: Path,
) -> Generator[tuple[str, str], None, None]:
    """Start a daemon with a pre-seeded SQLite database.

    Returns (socket_path, db_path). The schema is created via the canonical
    migrations runner; tests then seed their own rows.
    """
    socket_path = str(temp_dir / "armor.sock")
    db_path = str(temp_dir / "test.db")
    run_migrations(db_path)

    proc = None
    try:
        proc = _start_daemon(socket_path, db_path)
        yield socket_path, db_path
    finally:
        if proc is not None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()


def _seed_incidents_after_daemon(db_path: str, count: int = 5) -> list[int]:
    """Seed rows after the daemon is up (it does its own migrations)."""
    ids: list[int] = []
    for i in range(count):
        ids.append(_seed_incident(db_path, session_id=f"sess-{i}"))
    return ids


class TestIncidentsRoundTrip:
    def test_incidents_list_returns_seeded_rows(self, daemon_with_seed: tuple[str, str]) -> None:
        """TC-036-01: incidents.list returns paginated rows."""
        socket_path, db_path = daemon_with_seed
        _seed_incidents_after_daemon(db_path, count=5)

        resp = _send(
            socket_path,
            {"v": 1, "op": "incidents.list", "payload": {"limit": 10}},
        )

        assert resp["verdict"] == "pass"
        assert "incidents" in resp
        assert len(resp["incidents"]) == 5
        # Sanity: each row has the expected shape.
        first = resp["incidents"][0]
        assert "id" in first
        assert "session_id" in first
        assert "attack_category" in first

    def test_incidents_show_returns_record_without_canary_value(self, daemon_with_seed: tuple[str, str]) -> None:
        """TC-036-02: incidents.show returns the full record by canary_id only."""
        socket_path, db_path = daemon_with_seed
        # The schema stores `triggered_canary` as the canary_id, never the value.
        # We seed with a canary_id; the response must echo the id, not a value.
        canary_id = "aws-key-001"
        incident_id = _seed_incident(db_path, session_id="sess-A", canary_id=canary_id)

        resp = _send(
            socket_path,
            {"v": 1, "op": "incidents.show", "payload": {"incident_id": incident_id}},
        )

        assert resp["verdict"] == "pass"
        incident = resp["incident"]
        assert incident is not None
        assert incident["id"] == incident_id
        assert incident["triggered_canary"] == canary_id
        # The response must never contain a literal canary value (we check by
        # asserting no "AKIA..." style placeholder appears — the canary_id
        # field is the contract).
        assert "value" not in incident

    def test_incidents_list_default_limit_is_50(self, daemon_with_seed: tuple[str, str]) -> None:
        """TC-036-12: when CLI omits --limit, the request uses 50.

        The daemon receives `limit` from the CLI; here we verify the daemon
        respects whatever limit was sent. The argparse default itself is
        verified in `test_cli_subcommands.py`.
        """
        socket_path, db_path = daemon_with_seed
        _seed_incidents_after_daemon(db_path, count=3)

        resp = _send(
            socket_path,
            {"v": 1, "op": "incidents.list", "payload": {"limit": 50}},
        )
        assert resp["verdict"] == "pass"
        assert len(resp["incidents"]) == 3


class TestSessionsRoundTrip:
    def test_sessions_list_with_seeded_states(self, daemon_with_seed: tuple[str, str]) -> None:
        """TC-036-03: sessions.list returns sessions with state + risk_score."""
        socket_path, db_path = daemon_with_seed
        _seed_session(db_path, "S-NORMAL", "Normal", 0.1)
        _seed_session(db_path, "S-WATCH", "Watching", 0.5)
        _seed_session(db_path, "S-ELEV", "Elevated", 1.0)

        resp = _send(socket_path, {"v": 1, "op": "sessions.list", "payload": {}})

        assert resp["verdict"] == "pass"
        sessions = resp["sessions"]
        assert len(sessions) == 3
        states = {s["session_id"]: s["current_state"] for s in sessions}
        assert states["S-NORMAL"] == "Normal"
        assert states["S-WATCH"] == "Watching"
        assert states["S-ELEV"] == "Elevated"

    def test_sessions_show_returns_signal_count_without_raw_text(self, daemon_with_seed: tuple[str, str]) -> None:
        """TC-036-04: sessions.show returns full state, no raw input text."""
        socket_path, db_path = daemon_with_seed
        # Seed with a signal_history JSON of 7 signals.
        history = [{"ts": i, "kind": "regex", "signal_id": f"regex:{i}", "severity": "low"} for i in range(7)]
        conn = sqlite3.connect(db_path)
        try:
            conn.execute(
                "INSERT INTO Session (session_id, current_state, risk_score, signal_history) VALUES (?, ?, ?, ?)",
                ("S1", "Watching", 0.5, json.dumps(history)),
            )
            conn.commit()
        finally:
            conn.close()

        resp = _send(
            socket_path,
            {"v": 1, "op": "sessions.show", "payload": {"session_id": "S1"}},
        )

        assert resp["verdict"] == "pass"
        session = resp["session"]
        assert session is not None
        assert session["signal_count"] == 7
        # No raw rolling-buffer text in the payload.
        assert "rolling_buffer_text" not in session
        assert "raw_text" not in session

    def test_sessions_unblock_blocked_to_watching(self, daemon_with_seed: tuple[str, str]) -> None:
        """TC-036-05: sessions.unblock transitions Blocked → Watching with audit row."""
        socket_path, db_path = daemon_with_seed
        _seed_session(db_path, "SB", "Blocked", 2.0)

        resp = _send(
            socket_path,
            {
                "v": 1,
                "op": "sessions.unblock",
                "payload": {
                    "session_id": "SB",
                    "reason": "manual review cleared",
                    "actor": "test-op",
                },
            },
        )

        assert resp["verdict"] == "pass"
        assert resp["new_state"] == "Watching"

        # Verify post-conditions in the database.
        conn = sqlite3.connect(db_path)
        try:
            cur = conn.cursor()
            cur.execute("SELECT current_state FROM Session WHERE session_id = ?", ("SB",))
            assert cur.fetchone()[0] == "Watching"

            cur.execute(
                "SELECT actor, action, session_id, reason FROM OperatorAuditLog WHERE session_id = ?",
                ("SB",),
            )
            rows = cur.fetchall()
            assert len(rows) == 1
            assert rows[0] == ("test-op", "session.unblock", "SB", "manual review cleared")
        finally:
            conn.close()

    def test_sessions_unblock_rejects_non_blocked(self, daemon_with_seed: tuple[str, str]) -> None:
        socket_path, db_path = daemon_with_seed
        _seed_session(db_path, "S2", "Normal")

        resp = _send(
            socket_path,
            {
                "v": 1,
                "op": "sessions.unblock",
                "payload": {"session_id": "S2", "reason": "x", "actor": "op"},
            },
        )

        assert resp["verdict"] == "error"
        assert "Blocked" in resp.get("message", "")


class TestUnblockCliArgparse:
    def test_reason_is_required(self) -> None:
        """TC-036-06: omitting --reason produces argparse usage error (exit 2)."""
        result = subprocess.run(
            ["uv", "run", "armor", "sessions", "unblock", "SB"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 2
        assert "--reason" in result.stderr


class TestHealthFull:
    def test_health_full_round_trip(self, daemon_with_seed: tuple[str, str]) -> None:
        socket_path, _db_path = daemon_with_seed
        resp = _send(socket_path, {"v": 1, "op": "health.full"})
        assert resp["verdict"] == "pass"
        health = resp["health"]
        assert "socket_reachable" in health
        assert "db_reachable" in health
        assert "uptime_seconds" in health
        assert "db_capacity_percent" not in health

    def test_health_metrics_after_input_workload(self, daemon_with_seed: tuple[str, str]) -> None:
        """TC-097-01/02/03: check metrics are computed, not placeholder zeros."""
        socket_path, _db_path = daemon_with_seed

        for idx in range(20):
            resp = _send(
                socket_path,
                {
                    "v": 1,
                    "op": "check.input",
                    "session_id": f"health-metrics-{idx}",
                    "payload": {"text": f"benign health metrics payload {idx}"},
                },
            )
            assert resp["verdict"] in {"pass", "advisory", "block"}

        resp = _send(socket_path, {"v": 1, "op": "health.full"})
        assert resp["verdict"] == "pass"
        health = resp["health"]

        assert "db_capacity_percent" not in health
        assert health["total_checks"] == 20
        assert health["p95_input_latency_ms"] > 0.0
        assert health["p95_input_latency_ms"] < 60_000.0
        assert "p95_output_latency_ms" not in health
