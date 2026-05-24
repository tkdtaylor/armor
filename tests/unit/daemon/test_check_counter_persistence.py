"""Unit tests for daemon check counter persistence (task 122)."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from armor.daemon.server import DaemonServer
from armor.db.migrations import run_migrations


@pytest.fixture
def temp_db_path(tmp_path: Path) -> str:
    """Create a temporary database path."""
    return str(tmp_path / "test.db")


@pytest.fixture
def temp_socket_path(tmp_path: Path) -> str:
    """Create a temporary socket path."""
    return str(tmp_path / "armor.sock")


@pytest.fixture(autouse=True)
def disable_llm_for_tests(monkeypatch) -> None:
    """Disable LLM for all daemon tests to avoid exit 78 on missing LLM."""
    monkeypatch.setenv("ARMOR_DISABLE_LLM", "true")


class TestCheckCounterPersistence:
    """Tests for TC-122: daemon check counter persistence."""

    def test_tc_122_01_daemon_stats_table_created_on_first_run(self, temp_db_path: str) -> None:
        """TC-122-01: daemon_stats table exists with id=1 and total_checks_cumulative=0 after first run."""
        # Run migrations on fresh DB
        run_migrations(temp_db_path)

        # Check that the daemon_stats table exists with initial row
        conn = sqlite3.connect(temp_db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # Query the daemon_stats table
        row = cursor.execute("SELECT total_checks_cumulative FROM daemon_stats WHERE id = 1").fetchone()

        assert row is not None, "daemon_stats table should be created with id=1"
        assert row["total_checks_cumulative"] == 0, "total_checks_cumulative should initialize to 0"

        conn.close()

    def test_tc_122_02_counter_persists_across_daemon_restart(self, temp_db_path: str, temp_socket_path: str) -> None:
        """TC-122-02: Counter persists across daemon restart."""
        # Create and initialize a server
        run_migrations(temp_db_path)
        server1 = DaemonServer(socket_path=temp_socket_path, db_path=temp_db_path)

        # Simulate some check operations by incrementing the counter and persisting
        for _ in range(5):
            server1._total_checks += 1
            server1._persist_check_count()

        # Verify the count is persisted
        conn = sqlite3.connect(temp_db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        row = cursor.execute("SELECT total_checks_cumulative FROM daemon_stats WHERE id = 1").fetchone()
        assert row["total_checks_cumulative"] == 5
        conn.close()

        # Create a new server instance (simulating daemon restart)
        server2 = DaemonServer(socket_path=temp_socket_path, db_path=temp_db_path)
        # Load the persisted count
        server2._load_persisted_check_count()

        # Verify the count was loaded correctly
        assert server2._total_checks == 5, "Persisted count should be loaded on startup"

    def test_tc_122_03_counter_increments_are_written_to_sqlite(self, temp_db_path: str, temp_socket_path: str) -> None:
        """TC-122-03: Counter increments are written to SQLite after each check."""
        run_migrations(temp_db_path)
        server = DaemonServer(socket_path=temp_socket_path, db_path=temp_db_path)

        # Simulate a check operation
        server._record_check_metric("check.input", 1.5)

        # Query SQLite directly
        conn = sqlite3.connect(temp_db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        row = cursor.execute("SELECT total_checks_cumulative FROM daemon_stats WHERE id = 1").fetchone()

        assert row is not None, "daemon_stats row should exist"
        assert row["total_checks_cumulative"] == 1, "total_checks_cumulative should be 1 after one check"

        # Simulate another check
        server._record_check_metric("check.output", 2.5)

        # Query again
        row = cursor.execute("SELECT total_checks_cumulative FROM daemon_stats WHERE id = 1").fetchone()
        assert row["total_checks_cumulative"] == 2, "total_checks_cumulative should be 2 after two checks"

        conn.close()

    def test_tc_122_04_offline_status_reads_cumulative_count(self, temp_db_path: str, temp_socket_path: str) -> None:
        """TC-122-04: The cumulative count can be read from SQLite when daemon is offline."""
        run_migrations(temp_db_path)

        # Simulate daemon running and recording checks
        server = DaemonServer(socket_path=temp_socket_path, db_path=temp_db_path)
        for i in range(10):
            server._record_check_metric("check.input", float(i + 1))

        # Now simulate daemon shutdown and read count directly from SQLite
        # (as the offline status command would do)
        conn = sqlite3.connect(temp_db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        row = cursor.execute("SELECT total_checks_cumulative FROM daemon_stats WHERE id = 1").fetchone()

        assert row is not None
        assert row["total_checks_cumulative"] == 10, "Offline read should show cumulative count of 10"

        conn.close()

    def test_counter_survives_multiple_restarts(self, temp_db_path: str, temp_socket_path: str) -> None:
        """Bonus test: Counter survives multiple restarts."""
        run_migrations(temp_db_path)

        # First restart: record 5 checks
        server1 = DaemonServer(socket_path=temp_socket_path, db_path=temp_db_path)
        for _ in range(5):
            server1._record_check_metric("check.input", 1.0)

        # Second restart: load count, add 3 more
        server2 = DaemonServer(socket_path=temp_socket_path, db_path=temp_db_path)
        server2._load_persisted_check_count()
        assert server2._total_checks == 5

        for _ in range(3):
            server2._record_check_metric("check.output", 2.0)

        # Third restart: load count, verify total is 8
        server3 = DaemonServer(socket_path=temp_socket_path, db_path=temp_db_path)
        server3._load_persisted_check_count()
        assert server3._total_checks == 8, "Counter should be 8 after 5 + 3 checks across three sessions"
