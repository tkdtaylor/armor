"""Tests for database migrations."""

import sqlite3
import tempfile
from pathlib import Path

import pytest

from armor.db.migrations import run_migrations


@pytest.fixture
def temp_db():
    """Create a temporary database file."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    yield db_path
    Path(db_path).unlink(missing_ok=True)


def test_schema_applies_cleanly(temp_db):
    """Schema applies without errors to fresh database."""
    run_migrations(temp_db)

    conn = sqlite3.connect(temp_db)
    cursor = conn.cursor()

    # Check tables exist
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
    tables = {row[0] for row in cursor.fetchall()}

    assert "Session" in tables
    assert "Incident" in tables
    assert "QuarantinedPayload" in tables

    # Check Session table structure
    cursor.execute("PRAGMA table_info(Session)")
    session_cols = {row[1] for row in cursor.fetchall()}
    expected_session_cols = {
        "session_id",
        "created_at",
        "last_seen_at",
        "current_state",
        "risk_score",
        "turn_count",
        "signal_history",
        "last_signal_at",
    }
    assert session_cols == expected_session_cols

    # Check Incident table structure
    cursor.execute("PRAGMA table_info(Incident)")
    incident_cols = {row[1] for row in cursor.fetchall()}
    expected_incident_cols = {
        "id",
        "ts",
        "session_id",
        "attack_category",
        "signal_id",
        "input_hash",
        "output_hash",
        "triggered_canary",
        "destinations",
        "encoding_flag",
        "risk_score",
        "severity",
        "action",
        "quarantine_id",
        "source_tool",
        "chunk_index",
        "chunk_metadata",
    }
    assert incident_cols == expected_incident_cols

    # Check QuarantinedPayload table structure
    cursor.execute("PRAGMA table_info(QuarantinedPayload)")
    quarantine_cols = {row[1] for row in cursor.fetchall()}
    expected_quarantine_cols = {"id", "ts", "input_text", "output_text", "expires_at"}
    assert quarantine_cols == expected_quarantine_cols

    conn.close()


def test_migrations_idempotent(temp_db):
    """Migrations are idempotent (re-running is safe)."""
    run_migrations(temp_db)

    # Insert a test row
    conn = sqlite3.connect(temp_db)
    cursor = conn.cursor()
    now = "2026-05-05 12:00:00"
    now_ts = 1000.0
    cursor.execute(
        "INSERT INTO Session (session_id, created_at, last_seen_at, current_state, signal_history, last_signal_at) VALUES (?, ?, ?, ?, ?, ?)",
        ("test-session", now, now, "Normal", "[]", now_ts),
    )
    conn.commit()

    # Get row count before re-migration
    cursor.execute("SELECT COUNT(*) FROM Session")
    count_before = cursor.fetchone()[0]
    conn.close()

    # Re-run migrations
    run_migrations(temp_db)

    # Verify row still exists and count unchanged
    conn = sqlite3.connect(temp_db)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM Session")
    count_after = cursor.fetchone()[0]

    assert count_after == count_before
    assert count_after == 1

    cursor.execute("SELECT session_id FROM Session WHERE session_id = ?", ("test-session",))
    row = cursor.fetchone()
    assert row is not None
    assert row[0] == "test-session"

    conn.close()


def test_wal_mode_enabled(temp_db):
    """WAL mode is enabled for concurrent reader support."""
    run_migrations(temp_db)

    conn = sqlite3.connect(temp_db)
    cursor = conn.cursor()

    cursor.execute("PRAGMA journal_mode")
    mode = cursor.fetchone()[0]

    assert mode.lower() == "wal"

    conn.close()


def test_indices_created(temp_db):
    """Indices on Incident table are created."""
    run_migrations(temp_db)

    conn = sqlite3.connect(temp_db)
    cursor = conn.cursor()

    # Check indices exist
    cursor.execute("SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='Incident'")
    indices = {row[0] for row in cursor.fetchall()}

    assert "idx_incident_session_ts" in indices
    assert "idx_incident_category_ts" in indices

    conn.close()


def _get_incident_columns_info(db_path: str) -> dict:
    """Helper to get Incident table column info as a dict keyed by column name."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("PRAGMA table_info(Incident)")
    rows = cursor.fetchall()
    conn.close()

    # Format: (cid, name, type, notnull, dflt_value, pk)
    result = {}
    for row in rows:
        cid, name, col_type, notnull, dflt_value, pk = row
        result[name] = {
            "cid": cid,
            "type": col_type,
            "notnull": notnull,
            "dflt_value": dflt_value,
            "pk": pk,
        }
    return result


def _create_v01_schema(db_path: str) -> None:
    """Create a v0.1 schema (without later Incident columns)."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Enable WAL mode
    cursor.execute("PRAGMA journal_mode = WAL;")

    # v0.1 schema: Incident table WITHOUT the v0.2 columns
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS Session (
            session_id TEXT PRIMARY KEY,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            last_seen_at TEXT NOT NULL DEFAULT (datetime('now')),
            current_state TEXT NOT NULL DEFAULT 'Normal' CHECK(current_state IN ('Normal', 'Watching', 'Elevated', 'High', 'Blocked')),
            risk_score REAL NOT NULL DEFAULT 0.0,
            turn_count INTEGER NOT NULL DEFAULT 0,
            signal_history TEXT NOT NULL DEFAULT '[]',
            last_signal_at REAL NOT NULL DEFAULT 0.0,
            UNIQUE(session_id)
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS Incident (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL DEFAULT (datetime('now')),
            session_id TEXT REFERENCES Session(session_id),
            attack_category TEXT NOT NULL,
            signal_id TEXT,
            input_hash TEXT NOT NULL,
            output_hash TEXT,
            triggered_canary TEXT,
            destinations TEXT,
            encoding_flag BOOLEAN DEFAULT 0,
            risk_score INTEGER DEFAULT 0,
            action TEXT DEFAULT 'blocked' CHECK(action IN ('blocked', 'advisory_only', 'passed_with_warning')),
            quarantine_id INTEGER REFERENCES QuarantinedPayload(id)
        )
        """
    )

    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_incident_session_ts ON Incident(session_id, ts)
        """
    )
    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_incident_category_ts ON Incident(attack_category, ts)
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS QuarantinedPayload (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL DEFAULT (datetime('now')),
            input_text TEXT NOT NULL,
            output_text TEXT,
            expires_at TEXT NOT NULL DEFAULT (datetime('now', '+168 hours'))
        )
        """
    )

    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_quarantined_expires_at ON QuarantinedPayload(expires_at)
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS SessionRollingBuffer (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL REFERENCES Session(session_id),
            turn_id TEXT NOT NULL,
            text TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
        """
    )

    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_rolling_buffer_session_ts ON SessionRollingBuffer(session_id, created_at)
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS OperatorAuditLog (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL DEFAULT (datetime('now')),
            actor TEXT NOT NULL DEFAULT 'operator',
            action TEXT NOT NULL,
            session_id TEXT NOT NULL REFERENCES Session(session_id),
            reason TEXT
        )
        """
    )

    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_operator_audit_session_ts ON OperatorAuditLog(session_id, ts)
        """
    )

    conn.commit()
    conn.close()


def test_fresh_schema_has_forensic_columns(temp_db):
    """TC-089-01: Fresh schema from schema.sql has source_tool, chunk_index, chunk_metadata."""
    run_migrations(temp_db)

    columns = _get_incident_columns_info(temp_db)

    # Assert presence of v0.2 columns
    assert "source_tool" in columns
    assert "chunk_index" in columns
    assert "chunk_metadata" in columns
    assert "severity" in columns

    # Verify types and nullability (should be NULL, NULL, TEXT NULL / INTEGER NULL)
    assert columns["source_tool"]["type"] == "TEXT"
    assert columns["source_tool"]["notnull"] == 0  # nullable

    assert columns["chunk_index"]["type"] == "INTEGER"
    assert columns["chunk_index"]["notnull"] == 0  # nullable

    assert columns["chunk_metadata"]["type"] == "TEXT"
    assert columns["chunk_metadata"]["notnull"] == 0  # nullable

    assert columns["severity"]["type"] == "TEXT"
    assert columns["severity"]["notnull"] == 1
    assert columns["severity"]["dflt_value"] == "'low'"


def test_v01_upgraded_converges_to_fresh(temp_db):
    """TC-089-02: v0.1 DB upgraded via migrations has same columns as fresh-init DB."""
    # Create a v0.1 snapshot
    _create_v01_schema(temp_db)

    # Get the column set from v0.1 before migration
    conn = sqlite3.connect(temp_db)
    cursor = conn.cursor()
    cursor.execute("PRAGMA table_info(Incident)")
    v01_columns_before = {row[1] for row in cursor.fetchall()}
    conn.close()

    # Verify v0.1 doesn't have the v0.2 columns yet
    assert "source_tool" not in v01_columns_before
    assert "chunk_index" not in v01_columns_before
    assert "chunk_metadata" not in v01_columns_before
    assert "severity" not in v01_columns_before

    # Now run migrations to upgrade to v0.2
    run_migrations(temp_db)

    # Get columns after migration
    upgraded_columns = _get_incident_columns_info(temp_db)

    # Compare with fresh-init DB
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        fresh_temp_db = f.name
    try:
        run_migrations(fresh_temp_db)
        fresh_columns = _get_incident_columns_info(fresh_temp_db)

        # The v0.2 columns should exist in both with same types
        for col_name in ["source_tool", "chunk_index", "chunk_metadata", "severity"]:
            assert col_name in upgraded_columns
            assert col_name in fresh_columns
            assert upgraded_columns[col_name]["type"] == fresh_columns[col_name]["type"]
            assert upgraded_columns[col_name]["notnull"] == fresh_columns[col_name]["notnull"]

    finally:
        Path(fresh_temp_db).unlink(missing_ok=True)


def test_migrations_idempotent_on_fresh_schema(temp_db):
    """TC-089-03: Running migrations on a fresh schema is idempotent."""
    # Initialize from current schema.sql
    run_migrations(temp_db)

    # Get the schema state
    conn = sqlite3.connect(temp_db)
    cursor = conn.cursor()
    cursor.execute("PRAGMA table_info(Incident)")
    columns_before = {row[1] for row in cursor.fetchall()}
    conn.close()

    # Run migrations again (should be a no-op)
    run_migrations(temp_db)

    # Verify schema unchanged
    conn = sqlite3.connect(temp_db)
    cursor = conn.cursor()
    cursor.execute("PRAGMA table_info(Incident)")
    columns_after = {row[1] for row in cursor.fetchall()}
    conn.close()

    assert columns_before == columns_after


def test_insert_and_read_forensic_columns(temp_db):
    """TC-089-04: Insert incident with new columns and round-trip read."""
    run_migrations(temp_db)

    conn = sqlite3.connect(temp_db)
    cursor = conn.cursor()

    # Create a session first
    cursor.execute(
        "INSERT INTO Session (session_id, created_at, last_seen_at, current_state, signal_history, last_signal_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        ("test-session", "2026-05-08 12:00:00", "2026-05-08 12:00:00", "Normal", "[]", 1000.0),
    )

    # Insert an incident with the new columns
    cursor.execute(
        "INSERT INTO Incident (session_id, attack_category, signal_id, input_hash, "
        "severity, source_tool, chunk_index, chunk_metadata) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            "test-session",
            "injection",
            "sig-1",
            "hash-1",
            "critical",
            "Read",
            0,
            '{"len":1024}',
        ),
    )
    conn.commit()

    # Read back and verify
    cursor.execute(
        "SELECT severity, source_tool, chunk_index, chunk_metadata FROM Incident WHERE signal_id = ?",
        ("sig-1",),
    )
    row = cursor.fetchone()

    assert row is not None
    assert row[0] == "critical"
    assert row[1] == "Read"
    assert row[2] == 0
    assert row[3] == '{"len":1024}'

    conn.close()
