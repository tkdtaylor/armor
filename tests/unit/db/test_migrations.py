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
        "state",
        "risk_score",
        "turn_count",
        "signal_history",
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
        "action",
        "quarantine_id",
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
    cursor.execute(
        "INSERT INTO Session (session_id, created_at, last_seen_at, state, signal_history) VALUES (?, ?, ?, ?, ?)",
        ("test-session", now, now, "Normal", "[]"),
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
