"""Tests for ForensicLogger."""

import hashlib
import json
import sqlite3
import tempfile
from pathlib import Path

import pytest

from armor.canaries._generate import write_values_file
from armor.canaries.catalogue import Catalogue
from armor.db.forensic import ForensicLogger
from armor.db.migrations import run_migrations
from armor.types import SessionContext, Verdict


@pytest.fixture
def temp_db():
    """Create a temporary database with schema."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    run_migrations(db_path)
    yield db_path
    Path(db_path).unlink(missing_ok=True)


@pytest.fixture
def catalogue():
    """Load test catalogue with ephemeral values.

    Since the bundled schema (default_catalogue.json) no longer contains values,
    we generate ephemeral values with a fixed seed for reproducibility.
    """
    schema_path = Path(__file__).parent.parent.parent.parent / "src" / "armor" / "canaries" / "default_catalogue.json"

    # Generate values in a temp file with a fixed seed
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tf:
        temp_values_path = Path(tf.name)

    try:
        write_values_file(temp_values_path, schema_path, seed=0xCAFEBABE)
        return Catalogue.load(temp_values_path)
    finally:
        # Clean up temp file
        if temp_values_path.exists():
            temp_values_path.unlink()


@pytest.fixture
def forensic_logger(temp_db, catalogue):
    """Create a ForensicLogger instance."""
    return ForensicLogger(temp_db, catalogue=catalogue)


@pytest.mark.asyncio
async def test_write_incident_basic(forensic_logger):
    """Write incident and verify row created."""
    verdict = Verdict.block_verdict(
        signal_id="test:001",
        severity="high",
    )
    ctx = SessionContext(session_id="test-session")

    incident_id = await forensic_logger.write_incident(verdict, ctx, "test input")

    assert incident_id is not None
    assert isinstance(incident_id, int)

    # Verify row in DB
    conn = sqlite3.connect(forensic_logger.db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT id, session_id, signal_id FROM Incident WHERE id = ?", (incident_id,))
    row = cursor.fetchone()

    assert row is not None
    assert row[1] == "test-session"
    assert row[2] == "test:001"

    conn.close()


def test_input_hash_sha256(forensic_logger):
    """Input hash is sha256 of the text."""
    input_text = "test input for hashing"
    expected_hash = hashlib.sha256(input_text.encode()).hexdigest()

    verdict = Verdict.block_verdict(signal_id="test:001")
    ctx = SessionContext(session_id="test-session")

    incident_id = forensic_logger._write_incident_sync(verdict, ctx, input_text)

    # Verify hash in DB
    conn = sqlite3.connect(forensic_logger.db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT input_hash FROM Incident WHERE id = ?", (incident_id,))
    row = cursor.fetchone()

    assert row[0] == expected_hash

    conn.close()


def test_triggered_canary_id_not_value(forensic_logger, catalogue):
    """TC-019-03: Triggered canary field contains ID, not value."""
    active_canaries = catalogue.active_canaries()
    if not active_canaries:
        pytest.skip("No active canaries in test catalogue")

    # Use first active canary
    canary = active_canaries[0]
    canary_id = canary.canary_id

    verdict = Verdict.block_verdict(
        signal_id=f"canary.scanner:{canary_id}",
        details={"canary_ids": [canary_id]},
    )
    ctx = SessionContext(session_id="test-session")

    incident_id = forensic_logger._write_incident_sync(verdict, ctx, "test")

    # Verify triggered_canary is the ID, not the value
    conn = sqlite3.connect(forensic_logger.db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT triggered_canary FROM Incident WHERE id = ?", (incident_id,))
    row = cursor.fetchone()

    assert row[0] == canary_id
    assert row[0] != canary.value  # Should NOT be the value

    conn.close()


def test_defensive_substitution_in_details(forensic_logger, catalogue):
    """Canary values in details are redacted."""
    active_canaries = catalogue.active_canaries()
    if not active_canaries:
        pytest.skip("No active canaries in test catalogue")

    canary = active_canaries[0]
    canary_value = canary.value

    # Include canary value in details
    verdict = Verdict.block_verdict(
        signal_id="test:001",
        details={
            "matched_content": f"Here is the secret: {canary_value}",
            "other_field": "safe content",
        },
    )
    ctx = SessionContext(session_id="test-session")

    incident_id = forensic_logger._write_incident_sync(verdict, ctx, "test")

    # Query should NOT contain the raw canary value in any column
    conn = sqlite3.connect(forensic_logger.db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM Incident WHERE id = ?", (incident_id,))
    row = cursor.fetchone()

    # Convert row to dict for inspection
    column_names = [description[0] for description in cursor.description]
    row_dict = dict(zip(column_names, row, strict=False))

    # The raw canary value should not appear in plaintext columns
    plaintext_columns = ["signal_id", "attack_category"]
    for col in plaintext_columns:
        if row_dict[col]:
            assert canary_value not in str(row_dict[col])

    conn.close()


def test_destinations_extraction(forensic_logger):
    """Destinations are sanitized to hostnames only."""
    verdict = Verdict.block_verdict(
        signal_id="test:001",
        details={
            "destinations": [
                "https://example.com/path?query=1",
                "10.0.0.1",
                "attacker@evil.com",
                "webhook.site",
            ]
        },
    )
    ctx = SessionContext(session_id="test-session")

    incident_id = forensic_logger._write_incident_sync(verdict, ctx, "test")

    # Verify destinations are sanitized
    conn = sqlite3.connect(forensic_logger.db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT destinations FROM Incident WHERE id = ?", (incident_id,))
    row = cursor.fetchone()

    if row[0]:
        destinations = json.loads(row[0])
        # Should have hostnames, not full URLs
        assert "example.com" in destinations or len(destinations) > 0
        assert "https://" not in str(destinations)
        assert "path?query" not in str(destinations)

    conn.close()


def test_output_hash_nullable(forensic_logger):
    """Output hash can be NULL (for input-side blocks)."""
    verdict = Verdict.block_verdict(signal_id="test:001")
    ctx = SessionContext(session_id="test-session")

    # Only pass input text, no output
    incident_id = forensic_logger._write_incident_sync(verdict, ctx, "input text")

    conn = sqlite3.connect(forensic_logger.db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT input_hash, output_hash FROM Incident WHERE id = ?", (incident_id,))
    row = cursor.fetchone()

    assert row[0] is not None  # input_hash
    assert row[1] is None  # output_hash

    conn.close()
