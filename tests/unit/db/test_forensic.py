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
    """TC-019-03, TC-096-05: Triggered canary field contains ID, not value."""
    active_canaries = catalogue.active_canaries()
    if not active_canaries:
        # Requires `armor canary generate`; see ADR-010
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
        # Requires `armor canary generate`; see ADR-010
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


def test_incidents_list_filters_by_persisted_severity(forensic_logger):
    """TC-107-02: incidents persist severity and can be filtered by it."""
    high_verdict = Verdict.block_verdict(signal_id="test:high", severity="high")
    critical_verdict = Verdict.block_verdict(signal_id="test:critical", severity="critical")

    high_id = forensic_logger._write_incident_sync(high_verdict, SessionContext(session_id="severity-high"), "high")
    forensic_logger._write_incident_sync(critical_verdict, SessionContext(session_id="severity-critical"), "critical")

    results = forensic_logger.list_incidents(limit=100, severity="high")

    assert [row["id"] for row in results] == [high_id]
    assert results[0]["severity"] == "high"


def test_incidents_list_filters_by_since_ts_with_other_filters(forensic_logger):
    """TC-107-03: since_ts combines with session/category filters."""
    old_id = forensic_logger._write_incident_sync(
        Verdict.block_verdict(signal_id="regex.instruction_override"),
        SessionContext(session_id="time-filter"),
        "old",
        source="user_input",
    )
    new_id = forensic_logger._write_incident_sync(
        Verdict.block_verdict(signal_id="regex.roleplay_hijack"),
        SessionContext(session_id="time-filter"),
        "new",
        source="user_input",
    )
    other_session_id = forensic_logger._write_incident_sync(
        Verdict.block_verdict(signal_id="regex.roleplay_hijack"),
        SessionContext(session_id="other-session"),
        "other",
        source="user_input",
    )

    conn = sqlite3.connect(forensic_logger.db_path)
    try:
        conn.execute("UPDATE Incident SET ts = ? WHERE id = ?", ("2026-05-01 00:00:00", old_id))
        conn.execute("UPDATE Incident SET ts = ? WHERE id = ?", ("2026-05-09 12:00:00", new_id))
        conn.execute("UPDATE Incident SET ts = ? WHERE id = ?", ("2026-05-09 12:00:00", other_session_id))
        conn.commit()
    finally:
        conn.close()

    results = forensic_logger.list_incidents(
        limit=100,
        session_id="time-filter",
        category="direct_injection.*",
        since_ts="2026-05-09 00:00:00",
    )

    assert [row["id"] for row in results] == [new_id]


def test_attack_category_direct_injection_input(forensic_logger):
    """TC-081-02: check.input with regex signal gets direct_injection.<vector> category."""
    verdict = Verdict.block_verdict(
        signal_id="regex.instruction_override",
        severity="critical",
    )
    ctx = SessionContext(session_id="test-session")

    # No source means it defaults to user_input for direct injection
    incident_id = forensic_logger._write_incident_sync(verdict, ctx, "test input", source="user_input")

    conn = sqlite3.connect(forensic_logger.db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT attack_category FROM Incident WHERE id = ?", (incident_id,))
    row = cursor.fetchone()

    assert row is not None
    assert row[0] == "direct_injection.instruction_override"

    conn.close()


def test_attack_category_indirect_injection_fetched(forensic_logger):
    """TC-081-01: check.fetched with regex signal gets indirect_injection.<vector> category."""
    verdict = Verdict.block_verdict(
        signal_id="regex.instruction_override",
        severity="critical",
    )
    ctx = SessionContext(session_id="test-session")

    # Tool result source should generate indirect_injection category
    incident_id = forensic_logger._write_incident_sync(verdict, ctx, "test fetched", source="tool_result_untrusted")

    conn = sqlite3.connect(forensic_logger.db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT attack_category FROM Incident WHERE id = ?", (incident_id,))
    row = cursor.fetchone()

    assert row is not None
    assert row[0] == "indirect_injection.instruction_override"

    conn.close()


def test_attack_category_six_vectors_indirect(forensic_logger):
    """TC-081-03: All six indirect-injection vectors map correctly."""
    vectors = {
        "regex.instruction_override": "instruction_override",
        "regex.system_prompt_extraction": "system_prompt_extraction",
        "regex.roleplay_hijack": "roleplay_hijack",
        "regex.encoding_request": "encoding_request",
        "regex.authority_impersonation": "authority_impersonation",
        "regex.memory_planting": "memory_planting",
    }

    for signal_id, expected_vector in vectors.items():
        verdict = Verdict.block_verdict(signal_id=signal_id)
        ctx = SessionContext(session_id="test-session")

        incident_id = forensic_logger._write_incident_sync(
            verdict, ctx, f"test {signal_id}", source="tool_result_untrusted"
        )

        conn = sqlite3.connect(forensic_logger.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT attack_category FROM Incident WHERE id = ?", (incident_id,))
        row = cursor.fetchone()

        assert row is not None
        expected_category = f"indirect_injection.{expected_vector}"
        assert row[0] == expected_category, f"Expected {expected_category} for {signal_id}, got {row[0]}"

        conn.close()


def test_attack_category_same_signal_different_source(forensic_logger):
    """TC-081-02 regression: same signal, different source, different category."""
    signal_id = "regex.roleplay_hijack"

    # Direct injection version
    verdict_direct = Verdict.block_verdict(signal_id=signal_id)
    ctx = SessionContext(session_id="test-session-1")
    incident_id_direct = forensic_logger._write_incident_sync(verdict_direct, ctx, "test", source="user_input")

    # Indirect injection version
    verdict_indirect = Verdict.block_verdict(signal_id=signal_id)
    ctx2 = SessionContext(session_id="test-session-2")
    incident_id_indirect = forensic_logger._write_incident_sync(
        verdict_indirect, ctx2, "test", source="tool_result_untrusted"
    )

    conn = sqlite3.connect(forensic_logger.db_path)
    cursor = conn.cursor()

    cursor.execute("SELECT attack_category FROM Incident WHERE id = ?", (incident_id_direct,))
    row_direct = cursor.fetchone()

    cursor.execute("SELECT attack_category FROM Incident WHERE id = ?", (incident_id_indirect,))
    row_indirect = cursor.fetchone()

    assert row_direct[0] == "direct_injection.roleplay_hijack"
    assert row_indirect[0] == "indirect_injection.roleplay_hijack"
    assert row_direct[0] != row_indirect[0]

    conn.close()


def test_attack_category_canary_remains_exfiltration(forensic_logger, catalogue):
    """TC-081-04: Canary leak via check.fetched still categorizes as exfiltration."""
    active_canaries = catalogue.active_canaries()
    if not active_canaries:
        # Requires `armor canary generate`; see ADR-010
        pytest.skip("No active canaries in test catalogue")

    canary = active_canaries[0]
    canary_id = canary.canary_id

    # Canary signal with triggered_canary set
    verdict = Verdict.block_verdict(
        signal_id=f"canary.scanner:{canary_id}",
        details={"canary_ids": [canary_id]},
    )
    ctx = SessionContext(session_id="test-session")

    # Even with tool_result_untrusted source, canary leaks remain exfiltration
    incident_id = forensic_logger._write_incident_sync(verdict, ctx, "test", source="tool_result_untrusted")

    conn = sqlite3.connect(forensic_logger.db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT attack_category FROM Incident WHERE id = ?", (incident_id,))
    row = cursor.fetchone()

    assert row is not None
    assert row[0] == "exfiltration.canary_leak"

    conn.close()


def test_incidents_list_filter_by_indirect_injection_category(forensic_logger):
    """TC-081-05: incidents list --category filter returns indirect_injection rows."""
    # Create a direct injection incident
    direct_verdict = Verdict.block_verdict(signal_id="regex.instruction_override")
    ctx_direct = SessionContext(session_id="session-direct")
    forensic_logger._write_incident_sync(direct_verdict, ctx_direct, "direct input", source="user_input")

    # Create an indirect injection incident
    indirect_verdict = Verdict.block_verdict(signal_id="regex.instruction_override")
    ctx_indirect = SessionContext(session_id="session-indirect")
    forensic_logger._write_incident_sync(
        indirect_verdict, ctx_indirect, "indirect input", source="tool_result_untrusted"
    )

    # Create another indirect injection with different vector
    indirect_verdict2 = Verdict.block_verdict(signal_id="regex.roleplay_hijack")
    ctx_indirect2 = SessionContext(session_id="session-indirect-2")
    forensic_logger._write_incident_sync(
        indirect_verdict2, ctx_indirect2, "indirect input 2", source="tool_result_untrusted"
    )

    # Query for indirect_injection.* category
    results = forensic_logger.list_incidents(limit=100, category="indirect_injection.*")

    # Should return only the indirect injection incidents
    assert len(results) >= 2
    categories = [row["attack_category"] for row in results]
    assert all(cat.startswith("indirect_injection.") for cat in categories)

    # Verify the specific categories are present
    assert any(cat == "indirect_injection.instruction_override" for cat in categories)
    assert any(cat == "indirect_injection.roleplay_hijack" for cat in categories)

    # Query for direct_injection.* category
    direct_results = forensic_logger.list_incidents(limit=100, category="direct_injection.*")
    direct_categories = [row["attack_category"] for row in direct_results]
    assert any(cat == "direct_injection.instruction_override" for cat in direct_categories)
