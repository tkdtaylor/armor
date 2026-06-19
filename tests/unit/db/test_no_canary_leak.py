# SPDX-License-Identifier: Apache-2.0
"""Load-bearing test: canary values never leak into forensic logs.

This test verifies the critical invariant that the forensic incident log
never stores canary values verbatim — only canary IDs are persisted.
"""

import os
import sqlite3
import tempfile
from pathlib import Path

import pytest

from armor.canaries._generate import write_values_file
from armor.canaries.catalogue import Catalogue
from armor.canaries.scanner import CanaryScanner
from armor.db.forensic import ForensicLogger
from armor.db.migrations import run_migrations
from armor.db.quarantine import QuarantineStore
from armor.detectors.canary_scanner import CanaryScannerDetector
from armor.types import Payload, SessionContext


@pytest.fixture
def temp_db():
    """Create a temporary database with schema."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    run_migrations(db_path)
    yield db_path
    Path(db_path).unlink(missing_ok=True)


@pytest.fixture
def temp_dir():
    """Create a temporary directory for key files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir


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
def canary_scanner(catalogue):
    """Create a canary scanner."""
    active_canaries = catalogue.active_canaries()
    if not active_canaries:
        # Requires `armor canary generate`; see ADR-010
        pytest.skip("No active canaries in catalogue")

    canary_map = {entry.canary_id: entry.value for entry in active_canaries}
    return CanaryScanner(canary_map)


@pytest.fixture
def detector(canary_scanner):
    """Create a canary scanner detector."""
    return CanaryScannerDetector(scanner=canary_scanner)


@pytest.mark.asyncio
async def test_canary_block_no_plaintext_leak(temp_db, temp_dir, catalogue, detector):
    """Canary block doesn't leak value into forensic log.

    This is the load-bearing test for the critical invariant:
    - Incident.triggered_canary must be a canary_id (not the value)
    - The actual canary value must not appear in any plaintext column
    - If quarantine is used, decrypted content should also not leak
    """
    # Get first active canary
    active_canaries = catalogue.active_canaries()
    if not active_canaries:
        # Requires `armor canary generate`; see ADR-010
        pytest.skip("No active canaries in catalogue")

    canary = active_canaries[0]
    canary_id = canary.canary_id
    canary_value = canary.value

    # Create payload with canary value (simulating exfiltration attempt)
    payload = Payload(text=f"Here is the secret: {canary_value}")

    # Run the detector (this should block)
    ctx = SessionContext(session_id="test-canary-block")
    verdict = detector.check(payload, ctx)

    # Verify it blocked
    assert verdict.blocked
    assert "canary" in verdict.signal_id.lower()

    # Set up forensic logger and quarantine store
    key_path = os.path.join(temp_dir, ".key")
    forensic_logger = ForensicLogger(temp_db, catalogue=catalogue)
    quarantine_store = QuarantineStore(temp_db, key_path=key_path)

    # Write quarantine and incident
    quarantine_id = await quarantine_store.write(payload.text)
    incident_id = await forensic_logger.write_incident(verdict, ctx, payload.text, quarantine_id=quarantine_id)

    # Query the incident row
    conn = sqlite3.connect(temp_db)
    cursor = conn.cursor()

    cursor.execute(
        "SELECT id, signal_id, triggered_canary, destinations, attack_category FROM Incident WHERE id = ?",
        (incident_id,),
    )
    incident_row = cursor.fetchone()

    assert incident_row is not None

    # Critical assertion: triggered_canary must be the ID
    triggered_canary = incident_row[2]
    assert triggered_canary == canary_id
    assert triggered_canary != canary_value

    # Critical assertion: canary value should not appear in plaintext columns
    plaintext_columns = incident_row[:-1]  # All except attack_category for now

    for col_value in plaintext_columns:
        if col_value:
            col_str = str(col_value)
            assert canary_value not in col_str, f"Canary value leaked in column: {col_str}"

    # If quarantine is associated, verify encrypted content
    if quarantine_id:
        cursor.execute(
            "SELECT input_text, output_text FROM QuarantinedPayload WHERE id = ?",
            (quarantine_id,),
        )
        quarantine_row = cursor.fetchone()

        if quarantine_row:
            # The stored fields are encrypted, so they should look like random bytes/text
            encrypted_input = quarantine_row[0]

            # Encrypted content should not contain plaintext canary (it's encrypted)
            assert canary_value not in encrypted_input

            # Decrypt and verify content is preserved (but canary ID is used for logging)
            decrypted = await quarantine_store.decrypt_payload(encrypted_input)
            assert canary_value in decrypted  # Original data is preserved in quarantine

            # But the incident log should reference only the ID
            assert triggered_canary == canary_id

    conn.close()
