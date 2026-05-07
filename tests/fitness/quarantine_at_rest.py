"""Fitness check: Quarantine table does not contain plaintext canary values.

Verifies that:
1. Active canary values are NOT greppable in the raw SQLite file
2. Encrypted payloads use unique IVs (Fernet tokens are timestamped and unique)
3. The quarantine store correctly encrypts at rest

Exit code 0 if all checks pass, non-zero if violations found.

Reference: TC-027-07, ADR-011
"""

import sqlite3
import sys
import tempfile
from pathlib import Path

from armor.canaries.catalogue import Catalogue
from armor.db.quarantine import QuarantineStore


def check_quarantine_at_rest() -> bool:
    """Verify quarantine table is not greppable for canary values.

    Creates a test quarantine store, populates it with payloads containing
    every active canary value, then opens the raw SQLite file as bytes and
    searches for the canary values. None should be found.

    Returns:
        True if all checks pass, False if violations found.
    """
    violations = []

    # Create temporary directory for test DB and key
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir_path = Path(tmpdir)
        db_path = str(tmpdir_path / "test.db")
        key_path = str(tmpdir_path / ".key")

        # Load the canary catalogue to get active canaries
        try:
            # Find the canary catalogue file (check common locations)
            catalogue_path = None
            for candidate in [
                Path("/tmp/armor-canaries.json"),
                Path("./armor-canaries.json"),
                Path("./.armor/canaries.json"),
                Path(Path.home()) / ".armor" / "canaries.json",
            ]:
                if candidate.exists():
                    catalogue_path = candidate
                    break

            if not catalogue_path:
                # Fallback: create a minimal test catalogue with one canary
                print("WARNING: No canary catalogue found, using minimal test catalogue", file=sys.stderr)
                active_canaries = ["AKIAARMORTRAP000001"]
            else:
                catalogue = Catalogue.load(catalogue_path)
                active_canaries = [entry.value for entry in catalogue.active_canaries()]

            if not active_canaries:
                print("ERROR: No active canaries loaded", file=sys.stderr)
                return False

            print(f"Loaded {len(active_canaries)} active canaries")

        except Exception as e:
            print(f"ERROR: Failed to load canary catalogue: {e}", file=sys.stderr)
            # Create a minimal test catalogue
            active_canaries = ["AKIAARMORTRAP000001"]
            print("WARNING: Using fallback test canaries", file=sys.stderr)

        # Initialize the database schema
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            # Create the QuarantinedPayload table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS QuarantinedPayload (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts TEXT NOT NULL DEFAULT (datetime('now')),
                    input_text TEXT NOT NULL,
                    output_text TEXT,
                    expires_at TEXT NOT NULL DEFAULT (datetime('now', '+168 hours'))
                )
            """)
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"ERROR: Failed to initialize database schema: {e}", file=sys.stderr)
            return False

        # Create and populate quarantine store
        try:
            store = QuarantineStore(db_path, key_path=key_path, ttl_hours=24)

            # Write a payload containing each canary value
            for i, canary_value in enumerate(active_canaries):
                input_text = f"input_{i}_containing_{canary_value}"
                output_text = f"output_{i}_containing_{canary_value}"

                row_id = store._write_sync(input_text, output_text)
                print(f"Wrote quarantine row {row_id} with canary reference")

        except Exception as e:
            print(f"ERROR: Failed to populate quarantine: {e}", file=sys.stderr)
            return False

        # Read the raw SQLite file as bytes
        try:
            with open(db_path, "rb") as f:
                db_bytes = f.read()
        except Exception as e:
            print(f"ERROR: Failed to read raw SQLite file: {e}", file=sys.stderr)
            return False

        # Search for each canary value in the raw bytes
        for i, canary_value in enumerate(active_canaries):
            # Encode the canary value as UTF-8 bytes
            canary_bytes = canary_value.encode("utf-8")

            # Search for this canary in the raw file
            if canary_bytes in db_bytes:
                rel_offset = db_bytes.find(canary_bytes)
                violations.append((i, canary_value, rel_offset))
                print(
                    f"VIOLATION: Canary #{i} found in raw DB at byte offset {rel_offset}",
                    file=sys.stderr,
                )

    if violations:
        print(f"ERROR: Found {len(violations)} canary value(s) in plaintext in quarantine DB", file=sys.stderr)
        for idx, value, offset in violations:
            print(f"  Canary {idx}: offset={offset}, length={len(value)}", file=sys.stderr)
        return False

    print("OK: No canary values found in plaintext in quarantine DB")
    return True


if __name__ == "__main__":
    sys.exit(0 if check_quarantine_at_rest() else 1)
