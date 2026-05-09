"""Fitness check: quarantine table is not greppable for canary values.

Per ADR-011, payloads written to the quarantine table must be encrypted at
rest so that an operator with raw SQLite access cannot recover plaintext
canary values. This test:

1. Builds an ephemeral catalogue + quarantine store backed by a temp DB.
2. Writes payloads containing every active canary value into the store.
3. Reads the raw SQLite file as bytes and asserts no canary value appears
   verbatim.

Spec markers:
    TC-027-07 — encrypted payloads not greppable for canary values.
"""

from __future__ import annotations

import sqlite3
import tempfile
from pathlib import Path

import pytest

from armor.canaries.catalogue import Catalogue
from armor.db.quarantine import QuarantineStore

REPO_ROOT = Path(__file__).resolve().parents[2]


def _candidate_catalogue_paths() -> list[Path]:
    return [
        Path("/tmp/armor-canaries.json"),
        Path("./armor-canaries.json"),
        Path("./.armor/canaries.json"),
        Path.home() / ".armor" / "canaries.json",
    ]


def _load_active_canary_values() -> list[str]:
    """Load active canary values from the first available catalogue file."""
    for candidate in _candidate_catalogue_paths():
        if candidate.exists():
            try:
                catalogue = Catalogue.load(candidate)
                values = [entry.value for entry in catalogue.active_canaries()]
                if values:
                    return values
            except (FileNotFoundError, ValueError):
                continue
    # Fallback: use a deterministic test canary so the round-trip still proves
    # the encryption invariant even when no operator-generated catalogue exists.
    return ["AKIAARMORTRAP000001"]


def _init_quarantine_schema(db_path: str) -> None:
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
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
        conn.commit()
    finally:
        conn.close()


@pytest.mark.slow
def test_quarantine_table_does_not_leak_plaintext_canary_values() -> None:
    """TC-027-07: raw SQLite bytes never contain a canary value verbatim."""
    canary_values = _load_active_canary_values()
    assert canary_values, "test setup error: no canary values available"

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        db_path = str(tmp / "test.db")
        key_path = str(tmp / ".key")

        _init_quarantine_schema(db_path)
        store = QuarantineStore(db_path, key_path=key_path, ttl_hours=24)

        for i, canary_value in enumerate(canary_values):
            store._write_sync(
                f"input_{i}_containing_{canary_value}",
                f"output_{i}_containing_{canary_value}",
            )

        db_bytes = Path(db_path).read_bytes()

        violations: list[tuple[int, str, int]] = []
        for i, canary_value in enumerate(canary_values):
            offset = db_bytes.find(canary_value.encode("utf-8"))
            if offset != -1:
                violations.append((i, canary_value, offset))

    assert not violations, f"Found {len(violations)} canary value(s) in plaintext in quarantine DB:\n  " + "\n  ".join(
        f"#{idx}: offset={offset}, length={len(value)}" for idx, value, offset in violations
    )
