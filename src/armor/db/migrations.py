# SPDX-License-Identifier: Apache-2.0
"""Database migrations for armor.

Migrations are idempotent — running them on a populated DB is safe.
"""

import logging
import sqlite3
from pathlib import Path

logger = logging.getLogger(__name__)


def run_migrations(db_path: str) -> None:
    """Apply all pending migrations to the database.

    Args:
        db_path: Path to the SQLite database file.

    Raises:
        sqlite3.Error: If a migration fails.
    """
    db_path_obj = Path(db_path)
    db_path_obj.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(db_path)
    try:
        cursor = conn.cursor()

        # Enable WAL mode
        cursor.execute("PRAGMA journal_mode = WAL;")

        # Apply v0.1 schema (idempotent via IF NOT EXISTS)
        schema_path = Path(__file__).parent / "schema.sql"
        with open(schema_path) as f:
            schema_sql = f.read()

        # Execute schema file (contains multiple statements)
        cursor.executescript(schema_sql)

        # Migration v0.2: Add source_tool, chunk_index, chunk_metadata columns to Incident
        # for check.fetched chunking (ADR-033), and severity for operator filters.
        # NOTE: Fresh installs from schema.sql already have these columns.
        # This migration is idempotent and ensures v0.1 databases are upgraded to v0.2.
        cursor.execute(
            "PRAGMA table_info(Incident)",
        )
        columns = {row[1] for row in cursor.fetchall()}

        if "source_tool" not in columns:
            cursor.execute("ALTER TABLE Incident ADD COLUMN source_tool TEXT NULL")
            logger.info("Added source_tool column to Incident")

        if "chunk_index" not in columns:
            cursor.execute("ALTER TABLE Incident ADD COLUMN chunk_index INTEGER NULL")
            logger.info("Added chunk_index column to Incident")

        if "chunk_metadata" not in columns:
            cursor.execute("ALTER TABLE Incident ADD COLUMN chunk_metadata TEXT NULL")
            logger.info("Added chunk_metadata column to Incident")

        if "severity" not in columns:
            cursor.execute("ALTER TABLE Incident ADD COLUMN severity TEXT NOT NULL DEFAULT 'low'")
            logger.info("Added severity column to Incident")

        conn.commit()
        logger.info(f"Migrations applied to {db_path}")

    except sqlite3.Error as e:
        logger.error(f"Migration failed: {e}")
        raise
    finally:
        conn.close()
