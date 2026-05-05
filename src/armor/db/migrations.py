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

        conn.commit()
        logger.info(f"Migrations applied to {db_path}")

    except sqlite3.Error as e:
        logger.error(f"Migration failed: {e}")
        raise
    finally:
        conn.close()
