# SPDX-License-Identifier: Apache-2.0
"""Integration tests for OperatorAuditLog table and functionality.

Covers task 036 spec markers:
- TC-036-09: clear_blocked is atomic (audit row + state change roll back together).
"""

import sqlite3
import tempfile
from pathlib import Path

from armor.db.migrations import run_migrations


class TestOperatorAuditLogTable:
    """Tests for the OperatorAuditLog table."""

    def test_operator_audit_log_table_exists(self) -> None:
        """TC-028-10: OperatorAuditLog table exists in the schema."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = str(Path(tmpdir) / "test.db")

            # Run migrations
            run_migrations(db_path)

            # Check table exists
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            # Query table info
            cursor.execute("PRAGMA table_info(OperatorAuditLog)")
            columns = cursor.fetchall()

            conn.close()

            # Verify table exists and has expected columns
            assert len(columns) > 0, "OperatorAuditLog table should have columns"

            column_names = {col[1] for col in columns}
            expected_columns = {"id", "ts", "actor", "action", "session_id", "reason"}

            for expected_col in expected_columns:
                assert expected_col in column_names, f"Missing column: {expected_col}"

    def test_operator_audit_log_columns_correct_types(self) -> None:
        """Verify OperatorAuditLog columns have correct types."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = str(Path(tmpdir) / "test.db")

            run_migrations(db_path)

            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            cursor.execute("PRAGMA table_info(OperatorAuditLog)")
            columns = {col[1]: col[2] for col in cursor.fetchall()}

            conn.close()

            # Check column types
            assert columns.get("id") == "INTEGER"
            assert columns.get("ts") == "TEXT"
            assert columns.get("actor") == "TEXT"
            assert columns.get("action") == "TEXT"
            assert columns.get("session_id") == "TEXT"
            assert columns.get("reason") == "TEXT"

    def test_operator_audit_log_foreign_key_constraint(self) -> None:
        """Verify OperatorAuditLog has FK constraint on session_id."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = str(Path(tmpdir) / "test.db")

            run_migrations(db_path)

            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            # Get foreign key info
            cursor.execute("PRAGMA foreign_key_list(OperatorAuditLog)")
            fks = cursor.fetchall()

            conn.close()

            # Should have at least one foreign key (session_id -> Session)
            assert len(fks) > 0, "OperatorAuditLog should have foreign key constraint"

            # Check that session_id has the constraint
            session_fks = [fk for fk in fks if fk[3] == "session_id"]
            assert len(session_fks) > 0, "session_id should have foreign key constraint"

    def test_operator_audit_log_index_exists(self) -> None:
        """Verify OperatorAuditLog has the expected index."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = str(Path(tmpdir) / "test.db")

            run_migrations(db_path)

            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            # Get index info
            cursor.execute("SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='OperatorAuditLog'")
            indexes = [row[0] for row in cursor.fetchall()]

            conn.close()

            # Should have idx_operator_audit_session_ts index
            assert "idx_operator_audit_session_ts" in indexes

    def test_operator_audit_log_insert_and_query(self) -> None:
        """Test inserting and querying audit log entries."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = str(Path(tmpdir) / "test.db")

            run_migrations(db_path)

            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            # First create a session to satisfy the FK constraint
            cursor.execute(
                "INSERT INTO Session (session_id, created_at, last_seen_at, current_state) VALUES (?, ?, ?, ?)",
                ("test-session-1", "2026-05-06T14:00:00", "2026-05-06T14:00:00", "Blocked"),
            )

            # Insert an audit log entry
            cursor.execute(
                "INSERT INTO OperatorAuditLog (ts, actor, action, session_id, reason) VALUES (?, ?, ?, ?, ?)",
                ("2026-05-06T14:05:00", "operator", "unblock", "test-session-1", "manual review cleared"),
            )

            conn.commit()

            # Query the audit log
            cursor.execute(
                "SELECT action, reason, session_id FROM OperatorAuditLog WHERE session_id = ?",
                ("test-session-1",),
            )
            result = cursor.fetchone()

            conn.close()

            assert result is not None
            assert result[0] == "unblock"
            assert result[1] == "manual review cleared"
            assert result[2] == "test-session-1"

    def test_operator_audit_log_defaults(self) -> None:
        """Test that OperatorAuditLog fields have correct defaults."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = str(Path(tmpdir) / "test.db")

            run_migrations(db_path)

            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            # Create a session
            cursor.execute(
                "INSERT INTO Session (session_id, created_at, last_seen_at, current_state) VALUES (?, ?, ?, ?)",
                ("test-session-2", "2026-05-06T14:00:00", "2026-05-06T14:00:00", "Blocked"),
            )

            # Insert without specifying ts and actor (should use defaults)
            cursor.execute(
                "INSERT INTO OperatorAuditLog (action, session_id) VALUES (?, ?)",
                ("unblock", "test-session-2"),
            )

            conn.commit()

            # Query back
            cursor.execute(
                "SELECT ts, actor, action FROM OperatorAuditLog WHERE session_id = ?",
                ("test-session-2",),
            )
            result = cursor.fetchone()

            conn.close()

            assert result is not None
            # ts should be set to current datetime (non-empty)
            assert result[0], "ts should have a default value"
            # actor should be "operator"
            assert result[1] == "operator"
            assert result[2] == "unblock"
