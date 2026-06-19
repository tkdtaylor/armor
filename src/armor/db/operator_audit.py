# SPDX-License-Identifier: Apache-2.0
"""Operator audit-log writer.

Provides an append-only writer for `OperatorAuditLog`. The state-machine's
`clear_blocked()` couples this writer with the session-state mutation in a
single SQLite transaction so they roll back together if either fails.
"""

import sqlite3
from datetime import UTC, datetime


def _insert_unblock_row(
    cursor: sqlite3.Cursor,
    session_id: str,
    actor: str,
    reason: str,
    ts: str,
) -> int:
    """Insert one `session.unblock` row into `OperatorAuditLog`.

    Split out so tests can monkeypatch the helper to simulate a write
    failure mid-transaction (TC-036-09).
    """
    cursor.execute(
        "INSERT INTO OperatorAuditLog (ts, actor, action, session_id, reason) VALUES (?, ?, ?, ?, ?)",
        (ts, actor, "session.unblock", session_id, reason),
    )
    return int(cursor.lastrowid or 0)


def write_unblock_event(
    db_path: str,
    session_id: str,
    actor: str,
    reason: str,
) -> int:
    """Append a single `session.unblock` audit row.

    For the atomic transition (state mutation + audit write together) callers
    should use `state_machine.clear_blocked` instead — it shares the
    connection and rolls both writes back on failure.
    """
    ts = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    conn = sqlite3.connect(db_path)
    try:
        row_id = _insert_unblock_row(conn.cursor(), session_id, actor, reason, ts)
        conn.commit()
        return row_id
    finally:
        conn.close()
