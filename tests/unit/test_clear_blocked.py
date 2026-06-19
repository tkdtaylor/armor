# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the operator-clear path on the session state machine.

Covers task 036 spec markers:
- TC-036-07: clear_blocked function exists with the documented signature.
- TC-036-08: clear_blocked raises InvalidStateTransition on non-Blocked sessions.
- TC-036-09: clear_blocked is atomic (state + audit roll back together).

Implementation lands in `src/armor/session/state_machine.py` and
`src/armor/db/operator_audit.py` — these tests assert the contract.
"""

import inspect
import sqlite3
import tempfile
from pathlib import Path

import pytest

from armor.db.migrations import run_migrations


def _seed_session(db_path: str, session_id: str, state: str) -> None:
    conn = sqlite3.connect(db_path)
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO Session (session_id, current_state) VALUES (?, ?)",
            (session_id, state),
        )
        conn.commit()
    finally:
        conn.close()


def test_clear_blocked_signature_matches_spec() -> None:
    """TC-036-07: clear_blocked exists and has the documented signature."""
    from armor.session.state_machine import clear_blocked

    sig = inspect.signature(clear_blocked)
    params = list(sig.parameters.keys())
    # Required positional: session_id, actor, reason; plus a db_path hook.
    assert "session_id" in params
    assert "actor" in params
    assert "reason" in params


def test_clear_blocked_rejects_non_blocked_session() -> None:
    """TC-036-08: clear_blocked raises InvalidStateTransition on Normal."""
    from armor.session.state_machine import InvalidStateTransition, clear_blocked

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = str(Path(tmpdir) / "test.db")
        run_migrations(db_path)
        _seed_session(db_path, "S1", "Normal")

        with pytest.raises(InvalidStateTransition):
            clear_blocked("S1", actor="op", reason="x", db_path=db_path)


def test_clear_blocked_rejects_empty_reason() -> None:
    """TC-036-08: clear_blocked rejects empty reasons."""
    from armor.session.state_machine import clear_blocked

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = str(Path(tmpdir) / "test.db")
        run_migrations(db_path)
        _seed_session(db_path, "SB", "Blocked")

        with pytest.raises(ValueError):
            clear_blocked("SB", actor="op", reason="", db_path=db_path)


def test_clear_blocked_writes_audit_and_transitions() -> None:
    """TC-036-09 (happy path): writes one audit row + transitions to Watching."""
    from armor.session.state_machine import SessionState, clear_blocked

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = str(Path(tmpdir) / "test.db")
        run_migrations(db_path)
        _seed_session(db_path, "SB", "Blocked")

        new_state = clear_blocked("SB", actor="op-1", reason="manual review cleared", db_path=db_path)

        assert new_state == SessionState.WATCHING

        conn = sqlite3.connect(db_path)
        try:
            cur = conn.cursor()
            cur.execute("SELECT current_state FROM Session WHERE session_id = ?", ("SB",))
            assert cur.fetchone()[0] == "Watching"

            cur.execute(
                "SELECT actor, action, session_id, reason FROM OperatorAuditLog WHERE session_id = ?",
                ("SB",),
            )
            rows = cur.fetchall()
            assert len(rows) == 1
            actor, action, session_id, reason = rows[0]
            assert actor == "op-1"
            assert action == "session.unblock"
            assert session_id == "SB"
            assert reason == "manual review cleared"
        finally:
            conn.close()


def test_clear_blocked_atomic_rollback(monkeypatch: pytest.MonkeyPatch) -> None:
    """TC-036-09: if the audit write fails, the state mutation rolls back."""
    from armor.db import operator_audit
    from armor.session.state_machine import clear_blocked

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = str(Path(tmpdir) / "test.db")
        run_migrations(db_path)
        _seed_session(db_path, "SB", "Blocked")

        def boom(*_args: object, **_kwargs: object) -> None:
            raise RuntimeError("simulated audit-log failure")

        monkeypatch.setattr(operator_audit, "_insert_unblock_row", boom)

        with pytest.raises(RuntimeError, match="simulated"):
            clear_blocked("SB", actor="op", reason="r", db_path=db_path)

        conn = sqlite3.connect(db_path)
        try:
            cur = conn.cursor()
            cur.execute("SELECT current_state FROM Session WHERE session_id = ?", ("SB",))
            assert cur.fetchone()[0] == "Blocked"
            cur.execute("SELECT COUNT(*) FROM OperatorAuditLog WHERE session_id = ?", ("SB",))
            assert cur.fetchone()[0] == 0
        finally:
            conn.close()
