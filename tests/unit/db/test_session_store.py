# SPDX-License-Identifier: Apache-2.0
"""Tests for SessionStore (orthogonal behavior).

The risk-score / signal-history / FSM behavior previously tested via the
legacy ``update_after_check`` method now lives in
``test_apply_and_persist.py``; this file covers only behavior orthogonal to
the score-update path: session creation, LRU caching, and basic identity.
"""

import tempfile
from pathlib import Path

import pytest

from armor.db.migrations import run_migrations
from armor.db.session_store import SessionStore


@pytest.fixture
def temp_db():
    """Create a temporary database with schema."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    run_migrations(db_path)
    yield db_path
    Path(db_path).unlink(missing_ok=True)


@pytest.fixture
def session_store(temp_db):
    """Create a SessionStore instance."""
    return SessionStore(temp_db)


@pytest.mark.asyncio
async def test_get_or_create_new_session(session_store):
    """Create a new session on first access."""
    session_id = "test-session-001"
    row = await session_store.get_or_create(session_id)

    assert row.session_id == session_id
    assert row.current_state == "Normal"
    assert row.risk_score == 0
    assert row.turn_count == 0
    assert row.signal_history == []


@pytest.mark.asyncio
async def test_get_or_create_existing(session_store):
    """Return cached session on subsequent access."""
    session_id = "test-session-002"

    row1 = await session_store.get_or_create(session_id)
    row2 = await session_store.get_or_create(session_id)

    # Should be the same object
    assert row1 is row2


@pytest.mark.asyncio
async def test_lru_eviction(session_store):
    """LRU cache evicts least-recently-used sessions."""
    # Create 1025 sessions (exceeds default cache size of 1024)
    for i in range(1025):
        session_id = f"test-session-{i:04d}"
        await session_store.get_or_create(session_id)

    # Cache should have exactly 1024 entries
    assert len(session_store._cache) == 1024

    # The first session should have been evicted
    assert "test-session-0000" not in session_store._cache

    # But the data should still be in the database
    row = await session_store.get_or_create("test-session-0000")
    assert row is not None
    assert row.session_id == "test-session-0000"

    # And now it should be back in the cache
    assert "test-session-0000" in session_store._cache
