"""Tests for SessionStore."""

import asyncio
import tempfile
from pathlib import Path

import pytest

from armor.db.migrations import run_migrations
from armor.db.session_store import SessionStore
from armor.types import Verdict


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
    assert row.state == "Normal"
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
async def test_update_after_check_pass(session_store):
    """Pass verdict increments turn count but not risk score."""
    session_id = "test-session-003"

    row = await session_store.get_or_create(session_id)
    assert row.turn_count == 0

    verdict = Verdict.pass_verdict()
    await session_store.update_after_check(session_id, verdict)

    row = await session_store.get_or_create(session_id)
    assert row.turn_count == 1
    assert row.risk_score == 0


@pytest.mark.asyncio
async def test_update_after_check_block_critical(session_store):
    """Critical severity block increments risk score by 10."""
    session_id = "test-session-004"

    row = await session_store.get_or_create(session_id)
    assert row.risk_score == 0

    verdict = Verdict.block_verdict(
        signal_id="test:001",
        severity="critical",
    )
    await session_store.update_after_check(session_id, verdict)

    row = await session_store.get_or_create(session_id)
    assert row.risk_score == 10


@pytest.mark.asyncio
async def test_update_after_check_block_medium(session_store):
    """Medium severity block increments risk score by 3."""
    session_id = "test-session-005"

    row = await session_store.get_or_create(session_id)
    verdict = Verdict.block_verdict(
        signal_id="test:001",
        severity="medium",
    )
    await session_store.update_after_check(session_id, verdict)

    row = await session_store.get_or_create(session_id)
    assert row.risk_score == 3


@pytest.mark.asyncio
async def test_signal_history_rolling_window(session_store):
    """Signal history is capped at 50."""
    session_id = "test-session-006"

    row = await session_store.get_or_create(session_id)

    # Add 60 signals
    for i in range(60):
        verdict = Verdict.block_verdict(
            signal_id=f"test:signal-{i:03d}",
            severity="low",
        )
        await session_store.update_after_check(session_id, verdict)

    row = await session_store.get_or_create(session_id)
    assert len(row.signal_history) == 50

    # Check that the last signal is signal-59 (0-indexed)
    assert "signal-059" in row.signal_history[-1]["signal_id"]
    assert "signal-010" in row.signal_history[0]["signal_id"]  # Should start from signal-10


@pytest.mark.asyncio
async def test_risk_score_monotone(session_store):
    """Risk score is monotonically non-decreasing."""
    session_id = "test-session-007"

    row = await session_store.get_or_create(session_id)
    scores = [row.risk_score]

    # Add blocks of various severities
    for severity in ["low", "low", "medium", "high", "critical"]:
        verdict = Verdict.block_verdict(
            signal_id=f"test:{severity}",
            severity=severity,
        )
        await session_store.update_after_check(session_id, verdict)
        row = await session_store.get_or_create(session_id)
        scores.append(row.risk_score)

    # Verify monotone non-decreasing
    for i in range(1, len(scores)):
        assert scores[i] >= scores[i - 1]


@pytest.mark.asyncio
async def test_concurrent_updates_no_corruption(session_store):
    """Concurrent updates don't corrupt signal_history JSON."""
    session_id = "test-concurrent"

    await session_store.get_or_create(session_id)

    # Create concurrent update tasks
    async def update_task(i):
        verdict = Verdict.block_verdict(
            signal_id=f"test:concurrent-{i}",
            severity="low",
        )
        await session_store.update_after_check(session_id, verdict)

    # Run 10 concurrent updates
    await asyncio.gather(*[update_task(i) for i in range(10)])

    row = await session_store.get_or_create(session_id)

    # Verify signal_history is valid JSON
    assert isinstance(row.signal_history, list)
    assert len(row.signal_history) == 10

    # Verify all signals are present
    signal_ids = {sig["signal_id"] for sig in row.signal_history}
    assert len(signal_ids) == 10


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


@pytest.mark.asyncio
async def test_persistence_across_instances(temp_db):
    """Session data persists across store instances."""
    # Create first instance and write data
    store1 = SessionStore(temp_db)
    await store1.get_or_create("test-persist")
    verdict = Verdict.block_verdict(
        signal_id="test:persist",
        severity="critical",
    )
    await store1.update_after_check("test-persist", verdict)

    # Get risk score
    row1_updated = await store1.get_or_create("test-persist")
    risk_score_1 = row1_updated.risk_score

    # Create new instance and verify data
    store2 = SessionStore(temp_db)
    row2 = await store2.get_or_create("test-persist")
    assert row2.risk_score == risk_score_1
    assert row2.session_id == "test-persist"
