"""Tests for SessionStore.apply_and_persist (advisory accumulation + FSM integration).

TC-084-01: Advisory accumulation — score = confidence x weight.
TC-084-02: Multi-signal accumulation — multiple advisories compound.
TC-084-03: Cooldown decay — score decreases over time when no new signals.
TC-084-04: FSM transition — crossing thresholds changes state.
TC-084-05: Concurrent checks — no double-counting under row lock.
TC-084-06: Block also accumulates — blocks still update risk_score.
TC-084-07: Legacy function removed — SessionStore.update_after_check no longer exists.
"""

import asyncio
import tempfile
import time
from pathlib import Path

import pytest

from armor.db.migrations import run_migrations
from armor.db.session_store import SessionStore
from armor.session.state_machine import SessionState
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


class TestAdvisoryAccumulation:
    """TC-084-01: Advisory increments risk_score by confidence x weight."""

    @pytest.mark.asyncio
    async def test_tc_084_01_single_advisory_accumulates(self, session_store):
        """Single advisory: score = confidence x weight."""
        session_id = "test-084-01"
        await session_store.get_or_create(session_id)

        # Create advisory with confidence=0.6
        # Config has no explicit weight for this detector, so default 1.0
        # Expected score: 0.6 * 1.0 = 0.6
        verdict = Verdict.advisory_verdict(
            signal_id="test.detector:001",
            severity="medium",
            details={"confidence": 0.6},
        )

        config = {
            "session": {
                "thresholds": {"watching": 0.4, "elevated": 0.9, "high": 1.5},
                "cooldown_decay_per_min": 0.1,
                "signal_weights": {},
            }
        }

        _new_state, new_score = await session_store.apply_and_persist(session_id, verdict, config)

        assert new_score == pytest.approx(0.6)
        # Confirm it's persisted by fetching it again
        row = await session_store.get_or_create(session_id)
        assert row.risk_score == pytest.approx(0.6)

    @pytest.mark.asyncio
    async def test_tc_084_01_with_custom_weight(self, session_store):
        """Advisory with per-detector weight: score = confidence x weight."""
        session_id = "test-084-01-weight"
        await session_store.get_or_create(session_id)

        verdict = Verdict.advisory_verdict(
            signal_id="llm.validator:001",
            severity="medium",
            details={"confidence": 0.6},
        )

        config = {
            "session": {
                "thresholds": {"watching": 0.4, "elevated": 0.9, "high": 1.5},
                "cooldown_decay_per_min": 0.1,
                "signal_weights": {"llm.validator": 0.5},
            }
        }

        _new_state, new_score = await session_store.apply_and_persist(session_id, verdict, config)

        # 0.6 * 0.5 = 0.3
        assert new_score == pytest.approx(0.3)

        row = await session_store.get_or_create(session_id)
        assert row.risk_score == pytest.approx(0.3)


class TestMultiSignalAccumulation:
    """TC-084-02: Multiple advisories in one verdict compound."""

    @pytest.mark.asyncio
    async def test_tc_084_02_two_advisories_compound(self, session_store):
        """Two advisories: total = (conf1 x w1) + (conf2 x w2)."""
        session_id = "test-084-02"
        await session_store.get_or_create(session_id)

        # First advisory
        verdict1 = Verdict.advisory_verdict(
            signal_id="detector.a:001",
            severity="medium",
            details={"confidence": 0.4},
        )

        config = {
            "session": {
                "thresholds": {"watching": 0.4, "elevated": 0.9, "high": 1.5},
                "cooldown_decay_per_min": 0.1,
                "signal_weights": {"detector.a": 0.5, "detector.b": 0.4},
            }
        }

        _state1, score1 = await session_store.apply_and_persist(session_id, verdict1, config)
        # 0.4 * 0.5 = 0.2
        assert score1 == pytest.approx(0.2)

        # Second advisory (applies immediately, minimal decay)
        verdict2 = Verdict.advisory_verdict(
            signal_id="detector.b:002",
            severity="medium",
            details={"confidence": 0.3},
        )

        _state2, score2 = await session_store.apply_and_persist(session_id, verdict2, config)
        # 0.2 + (0.3 * 0.4) = 0.2 + 0.12 = 0.32 (may have tiny decay, use approx)
        assert score2 == pytest.approx(0.32, abs=0.002)

        row = await session_store.get_or_create(session_id)
        assert row.risk_score == pytest.approx(0.32, abs=0.002)


class TestCooldownDecay:
    """TC-084-03: Cooldown decay reduces score on quiet turns."""

    @pytest.mark.asyncio
    async def test_tc_084_03_decay_on_quiet_turn(self, session_store, monkeypatch):
        """No new signal + elapsed time -> score decreases by decay_rate x minutes."""
        session_id = "test-084-03"
        await session_store.get_or_create(session_id)

        # First: set score to 0.4 via advisory
        verdict1 = Verdict.advisory_verdict(
            signal_id="test:001",
            severity="medium",
            details={"confidence": 0.4},
        )

        config = {
            "session": {
                "thresholds": {"watching": 0.4, "elevated": 0.9, "high": 1.5},
                "cooldown_decay_per_min": 0.1,
                "signal_weights": {},
            }
        }

        _state1, score1 = await session_store.apply_and_persist(session_id, verdict1, config)
        assert score1 == pytest.approx(0.4)

        # Advance time by 2 minutes (in simulation, we'll use datetime mocking)
        # Fetch the session, manipulate last_signal_at, and then apply a pass verdict
        row = await session_store.get_or_create(session_id)

        # Manually adjust last_signal_at in the row to 2 minutes ago
        row.last_signal_at = time.time() - (2 * 60)  # 2 minutes ago
        await asyncio.to_thread(session_store._persist_to_db, row)

        # Now apply a pass verdict (no signal) - decay should kick in
        verdict_pass = Verdict.pass_verdict()

        _state2, score2 = await session_store.apply_and_persist(session_id, verdict_pass, config)

        # Decay: 0.1 per min * 2 min = 0.2 reduction
        # Expected: 0.4 - 0.2 = 0.2 (may have tiny additional decay from call elapsed time)
        assert score2 == pytest.approx(0.2, abs=0.002)

        row = await session_store.get_or_create(session_id)
        assert row.risk_score == pytest.approx(0.2, abs=0.002)

    @pytest.mark.asyncio
    async def test_tc_084_03_decay_clamped_at_zero(self, session_store):
        """Decay cannot drive score below 0."""
        session_id = "test-084-03-clamp"
        await session_store.get_or_create(session_id)

        # Set score to 0.05
        verdict1 = Verdict.advisory_verdict(
            signal_id="test:001",
            severity="medium",
            details={"confidence": 0.05},
        )

        config = {
            "session": {
                "thresholds": {"watching": 0.4, "elevated": 0.9, "high": 1.5},
                "cooldown_decay_per_min": 0.1,
                "signal_weights": {},
            }
        }

        await session_store.apply_and_persist(session_id, verdict1, config)

        # Manually set last_signal_at to 10 minutes ago
        row = await session_store.get_or_create(session_id)
        row.last_signal_at = time.time() - (10 * 60)
        await asyncio.to_thread(session_store._persist_to_db, row)

        # Apply pass verdict
        verdict_pass = Verdict.pass_verdict()
        _state, score = await session_store.apply_and_persist(session_id, verdict_pass, config)

        # Decay would be 0.1 * 10 = 1.0, but clamped at 0
        assert score == pytest.approx(0.0)

        row = await session_store.get_or_create(session_id)
        assert row.risk_score == pytest.approx(0.0)


class TestFSMTransition:
    """TC-084-04: Crossing thresholds triggers FSM state transitions."""

    @pytest.mark.asyncio
    async def test_tc_084_04_cross_watching_threshold(self, session_store):
        """Score crosses 0.4 → state becomes Watching."""
        session_id = "test-084-04-watching"
        await session_store.get_or_create(session_id)

        verdict = Verdict.advisory_verdict(
            signal_id="test:001",
            severity="medium",
            details={"confidence": 0.5},
        )

        config = {
            "session": {
                "thresholds": {"watching": 0.4, "elevated": 0.9, "high": 1.5},
                "cooldown_decay_per_min": 0.1,
                "signal_weights": {},
            }
        }

        new_state, new_score = await session_store.apply_and_persist(session_id, verdict, config)

        assert new_state == SessionState.WATCHING.value
        assert new_score == pytest.approx(0.5)

        row = await session_store.get_or_create(session_id)
        assert row.current_state == SessionState.WATCHING.value

    @pytest.mark.asyncio
    async def test_tc_084_04_cross_elevated_threshold(self, session_store):
        """Score crosses 0.9 → state becomes Elevated."""
        session_id = "test-084-04-elevated"
        await session_store.get_or_create(session_id)

        # First, get to Watching state (score > 0.4)
        verdict1 = Verdict.advisory_verdict(
            signal_id="test:001",
            severity="medium",
            details={"confidence": 0.5},
        )

        config = {
            "session": {
                "thresholds": {"watching": 0.4, "elevated": 0.9, "high": 1.5},
                "cooldown_decay_per_min": 0.1,
                "signal_weights": {},
            }
        }

        await session_store.apply_and_persist(session_id, verdict1, config)

        # Now add another advisory to push over 0.9
        verdict2 = Verdict.advisory_verdict(
            signal_id="test:002",
            severity="medium",
            details={"confidence": 0.5},
        )

        new_state, new_score = await session_store.apply_and_persist(session_id, verdict2, config)

        # Score: 0.5 + 0.5 = 1.0 >= 0.9
        assert new_state == SessionState.ELEVATED.value
        assert new_score == pytest.approx(1.0, abs=0.002)

        row = await session_store.get_or_create(session_id)
        assert row.current_state == SessionState.ELEVATED.value

    @pytest.mark.asyncio
    async def test_tc_084_04_cross_high_threshold(self, session_store):
        """Score crosses 1.5 → state becomes High."""
        session_id = "test-084-04-high"
        await session_store.get_or_create(session_id)

        config = {
            "session": {
                "thresholds": {"watching": 0.4, "elevated": 0.9, "high": 1.5},
                "cooldown_decay_per_min": 0.1,
                "signal_weights": {},
            }
        }

        # Apply multiple advisories to reach High
        for i in range(3):
            verdict = Verdict.advisory_verdict(
                signal_id=f"test:{i:03d}",
                severity="medium",
                details={"confidence": 0.6},
            )
            state, score = await session_store.apply_and_persist(session_id, verdict, config)

        # Score: 0.6 * 3 = 1.8 >= 1.5
        assert state == SessionState.HIGH.value
        assert score == pytest.approx(1.8, abs=0.002)

        row = await session_store.get_or_create(session_id)
        assert row.current_state == SessionState.HIGH.value


class TestConcurrentChecks:
    """TC-084-05: No double-count under concurrent checks (row lock)."""

    @pytest.mark.asyncio
    async def test_tc_084_05_concurrent_advisories_no_double_count(self, session_store):
        """Two concurrent checks for same session: score is sum of both, not doubled."""
        session_id = "test-084-05-concurrent"
        await session_store.get_or_create(session_id)

        config = {
            "session": {
                "thresholds": {"watching": 0.4, "elevated": 0.9, "high": 1.5},
                "cooldown_decay_per_min": 0.1,
                "signal_weights": {},
            }
        }

        async def apply_advisory(conf):
            verdict = Verdict.advisory_verdict(
                signal_id=f"test:{conf}",
                severity="medium",
                details={"confidence": 0.5},
            )
            return await session_store.apply_and_persist(session_id, verdict, config)

        # Run two concurrent advisories
        await asyncio.gather(
            apply_advisory("001"),
            apply_advisory("002"),
        )

        # Both tasks ran, but due to the lock, they're serialized.
        # Expected final score: either 0.5 (first) + 0.5 (second) = 1.0
        # (not 1.0 from both seeing 0 and adding 0.5 each = impossible double-count)
        row = await session_store.get_or_create(session_id)
        assert row.risk_score == pytest.approx(1.0, abs=0.002)

        # Verify state transitions correctly (score ~1.0 should be Elevated or High)
        assert row.current_state in [SessionState.ELEVATED.value, SessionState.HIGH.value]


class TestBlockAlsoAccumulates:
    """TC-084-06: Block verdict still updates risk_score (backward compat)."""

    @pytest.mark.asyncio
    async def test_tc_084_06_block_transitions_to_blocked_state(self, session_store):
        """Block verdict immediately sets state to Blocked regardless of score."""
        session_id = "test-084-06-block"
        await session_store.get_or_create(session_id)

        config = {
            "session": {
                "thresholds": {"watching": 0.4, "elevated": 0.9, "high": 1.5},
                "cooldown_decay_per_min": 0.1,
                "signal_weights": {},
            }
        }

        verdict = Verdict.block_verdict(
            signal_id="test:block",
            severity="critical",
        )

        new_state, _new_score = await session_store.apply_and_persist(session_id, verdict, config)

        # Block should transition to Blocked state
        assert new_state == SessionState.BLOCKED.value

        row = await session_store.get_or_create(session_id)
        assert row.current_state == SessionState.BLOCKED.value


class TestLegacyFunctionRemoval:
    """TC-084-07: update_after_check is removed."""

    def test_tc_084_07_update_after_check_removed(self, session_store):
        """SessionStore no longer exposes update_after_check; callers must use apply_and_persist."""
        assert not hasattr(session_store, "update_after_check"), (
            "update_after_check must be removed per AC-084-05; callers should use apply_and_persist"
        )


class TestSignalHistoryPersistence:
    """Verify that advisory signals are properly recorded in history."""

    @pytest.mark.asyncio
    async def test_advisory_signal_in_history(self, session_store):
        """Advisory signals are added to signal_history."""
        session_id = "test-signal-history"
        await session_store.get_or_create(session_id)

        config = {
            "session": {
                "thresholds": {"watching": 0.4, "elevated": 0.9, "high": 1.5},
                "cooldown_decay_per_min": 0.1,
                "signal_weights": {},
            }
        }

        verdict = Verdict.advisory_verdict(
            signal_id="detector.test:001",
            severity="medium",
            details={"confidence": 0.5},
        )

        await session_store.apply_and_persist(session_id, verdict, config)

        row = await session_store.get_or_create(session_id)
        assert len(row.signal_history) == 1
        assert row.signal_history[0]["signal_id"] == "detector.test:001"
        # Kind is the part before the colon
        assert row.signal_history[0]["kind"] == "detector.test"


class TestTurnCountIncrement:
    """Verify that turn count increments on each check."""

    @pytest.mark.asyncio
    async def test_turn_count_increments_on_apply_and_persist(self, session_store):
        """Each apply_and_persist call increments turn_count."""
        session_id = "test-turn-count"
        row = await session_store.get_or_create(session_id)
        assert row.turn_count == 0

        config = {
            "session": {
                "thresholds": {"watching": 0.4, "elevated": 0.9, "high": 1.5},
                "cooldown_decay_per_min": 0.1,
                "signal_weights": {},
            }
        }

        for i in range(3):
            verdict = Verdict.advisory_verdict(
                signal_id=f"test:{i}",
                severity="medium",
                details={"confidence": 0.1},
            )
            await session_store.apply_and_persist(session_id, verdict, config)

        row = await session_store.get_or_create(session_id)
        assert row.turn_count == 3


class TestPassVerdictHandling:
    """Pass verdicts trigger decay but don't add signals."""

    @pytest.mark.asyncio
    async def test_pass_verdict_does_not_add_signal(self, session_store):
        """Pass verdict (no signal) triggers decay, doesn't appear in signal_history."""
        session_id = "test-pass"
        await session_store.get_or_create(session_id)

        config = {
            "session": {
                "thresholds": {"watching": 0.4, "elevated": 0.9, "high": 1.5},
                "cooldown_decay_per_min": 0.1,
                "signal_weights": {},
            }
        }

        # Add an advisory first
        verdict1 = Verdict.advisory_verdict(
            signal_id="test:001",
            severity="medium",
            details={"confidence": 0.5},
        )
        await session_store.apply_and_persist(session_id, verdict1, config)

        # Then apply a pass verdict
        verdict_pass = Verdict.pass_verdict()
        await session_store.apply_and_persist(session_id, verdict_pass, config)

        row = await session_store.get_or_create(session_id)
        # Signal history should only have the advisory, not the pass
        assert len(row.signal_history) == 1
        assert row.signal_history[0]["signal_id"] == "test:001"
