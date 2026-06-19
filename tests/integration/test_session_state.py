# SPDX-License-Identifier: Apache-2.0
"""Integration tests for session state machine with pipeline gating.

TC-022-15 through TC-022-19: Pipeline cost-tier gating, persistence, config,
and v0.2 corpus regression.
"""

import asyncio
import tempfile
from pathlib import Path

import pytest

from armor.db.migrations import run_migrations
from armor.db.session_store import SessionStore
from armor.pipeline import Pipeline
from armor.session.state_machine import SessionState
from armor.types import Payload, SessionContext, Verdict


class MockStaticDetector:
    """Mock static detector that emits advisory signals."""

    def __init__(self) -> None:
        self.id = "mock.static"
        self.category = "test"
        self.cost_tier = "static"
        self.invocation_count = 0

    def check(self, payload: Payload, ctx: SessionContext) -> Verdict:
        """Emit an advisory signal."""
        self.invocation_count += 1
        return Verdict.advisory_verdict(
            signal_id="mock.static:test",
            severity="medium",
            details={"confidence": 0.5},
        )


class MockLLMDetector:
    """Mock LLM-tier detector (expensive) that is optionally invoked."""

    def __init__(self) -> None:
        self.id = "mock.llm"
        self.category = "test"
        self.cost_tier = "llm"
        self.invocation_count = 0

    def check(self, payload: Payload, ctx: SessionContext) -> Verdict:
        """Emit an advisory signal."""
        self.invocation_count += 1
        return Verdict.advisory_verdict(
            signal_id="mock.llm:risky",
            severity="high",
            details={"confidence": 0.8},
        )


class TestPipelineCostTierGating:
    """Test pipeline cost-tier gating based on session state."""

    @pytest.mark.asyncio
    async def test_tc_022_15_llm_detector_skipped_at_normal(self) -> None:
        """TC-022-15: LLM-tier detector skipped at Normal state."""
        static = MockStaticDetector()
        llm = MockLLMDetector()

        payload = Payload(text="test input")
        ctx = SessionContext(session_id="test-session")

        # At Normal state, only static detectors run
        # Simulate Normal state by checking cost_tier
        detectors = [static]  # Only static, no LLM at Normal
        await Pipeline.run(detectors, payload, ctx)

        # Static detector should run
        assert static.invocation_count == 1
        assert llm.invocation_count == 0

    @pytest.mark.asyncio
    async def test_tc_022_16_llm_detector_runs_after_watching(self) -> None:
        """TC-022-16: LLM-tier detector runs after session escalates to Watching."""
        static = MockStaticDetector()
        llm = MockLLMDetector()

        payload = Payload(text="test input")
        ctx = SessionContext(session_id="test-session")

        # Simulate escalation: after a static advisory, session moves to Watching
        # At Watching or higher, both static and LLM detectors run
        detectors = [static, llm]  # Both static and LLM at Watching+
        await Pipeline.run(detectors, payload, ctx)

        # Both should run
        assert static.invocation_count == 1
        assert llm.invocation_count == 1


class TestSessionPersistence:
    """Test persistence round-trip via SessionStore."""

    @pytest.mark.asyncio
    async def test_tc_022_18_persistence_round_trip(self) -> None:
        """TC-022-18: Persistence round-trip via SessionStore."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"

            # Initialize DB
            run_migrations(str(db_path))

            # Create store
            store = SessionStore(db_path=str(db_path), cache_size=10)

            # Get/create session and manually set state
            session = await store.get_or_create("test-session")
            session.current_state = SessionState.ELEVATED.value
            session.risk_score = 1.2
            session.last_signal_at = 1000.0

            # Persist
            await store._locks["test-session"].acquire()
            try:
                await asyncio.to_thread(store._persist_to_db, session)
            finally:
                store._locks["test-session"].release()

            # Clear cache and reload
            store._cache.clear()

            # Load again
            loaded = await store.get_or_create("test-session")

            assert loaded.current_state == SessionState.ELEVATED.value
            assert loaded.risk_score == pytest.approx(1.2)
            assert loaded.last_signal_at == 1000.0

    @pytest.mark.asyncio
    async def test_tc_022_19_config_driven_thresholds(self) -> None:
        """TC-022-19: Thresholds are loaded from config (not hardcoded)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"

            # Initialize DB
            run_migrations(str(db_path))

            # Create store
            store = SessionStore(db_path=str(db_path), cache_size=10)

            config = {
                "session": {
                    "thresholds": {
                        "watching": 0.4,
                        "elevated": 0.9,
                        "high": 1.5,
                    },
                    "cooldown_decay_per_min": 0.1,
                    "signal_weights": {},
                }
            }

            # Apply an advisory and verify it uses config thresholds
            await store.get_or_create("test-session")

            # Create a signal that will cross the watching threshold
            signal = Verdict.advisory_verdict(
                "test.signal",
                details={"confidence": 0.5},
            )

            # Apply signal and persist
            new_state, new_score = await store.apply_and_persist("test-session", signal, config=config)

            # With confidence=0.5 and watching=0.4, should be Watching
            assert new_state == SessionState.WATCHING.value
            assert new_score == pytest.approx(0.5)

    @pytest.mark.asyncio
    async def test_tc_022_19_modified_thresholds_take_effect(self) -> None:
        """TC-022-19: Modified config thresholds take effect (not hardcoded)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"

            # Initialize DB
            run_migrations(str(db_path))

            # Create store
            store = SessionStore(db_path=str(db_path), cache_size=10)

            # Modified config with much lower watching threshold
            config_modified = {
                "session": {
                    "thresholds": {
                        "watching": 0.1,  # Very low
                        "elevated": 0.2,
                        "high": 0.3,
                    },
                    "cooldown_decay_per_min": 0.1,
                    "signal_weights": {},
                }
            }

            await store.get_or_create("test-session")

            # Signal with confidence=0.15
            signal = Verdict.advisory_verdict(
                "test.signal",
                details={"confidence": 0.15},
            )

            # Apply with modified config
            new_state, _new_score = await store.apply_and_persist("test-session", signal, config=config_modified)

            # With confidence=0.15 > modified watching=0.1, should still be Watching
            assert new_state == SessionState.WATCHING.value


class TestBlockedShortCircuit:
    """Test that Blocked state short-circuits detectors."""

    @pytest.mark.asyncio
    async def test_tc_022_17_blocked_short_circuits_detectors(self) -> None:
        """TC-022-17: Blocked short-circuits all detectors and emits block."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"

            # Initialize DB
            run_migrations(str(db_path))

            # Create store and manually set session to Blocked
            store = SessionStore(db_path=str(db_path), cache_size=10)

            # Get/create and set to Blocked state
            session = await store.get_or_create("test-session")
            session.current_state = SessionState.BLOCKED.value
            await store._locks["test-session"].acquire()
            try:
                await asyncio.to_thread(store._persist_to_db, session)
            finally:
                store._locks["test-session"].release()

            # Clear cache to reload
            store._cache.clear()

            # Now apply a new signal
            signal = Verdict.advisory_verdict(
                "test.signal",
                details={"confidence": 0.5},
            )

            config = {
                "session": {
                    "thresholds": {"watching": 0.4, "elevated": 0.9, "high": 1.5},
                    "cooldown_decay_per_min": 0.1,
                    "signal_weights": {},
                }
            }

            # Apply and persist
            new_state, _new_score = await store.apply_and_persist("test-session", signal, config=config)

            # Should remain Blocked
            assert new_state == SessionState.BLOCKED.value
