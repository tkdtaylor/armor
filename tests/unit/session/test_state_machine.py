"""Unit tests for the session state machine.

TC-022-01 through TC-022-14: Core FSM logic (forward transitions, cooldown step-back,
Blocked terminal, score accumulation, per-detector weights, score floor).
"""

from datetime import datetime, timedelta

import pytest

from armor.session.state_machine import SessionState, apply_signal
from armor.types import Verdict


class TestSessionStateOrdering:
    """Test that SessionState ordering is correct."""

    def test_session_state_ordering(self) -> None:
        """Verify state ordering: Normal < Watching < Elevated < High < Blocked."""
        assert SessionState.NORMAL < SessionState.WATCHING
        assert SessionState.WATCHING < SessionState.ELEVATED
        assert SessionState.ELEVATED < SessionState.HIGH
        assert SessionState.HIGH < SessionState.BLOCKED

    def test_session_state_equality(self) -> None:
        """Verify state equality."""
        assert SessionState.NORMAL == SessionState.NORMAL
        assert SessionState.NORMAL != SessionState.WATCHING


class TestForwardTransitions:
    """Test forward transitions when score crosses thresholds."""

    def test_tc_022_01_normal_to_watching(self) -> None:
        """TC-022-01: Forward transition Normal → Watching on threshold crossing."""
        t0 = datetime(2026, 5, 6, 12, 0, 0)
        config = {
            "session": {
                "thresholds": {"watching": 0.4, "elevated": 0.9, "high": 1.5},
                "cooldown_decay_per_min": 0.1,
                "signal_weights": {},
            }
        }

        # Start at Normal with score 0.0
        # Apply advisory(confidence=0.5) with weight 1.0 → score = 0.5 ≥ 0.4
        signal = Verdict.advisory_verdict("test.signal", details={"confidence": 0.5})
        new_state, new_score = apply_signal(
            current_state=SessionState.NORMAL,
            current_score=0.0,
            signal=signal,
            last_signal_at=t0,
            now=t0,
            config=config,
        )

        assert new_state == SessionState.WATCHING
        assert new_score == pytest.approx(0.5)

    def test_tc_022_02_watching_to_elevated(self) -> None:
        """TC-022-02: Forward transition Watching → Elevated."""
        t0 = datetime(2026, 5, 6, 12, 0, 0)
        config = {
            "session": {
                "thresholds": {"watching": 0.4, "elevated": 0.9, "high": 1.5},
                "cooldown_decay_per_min": 0.1,
                "signal_weights": {},
            }
        }

        signal = Verdict.advisory_verdict("test.signal", details={"confidence": 0.6})
        new_state, new_score = apply_signal(
            current_state=SessionState.WATCHING,
            current_score=0.4,
            signal=signal,
            last_signal_at=t0,
            now=t0,
            config=config,
        )

        assert new_state == SessionState.ELEVATED
        assert new_score == pytest.approx(1.0)

    def test_tc_022_03_elevated_to_high(self) -> None:
        """TC-022-03: Forward transition Elevated → High."""
        t0 = datetime(2026, 5, 6, 12, 0, 0)
        config = {
            "session": {
                "thresholds": {"watching": 0.4, "elevated": 0.9, "high": 1.5},
                "cooldown_decay_per_min": 0.1,
                "signal_weights": {},
            }
        }

        signal = Verdict.advisory_verdict("test.signal", details={"confidence": 0.8})
        new_state, new_score = apply_signal(
            current_state=SessionState.ELEVATED,
            current_score=1.0,
            signal=signal,
            last_signal_at=t0,
            now=t0,
            config=config,
        )

        assert new_state == SessionState.HIGH
        assert new_score == pytest.approx(1.8)

    def test_tc_022_04_multi_rung_jump(self) -> None:
        """TC-022-04: Multi-rung jump in a single call."""
        t0 = datetime(2026, 5, 6, 12, 0, 0)
        config = {
            "session": {
                "thresholds": {"watching": 0.4, "elevated": 0.9, "high": 1.5},
                "cooldown_decay_per_min": 0.1,
                "signal_weights": {},
            }
        }

        # Large advisory jumps from Normal to High, skipping Watching and Elevated
        signal = Verdict.advisory_verdict("test.signal", details={"confidence": 2.0})
        new_state, new_score = apply_signal(
            current_state=SessionState.NORMAL,
            current_score=0.0,
            signal=signal,
            last_signal_at=t0,
            now=t0,
            config=config,
        )

        assert new_state == SessionState.HIGH
        assert new_score == pytest.approx(2.0)


class TestCooldownStepBack:
    """Test backward transitions when score decays below thresholds."""

    def test_tc_022_05_cooldown_watching_to_normal(self) -> None:
        """TC-022-05: Cooldown step-back Watching → Normal after decay."""
        t0 = datetime(2026, 5, 6, 12, 0, 0)
        t_later = t0 + timedelta(minutes=10)
        config = {
            "session": {
                "thresholds": {"watching": 0.4, "elevated": 0.9, "high": 1.5},
                "cooldown_decay_per_min": 0.1,
                "signal_weights": {},
            }
        }

        # In Watching with score 0.5; decay by 0.1 * 10 = 1.0 → score = 0.0 < 0.4
        signal = Verdict.advisory_verdict("test.signal", details={"confidence": 0.0})
        new_state, new_score = apply_signal(
            current_state=SessionState.WATCHING,
            current_score=0.5,
            signal=signal,
            last_signal_at=t0,
            now=t_later,
            config=config,
        )

        assert new_state == SessionState.NORMAL
        assert new_score == pytest.approx(0.0)

    def test_tc_022_06_cooldown_elevated_to_watching_single_rung(self) -> None:
        """TC-022-06: Cooldown step-back Elevated → Watching (single rung only)."""
        t0 = datetime(2026, 5, 6, 12, 0, 0)
        t_later = t0 + timedelta(minutes=100)  # Very large decay
        config = {
            "session": {
                "thresholds": {"watching": 0.4, "elevated": 0.9, "high": 1.5},
                "cooldown_decay_per_min": 0.1,
                "signal_weights": {},
            }
        }

        # In Elevated with score 1.0; decay by 0.1 * 100 = 10.0 → score clamped at 0
        # But state moves down by one rung only
        signal = Verdict.advisory_verdict("test.signal", details={"confidence": 0.0})
        new_state, new_score = apply_signal(
            current_state=SessionState.ELEVATED,
            current_score=1.0,
            signal=signal,
            last_signal_at=t0,
            now=t_later,
            config=config,
        )

        assert new_state == SessionState.WATCHING
        assert new_score == pytest.approx(0.0)

    def test_tc_022_07_cooldown_rung_by_rung_step_back(self) -> None:
        """TC-022-07: Cooldown step-back one rung per call (High → Elevated → Watching)."""
        t0 = datetime(2026, 5, 6, 12, 0, 0)
        t_later_1 = t0 + timedelta(minutes=100)
        t_later_2 = t_later_1 + timedelta(minutes=100)
        t_later_3 = t_later_2 + timedelta(minutes=100)

        config = {
            "session": {
                "thresholds": {"watching": 0.4, "elevated": 0.9, "high": 1.5},
                "cooldown_decay_per_min": 0.1,
                "signal_weights": {},
            }
        }

        # Start in High; first call steps to Elevated
        signal = Verdict.advisory_verdict("test.signal", details={"confidence": 0.0})
        state1, score1 = apply_signal(
            current_state=SessionState.HIGH,
            current_score=1.8,
            signal=signal,
            last_signal_at=t0,
            now=t_later_1,
            config=config,
        )
        assert state1 == SessionState.ELEVATED

        # Second call steps to Watching
        state2, score2 = apply_signal(
            current_state=state1,
            current_score=score1,
            signal=signal,
            last_signal_at=t_later_1,
            now=t_later_2,
            config=config,
        )
        assert state2 == SessionState.WATCHING

        # Third call steps to Normal
        state3, _score3 = apply_signal(
            current_state=state2,
            current_score=score2,
            signal=signal,
            last_signal_at=t_later_2,
            now=t_later_3,
            config=config,
        )
        assert state3 == SessionState.NORMAL


class TestBlockedTerminal:
    """Test that Blocked state is terminal."""

    def test_tc_022_08_block_from_normal_jumps_to_blocked(self) -> None:
        """TC-022-08: `block` signal jumps directly to Blocked from Normal."""
        t0 = datetime(2026, 5, 6, 12, 0, 0)
        config = {
            "session": {
                "thresholds": {"watching": 0.4, "elevated": 0.9, "high": 1.5},
                "cooldown_decay_per_min": 0.1,
                "signal_weights": {},
            }
        }

        signal = Verdict.block_verdict("test.block")
        new_state, _new_score = apply_signal(
            current_state=SessionState.NORMAL,
            current_score=0.0,
            signal=signal,
            last_signal_at=t0,
            now=t0,
            config=config,
        )

        assert new_state == SessionState.BLOCKED

    def test_tc_022_09_block_from_high_jumps_to_blocked(self) -> None:
        """TC-022-09: `block` signal jumps to Blocked from High."""
        t0 = datetime(2026, 5, 6, 12, 0, 0)
        config = {
            "session": {
                "thresholds": {"watching": 0.4, "elevated": 0.9, "high": 1.5},
                "cooldown_decay_per_min": 0.1,
                "signal_weights": {},
            }
        }

        signal = Verdict.block_verdict("test.block")
        new_state, _new_score = apply_signal(
            current_state=SessionState.HIGH,
            current_score=1.8,
            signal=signal,
            last_signal_at=t0,
            now=t0,
            config=config,
        )

        assert new_state == SessionState.BLOCKED

    def test_tc_022_10_blocked_terminal_under_cooldown(self) -> None:
        """TC-022-10: Blocked is terminal under cooldown."""
        t0 = datetime(2026, 5, 6, 12, 0, 0)
        t_later = t0 + timedelta(minutes=60)  # Huge decay
        config = {
            "session": {
                "thresholds": {"watching": 0.4, "elevated": 0.9, "high": 1.5},
                "cooldown_decay_per_min": 0.1,
                "signal_weights": {},
            }
        }

        signal = Verdict.advisory_verdict("test.signal", details={"confidence": 0.0})
        new_state, _new_score = apply_signal(
            current_state=SessionState.BLOCKED,
            current_score=2.0,
            signal=signal,
            last_signal_at=t0,
            now=t_later,
            config=config,
        )

        assert new_state == SessionState.BLOCKED

    def test_tc_022_11_blocked_terminal_under_advisories(self) -> None:
        """TC-022-11: Blocked is terminal under fresh advisories."""
        t0 = datetime(2026, 5, 6, 12, 0, 0)
        config = {
            "session": {
                "thresholds": {"watching": 0.4, "elevated": 0.9, "high": 1.5},
                "cooldown_decay_per_min": 0.1,
                "signal_weights": {},
            }
        }

        signal = Verdict.advisory_verdict("test.signal", details={"confidence": 0.5})
        new_state, _new_score = apply_signal(
            current_state=SessionState.BLOCKED,
            current_score=0.0,
            signal=signal,
            last_signal_at=t0,
            now=t0,
            config=config,
        )

        assert new_state == SessionState.BLOCKED


class TestScoreAccumulation:
    """Test score accumulation from signals."""

    def test_tc_022_12_rapid_fire_advisories_accumulate(self) -> None:
        """TC-022-12: Score accumulation from rapid-fire advisories."""
        t0 = datetime(2026, 5, 6, 12, 0, 0)
        config = {
            "session": {
                "thresholds": {"watching": 0.4, "elevated": 0.9, "high": 1.5},
                "cooldown_decay_per_min": 0.1,
                "signal_weights": {},
            }
        }

        # Call 1: score = 0.0 + 0.2 = 0.2 (Normal)
        signal1 = Verdict.advisory_verdict("test.signal", details={"confidence": 0.2})
        state1, score1 = apply_signal(
            current_state=SessionState.NORMAL,
            current_score=0.0,
            signal=signal1,
            last_signal_at=t0,
            now=t0,
            config=config,
        )
        assert score1 == pytest.approx(0.2)
        assert state1 == SessionState.NORMAL

        # Call 2: score = 0.2 + 0.2 = 0.4 (transitions to Watching)
        signal2 = Verdict.advisory_verdict("test.signal", details={"confidence": 0.2})
        state2, score2 = apply_signal(
            current_state=state1,
            current_score=score1,
            signal=signal2,
            last_signal_at=t0,
            now=t0,
            config=config,
        )
        assert score2 == pytest.approx(0.4)
        assert state2 == SessionState.WATCHING

        # Call 3: score = 0.4 + 0.2 = 0.6 (stays in Watching)
        signal3 = Verdict.advisory_verdict("test.signal", details={"confidence": 0.2})
        state3, score3 = apply_signal(
            current_state=state2,
            current_score=score2,
            signal=signal3,
            last_signal_at=t0,
            now=t0,
            config=config,
        )
        assert score3 == pytest.approx(0.6)
        assert state3 == SessionState.WATCHING

    def test_tc_022_13_per_detector_weight_override(self) -> None:
        """TC-022-13: Per-detector weight override."""
        t0 = datetime(2026, 5, 6, 12, 0, 0)
        config = {
            "session": {
                "thresholds": {"watching": 0.4, "elevated": 0.9, "high": 1.5},
                "cooldown_decay_per_min": 0.1,
                "signal_weights": {"meta.topic_coherence": 0.5},
            }
        }

        # Advisory from meta.topic_coherence with confidence=1.0 but weight=0.5
        signal = Verdict.advisory_verdict("meta.topic_coherence", details={"confidence": 1.0})
        _new_state, new_score = apply_signal(
            current_state=SessionState.NORMAL,
            current_score=0.0,
            signal=signal,
            last_signal_at=t0,
            now=t0,
            config=config,
        )

        # Score should be 1.0 * 0.5 = 0.5
        assert new_score == pytest.approx(0.5)

    def test_tc_022_14_score_floor_at_zero(self) -> None:
        """TC-022-14: Score floor at zero."""
        t0 = datetime(2026, 5, 6, 12, 0, 0)
        t_later = t0 + timedelta(minutes=100)  # Huge decay
        config = {
            "session": {
                "thresholds": {"watching": 0.4, "elevated": 0.9, "high": 1.5},
                "cooldown_decay_per_min": 0.1,
                "signal_weights": {},
            }
        }

        # Very low score with huge decay → should be clamped at 0.0
        signal = Verdict.advisory_verdict("test.signal", details={"confidence": 0.0})
        _new_state, new_score = apply_signal(
            current_state=SessionState.WATCHING,
            current_score=0.1,
            signal=signal,
            last_signal_at=t0,
            now=t_later,
            config=config,
        )

        assert new_score == pytest.approx(0.0)
        assert new_score >= 0.0


class TestConfigDefaults:
    """Test that config defaults work and are not hardcoded."""

    def test_apply_signal_with_no_config_uses_defaults(self) -> None:
        """Test that apply_signal works without config (uses hardcoded defaults)."""
        t0 = datetime(2026, 5, 6, 12, 0, 0)

        # No config provided; should use hardcoded defaults
        signal = Verdict.advisory_verdict("test.signal", details={"confidence": 0.5})
        new_state, new_score = apply_signal(
            current_state=SessionState.NORMAL,
            current_score=0.0,
            signal=signal,
            last_signal_at=t0,
            now=t0,
            config=None,
        )

        # With default watching=0.4, confidence=0.5 should cross the threshold
        assert new_state == SessionState.WATCHING
        assert new_score == pytest.approx(0.5)

    def test_thresholds_are_configurable(self) -> None:
        """Test that thresholds are loaded from config (not hardcoded)."""
        t0 = datetime(2026, 5, 6, 12, 0, 0)
        config_modified = {
            "session": {
                "thresholds": {"watching": 0.1, "elevated": 0.2, "high": 0.3},
                "cooldown_decay_per_min": 0.1,
                "signal_weights": {},
            }
        }

        # With modified thresholds, a small advisory should cross watching threshold
        signal = Verdict.advisory_verdict("test.signal", details={"confidence": 0.15})
        new_state, _new_score = apply_signal(
            current_state=SessionState.NORMAL,
            current_score=0.0,
            signal=signal,
            last_signal_at=t0,
            now=t0,
            config=config_modified,
        )

        # confidence=0.15 > modified watching=0.1 → should be Watching
        assert new_state == SessionState.WATCHING
