"""Unit tests for canary activation rules."""

from datetime import UTC, datetime

from armor.canaries.activation import (
    evaluate,
    hash_canary_id,
)
from armor.session.state_machine import SessionState
from armor.types import SessionContext, Signal


class TestActivationRuleEvaluation:
    """Tests for the evaluate() function."""

    def test_always_rule_is_always_true(self):
        """Test that 'always' rule returns True in any context."""
        rule = {"type": "always"}
        ctx = SessionContext(session_id="test")
        now = datetime.now(UTC)

        assert evaluate(rule, ctx, now) is True

    def test_missing_rule_defaults_to_always(self):
        """Test that missing rule defaults to always (backwards-compat)."""
        rule = {}
        ctx = SessionContext(session_id="test")
        now = datetime.now(UTC)

        assert evaluate(rule, ctx, now) is True

    def test_none_rule_defaults_to_always(self):
        """Test that None rule defaults to always (backwards-compat)."""
        rule = None
        ctx = SessionContext(session_id="test")
        now = datetime.now(UTC)

        assert evaluate(rule, ctx, now) is True

    def test_unknown_rule_type_returns_false(self):
        """Test that unknown rule type returns False (fail-closed)."""
        rule = {"type": "unknown_rule_type"}
        ctx = SessionContext(session_id="test")
        now = datetime.now(UTC)

        assert evaluate(rule, ctx, now) is False

    def test_tool_used_rule_with_no_history(self):
        """Test that tool_used rule returns False when no tool used."""
        rule = {"type": "tool_used", "tool": "WebFetch", "scope": "session"}
        ctx = SessionContext(session_id="test", signal_history=[])
        now = datetime.now(UTC)

        assert evaluate(rule, ctx, now) is False

    def test_tool_used_rule_with_matching_signal(self):
        """Test that tool_used rule returns True when tool signal exists."""
        rule = {"type": "tool_used", "tool": "WebFetch", "scope": "session"}
        signal = Signal(
            timestamp=datetime.now(UTC).timestamp(),
            kind="meta.tool_rate.WebFetch",
            signal_id="meta.tool_rate:WebFetch",
            severity="low",
        )
        ctx = SessionContext(session_id="test", signal_history=[signal])
        now = datetime.now(UTC)

        assert evaluate(rule, ctx, now) is True

    def test_tool_used_rule_missing_tool_field(self):
        """Test that tool_used rule without 'tool' field returns False."""
        rule = {"type": "tool_used"}
        ctx = SessionContext(session_id="test")
        now = datetime.now(UTC)

        assert evaluate(rule, ctx, now) is False

    def test_session_turn_min_rule_below_threshold(self):
        """Test that session_turn_min rule returns False below threshold."""
        rule = {"type": "session_turn_min", "min_turns": 10}
        ctx = SessionContext(session_id="test", turn_count=5)
        now = datetime.now(UTC)

        assert evaluate(rule, ctx, now) is False

    def test_session_turn_min_rule_at_threshold(self):
        """Test that session_turn_min rule returns True at threshold."""
        rule = {"type": "session_turn_min", "min_turns": 10}
        ctx = SessionContext(session_id="test", turn_count=10)
        now = datetime.now(UTC)

        assert evaluate(rule, ctx, now) is True

    def test_session_turn_min_rule_above_threshold(self):
        """Test that session_turn_min rule returns True above threshold."""
        rule = {"type": "session_turn_min", "min_turns": 10}
        ctx = SessionContext(session_id="test", turn_count=15)
        now = datetime.now(UTC)

        assert evaluate(rule, ctx, now) is True

    def test_session_turn_min_rule_falls_back_to_signal_history(self):
        """Test that session_turn_min rule falls back to signal_history length."""
        rule = {"type": "session_turn_min", "min_turns": 3}
        signal1 = Signal(timestamp=1.0, kind="test1", signal_id="test1", severity="low")
        signal2 = Signal(timestamp=2.0, kind="test2", signal_id="test2", severity="low")
        signal3 = Signal(timestamp=3.0, kind="test3", signal_id="test3", severity="low")
        ctx = SessionContext(
            session_id="test",
            signal_history=[signal1, signal2, signal3],
            turn_count=0,  # turn_count is 0, so fallback to signal_history
        )
        now = datetime.now(UTC)

        assert evaluate(rule, ctx, now) is True

    def test_time_window_rule_requires_hash(self):
        """Test that time_window rule requires _canary_hash injection."""
        rule = {"type": "time_window", "period_days": 7}
        ctx = SessionContext(session_id="test")
        now = datetime.now(UTC)

        # Without hash, should return False (validation fails)
        assert evaluate(rule, ctx, now) is False

    def test_time_window_rule_with_hash(self):
        """Test that time_window rule works with injected hash."""
        day_of_year = datetime.now(UTC).timetuple().tm_yday
        period = 7
        # To make (day_of_year + hash) % period == 0, we need:
        # hash = (period - (day_of_year % period)) % period
        hash_val = (period - (day_of_year % period)) % period

        rule = {
            "type": "time_window",
            "period_days": period,
            "_canary_hash": hash_val,
        }
        ctx = SessionContext(session_id="test")
        now = datetime.now(UTC)

        assert evaluate(rule, ctx, now) is True

    def test_fsm_state_at_least_with_no_history(self):
        """Test fsm_state_at_least with no state history."""
        rule = {"type": "fsm_state_at_least", "state": "Watching"}
        ctx = SessionContext(session_id="test", state=SessionState.NORMAL)
        now = datetime.now(UTC)

        assert evaluate(rule, ctx, now) is False

    def test_fsm_state_at_least_with_matching_state(self):
        """Test fsm_state_at_least when current state matches."""
        rule = {"type": "fsm_state_at_least", "state": "Watching"}
        ctx = SessionContext(session_id="test", state=SessionState.WATCHING)
        now = datetime.now(UTC)

        assert evaluate(rule, ctx, now) is True

    def test_fsm_state_at_least_with_elevated_state(self):
        """Test fsm_state_at_least when current state is above threshold."""
        rule = {"type": "fsm_state_at_least", "state": "Watching"}
        ctx = SessionContext(session_id="test", state=SessionState.ELEVATED)
        now = datetime.now(UTC)

        assert evaluate(rule, ctx, now) is True

    def test_fsm_state_at_least_missing_state_field(self):
        """Test fsm_state_at_least without 'state' field."""
        rule = {"type": "fsm_state_at_least"}
        ctx = SessionContext(session_id="test", state=SessionState.NORMAL)
        now = datetime.now(UTC)

        assert evaluate(rule, ctx, now) is False

    def test_fsm_state_at_least_unknown_state(self):
        """Test fsm_state_at_least with unknown state name."""
        rule = {"type": "fsm_state_at_least", "state": "UnknownState"}
        ctx = SessionContext(session_id="test", state=SessionState.NORMAL)
        now = datetime.now(UTC)

        assert evaluate(rule, ctx, now) is False


class TestHashCanaryId:
    """Tests for the hash_canary_id() function."""

    def test_hash_is_deterministic(self):
        """Test that hash_canary_id returns the same hash for the same ID."""
        id1 = "aws-key-001"
        hash1 = hash_canary_id(id1)
        hash2 = hash_canary_id(id1)

        assert hash1 == hash2

    def test_hash_differs_for_different_ids(self):
        """Test that different IDs produce different hashes."""
        hash1 = hash_canary_id("aws-key-001")
        hash2 = hash_canary_id("github-pat-001")

        assert hash1 != hash2

    def test_hash_is_within_32bit_range(self):
        """Test that hash is within 32-bit unsigned integer range."""
        h = hash_canary_id("any-id")
        assert 0 <= h < 2**32

    def test_hash_is_int(self):
        """Test that hash returns an integer."""
        h = hash_canary_id("test-id")
        assert isinstance(h, int)
