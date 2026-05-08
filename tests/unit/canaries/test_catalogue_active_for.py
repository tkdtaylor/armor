"""Unit tests for Catalogue.active_for() method and activation integration."""

from datetime import UTC, datetime

from armor.canaries.catalogue import CanaryEntry, Catalogue
from armor.types import SessionContext, Signal


class TestCatalogueActiveFor:
    """Tests for Catalogue.active_for() method."""

    def test_active_for_with_always_rule(self):
        """Test that canaries with 'always' rule are always active."""
        entry1 = CanaryEntry(
            canary_id="test-001",
            kind="credential",
            service="test",
            value="test-value-001",
            marker_rule="test.*",
            active=True,
            created_at="2026-05-07T00:00:00Z",
            activation={"type": "always"},
        )
        entry2 = CanaryEntry(
            canary_id="test-002",
            kind="credential",
            service="test",
            value="test-value-002",
            marker_rule="test.*",
            active=True,
            created_at="2026-05-07T00:00:00Z",
            activation=None,  # Defaults to always
        )

        catalogue = Catalogue([entry1, entry2])
        ctx = SessionContext(session_id="test")
        now = datetime.now(UTC)

        active = catalogue.active_for(ctx, now)
        active_ids = {e.canary_id for e in active}

        assert "test-001" in active_ids
        assert "test-002" in active_ids

    def test_active_for_excludes_inactive_entries(self):
        """Test that inactive=False entries are never returned."""
        entry1 = CanaryEntry(
            canary_id="test-001",
            kind="credential",
            service="test",
            value="test-value-001",
            marker_rule="test.*",
            active=True,
            created_at="2026-05-07T00:00:00Z",
        )
        entry2 = CanaryEntry(
            canary_id="test-002",
            kind="credential",
            service="test",
            value="test-value-002",
            marker_rule="test.*",
            active=False,  # Inactive
            created_at="2026-05-07T00:00:00Z",
        )

        catalogue = Catalogue([entry1, entry2])
        ctx = SessionContext(session_id="test")
        now = datetime.now(UTC)

        active = catalogue.active_for(ctx, now)
        active_ids = {e.canary_id for e in active}

        assert "test-001" in active_ids
        assert "test-002" not in active_ids

    def test_active_for_with_session_turn_min_rule(self):
        """Test that session_turn_min rule gates activation."""
        entry = CanaryEntry(
            canary_id="test-turn-gate",
            kind="credential",
            service="test",
            value="test-value",
            marker_rule="test.*",
            active=True,
            created_at="2026-05-07T00:00:00Z",
            activation={"type": "session_turn_min", "min_turns": 5},
        )

        catalogue = Catalogue([entry])
        now = datetime.now(UTC)

        # At turn 1: should not be active
        ctx1 = SessionContext(session_id="test", turn_count=1)
        active1 = catalogue.active_for(ctx1, now)
        assert len(active1) == 0

        # At turn 5: should be active
        ctx5 = SessionContext(session_id="test", turn_count=5)
        active5 = catalogue.active_for(ctx5, now)
        assert len(active5) == 1
        assert active5[0].canary_id == "test-turn-gate"

        # At turn 10: should still be active
        ctx10 = SessionContext(session_id="test", turn_count=10)
        active10 = catalogue.active_for(ctx10, now)
        assert len(active10) == 1
        assert active10[0].canary_id == "test-turn-gate"

    def test_active_for_values_consistency(self):
        """Test that active_for returns consistent values across calls."""
        entry = CanaryEntry(
            canary_id="test-001",
            kind="credential",
            service="test",
            value="consistent-value",
            marker_rule="test.*",
            active=True,
            created_at="2026-05-07T00:00:00Z",
            activation={"type": "session_turn_min", "min_turns": 1},
        )

        catalogue = Catalogue([entry])
        ctx = SessionContext(session_id="test", turn_count=1)
        now = datetime.now(UTC)

        # Call active_for multiple times with the same context
        active1 = catalogue.active_for(ctx, now)
        active2 = catalogue.active_for(ctx, now)
        active3 = catalogue.active_for(ctx, now)

        # All should have the same value
        assert active1[0].value == active2[0].value == active3[0].value
        assert active1[0].value == "consistent-value"

    def test_has_subset_changed_detects_changes(self):
        """Test that has_subset_changed() detects subset changes."""
        entry1 = CanaryEntry(
            canary_id="test-001",
            kind="credential",
            service="test",
            value="test-value-001",
            marker_rule="test.*",
            active=True,
            created_at="2026-05-07T00:00:00Z",
            activation={"type": "always"},
        )
        entry2 = CanaryEntry(
            canary_id="test-002",
            kind="credential",
            service="test",
            value="test-value-002",
            marker_rule="test.*",
            active=True,
            created_at="2026-05-07T00:00:00Z",
            activation={"type": "session_turn_min", "min_turns": 5},
        )

        catalogue = Catalogue([entry1, entry2])

        # First subset (only entry1 is active)
        subset1 = [entry1]
        changed1 = catalogue.has_subset_changed(subset1)
        assert changed1 is True  # First call always changes

        # Same subset (should not change)
        subset1_again = [entry1]
        changed1_again = catalogue.has_subset_changed(subset1_again)
        assert changed1_again is False

        # Different subset (should change)
        subset2 = [entry1, entry2]
        changed2 = catalogue.has_subset_changed(subset2)
        assert changed2 is True

        # Back to original subset (should change)
        subset1_final = [entry1]
        changed1_final = catalogue.has_subset_changed(subset1_final)
        assert changed1_final is True

    def test_active_for_with_tool_used_rule(self):
        """Test that tool_used rule gates activation."""
        entry = CanaryEntry(
            canary_id="test-tool-gate",
            kind="credential",
            service="test",
            value="test-value",
            marker_rule="test.*",
            active=True,
            created_at="2026-05-07T00:00:00Z",
            activation={"type": "tool_used", "tool": "WebFetch", "scope": "session"},
        )

        catalogue = Catalogue([entry])
        now = datetime.now(UTC)

        # Without tool usage signal
        ctx_no_tool = SessionContext(session_id="test", signal_history=[])
        active_no_tool = catalogue.active_for(ctx_no_tool, now)
        assert len(active_no_tool) == 0

        # With tool usage signal
        signal = Signal(
            timestamp=now.timestamp(),
            kind="meta.tool_rate.WebFetch",
            signal_id="meta.tool_rate:WebFetch",
            severity="low",
        )
        ctx_with_tool = SessionContext(session_id="test", signal_history=[signal])
        active_with_tool = catalogue.active_for(ctx_with_tool, now)
        assert len(active_with_tool) == 1
        assert active_with_tool[0].canary_id == "test-tool-gate"

    def test_active_for_with_fsm_state_rule(self):
        """Test that fsm_state_at_least rule gates activation."""
        entry = CanaryEntry(
            canary_id="test-fsm-gate",
            kind="credential",
            service="test",
            value="test-value",
            marker_rule="test.*",
            active=True,
            created_at="2026-05-07T00:00:00Z",
            activation={"type": "fsm_state_at_least", "state": "Elevated"},
        )

        catalogue = Catalogue([entry])
        now = datetime.now(UTC)

        # In Normal state: should not be active
        ctx_normal = SessionContext(session_id="test", state="Normal")
        active_normal = catalogue.active_for(ctx_normal, now)
        assert len(active_normal) == 0

        # In Elevated state: should be active
        ctx_elevated = SessionContext(session_id="test", state="Elevated")
        active_elevated = catalogue.active_for(ctx_elevated, now)
        assert len(active_elevated) == 1
        assert active_elevated[0].canary_id == "test-fsm-gate"

        # In High state: should be active (higher than threshold)
        ctx_high = SessionContext(session_id="test", state="High")
        active_high = catalogue.active_for(ctx_high, now)
        assert len(active_high) == 1
        assert active_high[0].canary_id == "test-fsm-gate"
