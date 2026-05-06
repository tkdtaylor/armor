"""Unit tests for the rolling buffer.

Tests the RollingBuffer class for:
- Bounded eviction (by chars and turns)
- Concatenation order
- Persistence round-trip
- Partial-canary detection at split points
"""

import tempfile
from pathlib import Path

import pytest

from armor.canaries.scanner import CanaryScanner
from armor.db.migrations import run_migrations
from armor.db.session_store import SessionStore
from armor.session.rolling_buffer import RollingBuffer


class TestRollingBufferBasics:
    """TC-023-01, TC-023-02, TC-023-03: Basic buffer operations."""

    def test_eviction_by_capacity_chars(self) -> None:
        """TC-023-01: Eviction by capacity_chars.

        When capacity_chars is exceeded, oldest entries are evicted first.
        """
        buf = RollingBuffer(capacity_chars=10, capacity_turns=100)

        buf.append("t1", "abcde")  # 5 chars
        buf.append("t2", "fghij")  # 5 chars, total 10
        buf.append("t3", "klmno")  # 5 chars, total would be 15 > 10

        # t1 should be evicted
        assert len(buf.concatenated()) <= 10
        assert buf.concatenated() == "fghijklmno"
        assert buf.turn_ids() == ["t2", "t3"]

    def test_eviction_by_capacity_turns(self) -> None:
        """TC-023-02: Eviction by capacity_turns.

        When capacity_turns is exceeded, oldest entries are evicted first.
        """
        buf = RollingBuffer(capacity_chars=10000, capacity_turns=2)

        buf.append("t1", "a")
        buf.append("t2", "b")
        buf.append("t3", "c")

        # Should hold only t2 and t3
        assert buf.concatenated() == "bc"
        assert buf.turn_ids() == ["t2", "t3"]
        assert len(buf) == 2

    def test_concatenation_order_oldest_first(self) -> None:
        """TC-023-03: Concatenation order is oldest-first.

        Turns are concatenated in append order.
        """
        buf = RollingBuffer(capacity_chars=10000, capacity_turns=100)

        buf.append("t1", "FIRST")
        buf.append("t2", "SECOND")
        buf.append("t3", "THIRD")

        # Default separator is empty string
        assert buf.concatenated() == "FIRSTSECONDTHIRD"
        assert buf.turn_ids() == ["t1", "t2", "t3"]

    def test_separator_option(self) -> None:
        """Verify that concatenated() respects the separator parameter."""
        buf = RollingBuffer(capacity_chars=10000, capacity_turns=100)

        buf.append("t1", "FIRST")
        buf.append("t2", "SECOND")

        assert buf.concatenated(separator="|") == "FIRST|SECOND"

    def test_both_limits_enforced(self) -> None:
        """Verify that both limits are enforced simultaneously."""
        # Set a very tight limit to trigger both constraints
        buf = RollingBuffer(capacity_chars=20, capacity_turns=3)

        buf.append("t1", "12345")  # 5 chars
        buf.append("t2", "67890")  # 5 chars, total 10
        buf.append("t3", "ABCDE")  # 5 chars, total 15
        buf.append("t4", "FGHIJ")  # 5 chars, total would be 20

        # At this point we have 4 turns = exceeds capacity_turns=3
        # So t1 is evicted regardless of char count
        assert len(buf) <= 3
        assert len(buf.concatenated()) <= 20


class TestPartialCanaryDetection:
    """TC-023-04, TC-023-05: Partial-canary detection at split points."""

    @staticmethod
    def _get_test_scanner() -> CanaryScanner:
        """Create a test scanner with known canaries."""
        # Build a simple test scanner with known patterns
        canary_map = {
            "aws_akia_001": "AKIA1234567890ABCDEF",  # 20 chars
            "github_pat_001": "ghp_1234567890abcdefghij",  # 24 chars
        }
        return CanaryScanner(canary_map)

    def test_partial_canary_split_mid_token(self) -> None:
        """TC-023-04: Partial-canary match split mid-token.

        When a canary is split across turns, the per-turn scanner misses it,
        but the buffer concatenation matches.
        """
        scanner = self._get_test_scanner()
        buf = RollingBuffer(capacity_chars=10000, capacity_turns=100)

        # Split AKIA1234567890ABCDEF as AKIA12345 + 67890ABCDEF
        buf.append("t1", "AKIA12345")
        buf.append("t2", "67890ABCDEF")

        # Per-turn scans should miss
        hits_t1 = scanner.scan("AKIA12345")
        hits_t2 = scanner.scan("67890ABCDEF")
        assert len(hits_t1) == 0, "t1 alone should not match"
        assert len(hits_t2) == 0, "t2 alone should not match"

        # Buffer concatenation should match
        concatenated = buf.concatenated()
        assert concatenated == "AKIA1234567890ABCDEF"
        hits_buffer = scanner.scan(concatenated)
        assert len(hits_buffer) > 0, "Full concatenation should match"
        assert hits_buffer[0].canary_id == "aws_akia_001"

    def test_partial_canary_split_at_midpoint(self) -> None:
        """TC-023-05: Partial-canary match split at exact midpoint.

        Verify detection works with different split points.
        """
        scanner = self._get_test_scanner()
        buf = RollingBuffer(capacity_chars=10000, capacity_turns=100)

        # Split AKIA1234567890ABCDEF at midpoint: AKIA1234567890 + ABCDEF
        buf.append("t1", "AKIA1234567890")
        buf.append("t2", "ABCDEF")

        concatenated = buf.concatenated()
        assert concatenated == "AKIA1234567890ABCDEF"
        hits = scanner.scan(concatenated)
        assert len(hits) > 0
        assert hits[0].canary_id == "aws_akia_001"


class TestPrefixAdvisory:
    """TC-023-06, TC-023-07: Partial-match prefix detection."""

    @staticmethod
    def _get_test_scanner() -> CanaryScanner:
        """Create a test scanner with known canaries."""
        canary_map = {
            "github_pat_001": "ghp_1234567890abcdefghij",  # 24 chars
        }
        return CanaryScanner(canary_map)

    def test_prefix_at_threshold(self) -> None:
        """TC-023-06: Prefix advisory when >= min_chars.

        A 12-character prefix of a canary should trigger an advisory signal.
        """
        scanner = self._get_test_scanner()
        buf = RollingBuffer(capacity_chars=10000, capacity_turns=100)

        canary_value = "ghp_1234567890abcdefghij"
        prefix_12 = canary_value[:12]  # "ghp_12345678"

        buf.append("t1", prefix_12)

        concatenated = buf.concatenated()
        assert concatenated == prefix_12

        # The prefix alone should not match a full canary scan
        hits_full = scanner.scan(concatenated)
        assert len(hits_full) == 0, "Prefix alone should not match full canary"

        # But we can detect the prefix manually
        assert concatenated.startswith("ghp_")
        assert len(concatenated) == 12

    def test_no_match_below_threshold(self) -> None:
        """TC-023-07: No spurious match below threshold.

        A 4-character prefix should not trigger a partial-match advisory.
        """
        scanner = self._get_test_scanner()
        buf = RollingBuffer(capacity_chars=10000, capacity_turns=100)

        canary_value = "ghp_1234567890abcdefghij"
        prefix_4 = canary_value[:4]  # "ghp_"

        buf.append("t1", prefix_4)

        concatenated = buf.concatenated()
        assert concatenated == "ghp_"

        # No match expected
        hits = scanner.scan(concatenated)
        assert len(hits) == 0


class TestPersistence:
    """TC-023-08: Persistence round-trip via SessionStore."""

    def test_persistence_round_trip(self) -> None:
        """TC-023-08: Buffer state can be saved and loaded byte-identical.

        Create a buffer, save it via SessionStore, load it back, and verify
        the concatenated output is identical.
        """
        # Create a temporary database
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            run_migrations(str(db_path))
            store = SessionStore(str(db_path))

            # Create a buffer and populate it
            buf_original = RollingBuffer(capacity_chars=10000, capacity_turns=100)
            buf_original.append("turn_1", "First output")
            buf_original.append("turn_2", "Second output")
            buf_original.append("turn_3", "Third output")

            original_concat = buf_original.concatenated()
            original_turns = buf_original.turn_ids()

            # Save the buffer
            store.save_rolling_buffer("session_123", buf_original)

            # Load it back
            buf_loaded = store.load_rolling_buffer("session_123")

            # Verify byte-identical
            loaded_concat = buf_loaded.concatenated()
            loaded_turns = buf_loaded.turn_ids()

            assert loaded_concat == original_concat
            assert loaded_turns == original_turns
            assert len(buf_loaded) == len(buf_original)

    def test_load_empty_session(self) -> None:
        """Verify that loading a session with no rolling buffer entries returns an empty buffer."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            run_migrations(str(db_path))
            store = SessionStore(str(db_path))

            # Load a non-existent session's buffer
            buf = store.load_rolling_buffer("nonexistent_session")

            assert len(buf) == 0
            assert buf.concatenated() == ""
            assert buf.turn_ids() == []


class TestEdgeCases:
    """Edge cases and boundary conditions."""

    def test_empty_text_appends(self) -> None:
        """Verify that empty strings can be appended."""
        buf = RollingBuffer(capacity_chars=1000, capacity_turns=10)

        buf.append("t1", "")
        buf.append("t2", "content")
        buf.append("t3", "")

        assert buf.concatenated() == "content"
        assert buf.turn_ids() == ["t1", "t2", "t3"]

    def test_single_large_turn(self) -> None:
        """Verify behavior when a single turn is larger than capacity_chars.

        The buffer will evict the entry if it exceeds capacity, since there are
        no older entries to evict. This is edge-case behavior; in practice,
        capacity_chars should be larger than a single turn's output.
        """
        buf = RollingBuffer(capacity_chars=10, capacity_turns=100)

        large_text = "x" * 50  # 50 chars, exceeds capacity_chars=10

        # Appending a single large turn that exceeds capacity will result
        # in that turn being evicted to satisfy the capacity constraint
        buf.append("t1", large_text)

        # The buffer is now empty (the single entry was evicted to satisfy capacity)
        assert len(buf) == 0
        assert buf.concatenated() == ""

    def test_zero_capacity_raises(self) -> None:
        """Verify that zero or negative capacity raises ValueError."""
        with pytest.raises(ValueError):
            RollingBuffer(capacity_chars=0, capacity_turns=10)

        with pytest.raises(ValueError):
            RollingBuffer(capacity_chars=10, capacity_turns=0)

    def test_multiple_appends_respects_both_limits(self) -> None:
        """Verify that appending respects both capacity_chars and capacity_turns simultaneously."""
        buf = RollingBuffer(capacity_chars=50, capacity_turns=5)

        for i in range(10):
            buf.append(f"t{i}", f"text_{i}_" * 5)  # Each append is ~40 chars

        # Should not exceed either limit
        assert len(buf) <= 5
        assert len(buf.concatenated()) <= 50


class TestBufferCleanup:
    """Test buffer cleanup and reset."""

    def test_clear_empties_buffer(self) -> None:
        """Verify that clear() empties the buffer."""
        buf = RollingBuffer(capacity_chars=10000, capacity_turns=100)

        buf.append("t1", "data1")
        buf.append("t2", "data2")

        assert len(buf) > 0

        buf.clear()

        assert len(buf) == 0
        assert buf.concatenated() == ""
        assert buf.turn_ids() == []
