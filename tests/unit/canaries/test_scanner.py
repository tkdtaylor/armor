"""Unit tests for canary scanner."""

import pytest

from armor.canaries.scanner import CanaryHit, CanaryScanner


class TestCanaryHit:
    """Tests for CanaryHit dataclass."""

    def test_create_hit(self):
        """Test creating a CanaryHit."""
        hit = CanaryHit(canary_id="aws-key-001", position=10)
        assert hit.canary_id == "aws-key-001"
        assert hit.position == 10

    def test_hit_is_frozen(self):
        """Test that CanaryHit is immutable."""
        hit = CanaryHit(canary_id="aws-key-001", position=10)
        with pytest.raises(AttributeError):
            hit.canary_id = "changed"


class TestCanaryScannerInit:
    """Tests for scanner initialization."""

    def test_init_with_canaries(self):
        """Test initializing scanner with canaries."""
        canaries = {
            "aws-key-001": "EXAMPLEKEY0000000001",
            "github-pat-001": "ghp_abcdefghijklmnopqrstuvwxyz123456abcd",
        }
        scanner = CanaryScanner(canaries)
        assert scanner is not None

    def test_init_empty_raises(self):
        """Test that empty canary dict raises."""
        with pytest.raises(ValueError, match="at least one canary"):
            CanaryScanner({})


class TestCanaryScannerScan:
    """Tests for scanning text."""

    def test_scan_single_hit(self):
        """Test scanning text with a single canary hit."""
        canaries = {"aws-key-001": "EXAMPLEKEY0000000001"}
        scanner = CanaryScanner(canaries)

        text = "Here is a secret: EXAMPLEKEY0000000001 do not share"
        hits = scanner.scan(text)

        assert len(hits) == 1
        assert hits[0].canary_id == "aws-key-001"
        # Position should be where the match ends
        assert hits[0].position > 0

    def test_scan_no_hits(self):
        """Test scanning text with no hits."""
        canaries = {"aws-key-001": "EXAMPLEKEY0000000001"}
        scanner = CanaryScanner(canaries)

        text = "This is benign text with no secrets"
        hits = scanner.scan(text)

        assert len(hits) == 0

    def test_scan_multiple_hits(self):
        """Test scanning text with multiple hits."""
        canaries = {
            "aws-key-001": "EXAMPLEKEY0000000001",
            "github-pat-001": "ghp_abcdefghijklmnopqrstuvwxyz123456abcd",
        }
        scanner = CanaryScanner(canaries)

        text = "Stolen: EXAMPLEKEY0000000001 and ghp_abcdefghijklmnopqrstuvwxyz123456abcd"
        hits = scanner.scan(text)

        assert len(hits) == 2
        canary_ids = [hit.canary_id for hit in hits]
        assert "aws-key-001" in canary_ids
        assert "github-pat-001" in canary_ids

    def test_scan_hit_at_position_zero(self):
        """Test scanning with hit at start of text."""
        canaries = {"aws-key-001": "EXAMPLEKEY0000000001"}
        scanner = CanaryScanner(canaries)

        text = "EXAMPLEKEY0000000001 is the secret"
        hits = scanner.scan(text)

        assert len(hits) == 1
        # Position should be end of match (len of canary - 1 for 0-indexing, then +1 for end)
        assert hits[0].position == len("EXAMPLEKEY0000000001") - 1

    def test_scan_hit_at_end(self):
        """Test scanning with hit at end of text."""
        canaries = {"aws-key-001": "EXAMPLEKEY0000000001"}
        scanner = CanaryScanner(canaries)

        text = "The secret is EXAMPLEKEY0000000001"
        hits = scanner.scan(text)

        assert len(hits) == 1
        assert hits[0].canary_id == "aws-key-001"

    def test_scan_empty_text(self):
        """Test scanning empty text."""
        canaries = {"aws-key-001": "EXAMPLEKEY0000000001"}
        scanner = CanaryScanner(canaries)

        hits = scanner.scan("")
        assert len(hits) == 0

    def test_scan_overlapping_patterns(self):
        """Test scanning with overlapping pattern matches."""
        # Create canaries where one is a substring/pattern of another
        canaries = {
            "canary-1": "AAA",
            "canary-2": "AAAA",
        }
        scanner = CanaryScanner(canaries)

        # Text with overlapping match
        text = "AAAA"
        hits = scanner.scan(text)

        # Should find matches
        assert len(hits) >= 1

    def test_scan_no_value_in_hit(self):
        """Test that hit does not contain the canary value."""
        canaries = {"aws-key-001": "EXAMPLEKEY0000000001"}
        scanner = CanaryScanner(canaries)

        text = "EXAMPLEKEY0000000001 leaked"
        hits = scanner.scan(text)

        assert len(hits) == 1
        hit = hits[0]
        # Hit should have canary_id and position, but not the value
        assert hasattr(hit, "canary_id")
        assert hasattr(hit, "position")
        assert not hasattr(hit, "value")

    def test_scan_case_sensitive(self):
        """Test that scanning is case-sensitive."""
        canaries = {"aws-key-001": "EXAMPLEKEY0000000001"}
        scanner = CanaryScanner(canaries)

        # Lowercase should not match
        text = "akiaarmortrap000001"
        hits = scanner.scan(text)
        assert len(hits) == 0

    def test_scan_partial_match_not_detected(self):
        """Test that partial matches are not detected."""
        canaries = {"aws-key-001": "EXAMPLEKEY0000000001"}
        scanner = CanaryScanner(canaries)

        # Partial match should not trigger
        text = "AKIAARMORTRAP00000"
        hits = scanner.scan(text)
        assert len(hits) == 0

    def test_scan_with_surrounding_text(self):
        """Test scanning where canary has surrounding text."""
        canaries = {"aws-key-001": "EXAMPLEKEY0000000001"}
        scanner = CanaryScanner(canaries)

        text = "prefix EXAMPLEKEY0000000001 suffix"
        hits = scanner.scan(text)

        assert len(hits) == 1
        assert hits[0].canary_id == "aws-key-001"

    def test_scan_repeated_canary(self):
        """Test scanning with same canary repeated."""
        canaries = {"aws-key-001": "EXAMPLEKEY0000000001"}
        scanner = CanaryScanner(canaries)

        text = "EXAMPLEKEY0000000001 and EXAMPLEKEY0000000001 again"
        hits = scanner.scan(text)

        assert len(hits) == 2
        assert all(hit.canary_id == "aws-key-001" for hit in hits)

    def test_scan_many_canaries(self):
        """Test scanner with many canaries."""
        canaries = {f"canary-{i:03d}": f"VALUE{i:03d}" for i in range(100)}
        scanner = CanaryScanner(canaries)

        text = "DATA VALUE050 DATA VALUE075 DATA"
        hits = scanner.scan(text)

        assert len(hits) == 2
        canary_ids = [hit.canary_id for hit in hits]
        assert "canary-050" in canary_ids
        assert "canary-075" in canary_ids
