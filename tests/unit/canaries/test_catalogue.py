"""Unit tests for canary catalogue loading and validation."""

import json
import tempfile
from pathlib import Path

import pytest

from armor.canaries.catalogue import CanaryEntry, Catalogue


class TestCanaryEntry:
    """Tests for CanaryEntry dataclass."""

    def test_create_entry(self):
        """Test creating a CanaryEntry."""
        entry = CanaryEntry(
            canary_id="aws-key-001",
            kind="credential",
            service="aws",
            value="AKIAARMORTRAP0000001",
            marker_rule=r"^AKIA[A-Z0-9]{16}$",
            active=True,
            created_at="2026-05-05T00:00:00Z",
        )
        assert entry.canary_id == "aws-key-001"
        assert entry.kind == "credential"
        assert entry.service == "aws"
        assert entry.value == "AKIAARMORTRAP0000001"
        assert entry.active is True

    def test_entry_is_frozen(self):
        """Test that CanaryEntry is immutable."""
        entry = CanaryEntry(
            canary_id="aws-key-001",
            kind="credential",
            service="aws",
            value="test",
            marker_rule=r"^test$",
            active=True,
            created_at="2026-05-05T00:00:00Z",
        )
        with pytest.raises(AttributeError):
            entry.canary_id = "changed"


class TestCatalogueLoad:
    """Tests for loading catalogues from JSON."""

    def test_load_valid_catalogue(self):
        """Test loading a valid catalogue from JSON."""
        data = [
            {
                "canary_id": "aws-key-001",
                "kind": "credential",
                "service": "aws",
                "value": "AKIAARMORTRAP0000001",
                "marker_rule": r"^AKIA[A-Z0-9]{16}$",
                "active": True,
                "created_at": "2026-05-05T00:00:00Z",
            },
            {
                "canary_id": "github-pat-001",
                "kind": "credential",
                "service": "github",
                "value": "ghp_abcdefghijklmnopqrstuvwxyz123456abcd",
                "marker_rule": r"^ghp_[A-Za-z0-9]{36}$",
                "active": True,
                "created_at": "2026-05-05T00:00:00Z",
            },
        ]

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            f.flush()
            path = f.name

        try:
            catalogue = Catalogue.load(path)
            assert len(catalogue.entries) == 2
            assert catalogue.entries[0].canary_id == "aws-key-001"
            assert catalogue.entries[1].canary_id == "github-pat-001"
        finally:
            Path(path).unlink()

    def test_load_file_not_found(self):
        """Test loading from non-existent file."""
        with pytest.raises(FileNotFoundError):
            Catalogue.load("/nonexistent/path/catalogue.json")

    def test_load_invalid_json(self):
        """Test loading invalid JSON."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("not valid json {")
            f.flush()
            path = f.name

        try:
            with pytest.raises(json.JSONDecodeError):
                Catalogue.load(path)
        finally:
            Path(path).unlink()

    def test_load_not_list(self):
        """Test loading JSON that is not a list."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"not": "a list"}, f)
            f.flush()
            path = f.name

        try:
            with pytest.raises(ValueError, match="must be a list"):
                Catalogue.load(path)
        finally:
            Path(path).unlink()

    def test_load_missing_field(self):
        """Test loading with missing required field."""
        data = [
            {
                "kind": "credential",
                "service": "aws",
                "value": "AKIAARMORTRAP0000001",
                # missing canary_id
                "marker_rule": r"^AKIA[A-Z0-9]{16}$",
                "active": True,
            }
        ]

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            f.flush()
            path = f.name

        try:
            with pytest.raises(ValueError, match="Missing field"):
                Catalogue.load(path)
        finally:
            Path(path).unlink()

    def test_load_value_not_matching_marker_rule(self):
        """Test rejection when value doesn't match marker_rule."""
        data = [
            {
                "canary_id": "aws-key-001",
                "kind": "credential",
                "service": "aws",
                "value": "NOT_A_KEY",
                "marker_rule": r"^AKIA[A-Z0-9]{16}$",
                "active": True,
                "created_at": "2026-05-05T00:00:00Z",
            }
        ]

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            f.flush()
            path = f.name

        try:
            with pytest.raises(ValueError, match="does not match marker_rule"):
                Catalogue.load(path)
        finally:
            Path(path).unlink()

    def test_load_invalid_marker_rule_regex(self):
        """Test rejection of invalid marker_rule regex."""
        data = [
            {
                "canary_id": "bad-regex",
                "kind": "credential",
                "service": "aws",
                "value": "test",
                "marker_rule": "[invalid(regex",
                "active": True,
                "created_at": "2026-05-05T00:00:00Z",
            }
        ]

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            f.flush()
            path = f.name

        try:
            with pytest.raises(ValueError, match="invalid marker_rule regex"):
                Catalogue.load(path)
        finally:
            Path(path).unlink()

    def test_load_inactive_canary_not_validated(self):
        """Test that inactive canaries are not validated."""
        data = [
            {
                "canary_id": "aws-key-001",
                "kind": "credential",
                "service": "aws",
                "value": "NOT_A_KEY",
                "marker_rule": r"^AKIA[A-Z0-9]{16}$",
                "active": False,  # inactive
                "created_at": "2026-05-05T00:00:00Z",
            },
            {
                "canary_id": "github-pat-001",
                "kind": "credential",
                "service": "github",
                "value": "ghp_abcdefghijklmnopqrstuvwxyz123456abcd",
                "marker_rule": r"^ghp_[A-Za-z0-9]{36}$",
                "active": True,
                "created_at": "2026-05-05T00:00:00Z",
            },
        ]

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            f.flush()
            path = f.name

        try:
            # Should load successfully despite inactive canary having bad value
            catalogue = Catalogue.load(path)
            assert len(catalogue.entries) == 2
        finally:
            Path(path).unlink()


class TestCatalogueEmpty:
    """Tests for empty catalogue rejection."""

    def test_empty_catalogue_rejected(self):
        """Test that empty catalogue is rejected."""
        with pytest.raises(ValueError, match="at least one active canary"):
            Catalogue([])

    def test_catalogue_with_only_inactive_rejected(self):
        """Test that catalogue with only inactive canaries is rejected."""
        entry = CanaryEntry(
            canary_id="aws-key-001",
            kind="credential",
            service="aws",
            value="AKIAARMORTRAP0000001",
            marker_rule=r"^AKIA[A-Z0-9]{16}$",
            active=False,
            created_at="2026-05-05T00:00:00Z",
        )

        with pytest.raises(ValueError, match="at least one active canary"):
            Catalogue([entry])


class TestCatalogueSaveAndLoad:
    """Tests for round-trip save and load."""

    def test_round_trip(self):
        """Test save and load round-trip preserves data."""
        entry1 = CanaryEntry(
            canary_id="aws-key-001",
            kind="credential",
            service="aws",
            value="AKIAARMORTRAP0000001",
            marker_rule=r"^AKIA[A-Z0-9]{16}$",
            active=True,
            created_at="2026-05-05T00:00:00Z",
        )
        entry2 = CanaryEntry(
            canary_id="github-pat-001",
            kind="credential",
            service="github",
            value="ghp_abcdefghijklmnopqrstuvwxyz123456abcd",
            marker_rule=r"^ghp_[A-Za-z0-9]{36}$",
            active=True,
            created_at="2026-05-05T00:00:00Z",
        )

        original = Catalogue([entry1, entry2])

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            path = f.name

        try:
            # Save and load
            original.save(path)
            loaded = Catalogue.load(path)

            # Check entries match
            assert len(loaded.entries) == 2
            assert loaded.entries[0].canary_id == entry1.canary_id
            assert loaded.entries[0].value == entry1.value
            assert loaded.entries[1].canary_id == entry2.canary_id
            assert loaded.entries[1].value == entry2.value
        finally:
            Path(path).unlink()


class TestCatalogueActivation:
    """Tests for filtering active canaries."""

    def test_active_canaries(self):
        """Test filtering to active canaries only."""
        entries = [
            CanaryEntry(
                canary_id="aws-key-001",
                kind="credential",
                service="aws",
                value="AKIAARMORTRAP0000001",
                marker_rule=r"^AKIA[A-Z0-9]{16}$",
                active=True,
                created_at="2026-05-05T00:00:00Z",
            ),
            CanaryEntry(
                canary_id="aws-key-002",
                kind="credential",
                service="aws",
                value="AKIAARMORTRAP0000002",
                marker_rule=r"^AKIA[A-Z0-9]{16}$",
                active=False,
                created_at="2026-05-05T00:00:00Z",
            ),
            CanaryEntry(
                canary_id="github-pat-001",
                kind="credential",
                service="github",
                value="ghp_abcdefghijklmnopqrstuvwxyz123456abcd",
                marker_rule=r"^ghp_[A-Za-z0-9]{36}$",
                active=True,
                created_at="2026-05-05T00:00:00Z",
            ),
        ]

        catalogue = Catalogue(entries)
        active = catalogue.active_canaries()

        assert len(active) == 2
        assert all(e.active for e in active)
        assert any(e.canary_id == "aws-key-001" for e in active)
        assert any(e.canary_id == "github-pat-001" for e in active)


class TestCatalogueGetById:
    """Tests for retrieving canaries by ID."""

    def test_get_by_id_found(self):
        """Test retrieving a canary by ID."""
        entry = CanaryEntry(
            canary_id="aws-key-001",
            kind="credential",
            service="aws",
            value="AKIAARMORTRAP0000001",
            marker_rule=r"^AKIA[A-Z0-9]{16}$",
            active=True,
            created_at="2026-05-05T00:00:00Z",
        )
        catalogue = Catalogue([entry])

        found = catalogue.get_by_id("aws-key-001")
        assert found == entry

    def test_get_by_id_not_found(self):
        """Test retrieving a non-existent canary."""
        entry = CanaryEntry(
            canary_id="aws-key-001",
            kind="credential",
            service="aws",
            value="AKIAARMORTRAP0000001",
            marker_rule=r"^AKIA[A-Z0-9]{16}$",
            active=True,
            created_at="2026-05-05T00:00:00Z",
        )
        catalogue = Catalogue([entry])

        found = catalogue.get_by_id("nonexistent")
        assert found is None


class TestCatalogueCountByKind:
    """Tests for counting canaries by kind."""

    def test_count_by_kind(self):
        """Test counting active canaries by kind."""
        entries = [
            CanaryEntry(
                canary_id="aws-key-001",
                kind="credential",
                service="aws",
                value="AKIAARMORTRAP0000001",
                marker_rule=r"^AKIA[A-Z0-9]{16}$",
                active=True,
                created_at="2026-05-05T00:00:00Z",
            ),
            CanaryEntry(
                canary_id="aws-key-002",
                kind="credential",
                service="aws",
                value="AKIAARMORTRAP0000002",
                marker_rule=r"^AKIA[A-Z0-9]{16}$",
                active=True,
                created_at="2026-05-05T00:00:00Z",
            ),
            CanaryEntry(
                canary_id="github-pat-001",
                kind="credential",
                service="github",
                value="ghp_abcdefghijklmnopqrstuvwxyz123456abcd",
                marker_rule=r"^ghp_[A-Za-z0-9]{36}$",
                active=True,
                created_at="2026-05-05T00:00:00Z",
            ),
            CanaryEntry(
                canary_id="url-001",
                kind="url",
                service="generic",
                value="https://canary.armor-trap.invalid/url-001",
                marker_rule=r"^https://canary\.armor-trap\.invalid/[a-z0-9\-]+$",
                active=False,
                created_at="2026-05-05T00:00:00Z",
            ),
        ]

        catalogue = Catalogue(entries)
        counts = catalogue.count_by_kind()

        assert counts["credential"] == 3
        assert "url" not in counts  # inactive canaries not counted
        assert len(counts) == 1  # only count kinds with active canaries
