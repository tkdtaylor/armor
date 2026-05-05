"""Unit tests for canary value generation at install time."""

import json
import os
import re
import stat

import pytest

from armor.canaries._generate import _generate_value_for_pattern, generate_values, write_values_file
from armor.canaries.catalogue import Catalogue


class TestGenerateValueForPattern:
    """Tests for pattern-specific value generation."""

    def test_aws_key_generation(self):
        """Test AWS key pattern generation."""
        pattern = r"^AKIA[A-Z0-9]{16}$"
        value = _generate_value_for_pattern(pattern)
        assert re.match(pattern, value)
        assert value.startswith("AKIA")
        assert len(value) == 20

    def test_github_pat_generation(self):
        """Test GitHub PAT pattern generation."""
        pattern = r"^ghp_[A-Za-z0-9]{36}$"
        value = _generate_value_for_pattern(pattern)
        assert re.match(pattern, value)
        assert value.startswith("ghp_")
        assert len(value) == 40

    def test_stripe_key_generation(self):
        """Test Stripe key pattern generation."""
        pattern = r"^sk_live_[A-Za-z0-9]{24}$"
        value = _generate_value_for_pattern(pattern)
        assert re.match(pattern, value)
        assert value.startswith("sk_live_")
        assert len(value) == 32

    def test_url_generation(self):
        """Test URL pattern generation."""
        pattern = r"^https://canary\.armor-trap\.invalid/[a-z0-9\-]+$"
        value = _generate_value_for_pattern(pattern)
        assert re.match(pattern, value)
        assert value.startswith("https://canary.armor-trap.invalid/")

    def test_path_generation(self):
        """Test path pattern generation."""
        pattern = r"^/etc/armor-canary-[a-z0-9\-]+\.pem$"
        value = _generate_value_for_pattern(pattern)
        assert re.match(pattern, value)
        assert value.startswith("/etc/armor-canary-")
        assert value.endswith(".pem")

    def test_hostname_generation(self):
        """Test hostname pattern generation."""
        pattern = r"^[a-z0-9\-]+\.canary\.armor-trap\.invalid$"
        value = _generate_value_for_pattern(pattern)
        assert re.match(pattern, value)
        assert value.endswith(".canary.armor-trap.invalid")

    def test_email_generation(self):
        """Test email pattern generation."""
        pattern = r"^canary-[a-z0-9\-]+@armor-trap\.invalid$"
        value = _generate_value_for_pattern(pattern)
        assert re.match(pattern, value)
        assert value.startswith("canary-")
        assert value.endswith("@armor-trap.invalid")

    def test_wallet_generation(self):
        """Test wallet pattern generation."""
        pattern = r"^1ARMORTRAP[0-9a-f]{32}$"
        value = _generate_value_for_pattern(pattern)
        assert re.match(pattern, value)
        assert value.startswith("1ARMORTRAP")
        assert len(value) == 42

    def test_unknown_pattern_raises(self):
        """Test that unknown patterns raise ValueError."""
        pattern = r"^unknown-pattern-[a-z]+$"
        with pytest.raises(ValueError, match="Don't know how to generate"):
            _generate_value_for_pattern(pattern)


class TestGenerateValues:
    """Tests for the generate_values function."""

    def test_generate_values_from_schema(self, tmp_path):
        """Test generating values from a schema file. TC-015-02"""
        # Create a minimal schema
        schema = [
            {
                "canary_id": "aws-key-000",
                "kind": "credential",
                "service": "aws",
                "marker_rule": r"^AKIA[A-Z0-9]{16}$",
                "active": True,
                "created_at": "2026-05-05T00:00:00Z",
            },
            {
                "canary_id": "github-pat-000",
                "kind": "credential",
                "service": "github",
                "marker_rule": r"^ghp_[A-Za-z0-9]{36}$",
                "active": True,
                "created_at": "2026-05-05T00:00:00Z",
            },
        ]
        schema_file = tmp_path / "schema.json"
        with open(schema_file, "w") as f:
            json.dump(schema, f)

        values = generate_values(schema_file)
        assert len(values) == 2
        assert values[0]["canary_id"] == "aws-key-000"
        assert re.match(r"^AKIA[A-Z0-9]{16}$", values[0]["value"])
        assert values[1]["canary_id"] == "github-pat-000"
        assert re.match(r"^ghp_[A-Za-z0-9]{36}$", values[1]["value"])

    def test_deterministic_generation_with_seed(self, tmp_path):
        """Test deterministic generation with the same seed. TC-015-02"""
        schema = [
            {
                "canary_id": "aws-key-000",
                "kind": "credential",
                "service": "aws",
                "marker_rule": r"^AKIA[A-Z0-9]{16}$",
                "active": True,
                "created_at": "2026-05-05T00:00:00Z",
            },
        ]
        schema_file = tmp_path / "schema.json"
        with open(schema_file, "w") as f:
            json.dump(schema, f)

        # Generate with same seed twice
        values1 = generate_values(schema_file, seed=0xCAFEBABE)
        values2 = generate_values(schema_file, seed=0xCAFEBABE)

        assert values1[0]["value"] == values2[0]["value"]

    def test_different_seed_different_values(self, tmp_path):
        """Test that different seeds produce different values. TC-015-02"""
        schema = [
            {
                "canary_id": "aws-key-000",
                "kind": "credential",
                "service": "aws",
                "marker_rule": r"^AKIA[A-Z0-9]{16}$",
                "active": True,
                "created_at": "2026-05-05T00:00:00Z",
            },
        ]
        schema_file = tmp_path / "schema.json"
        with open(schema_file, "w") as f:
            json.dump(schema, f)

        values1 = generate_values(schema_file, seed=0xCAFEBABE)
        values2 = generate_values(schema_file, seed=0xFEEDBEEF)

        assert values1[0]["value"] != values2[0]["value"]

    def test_skip_inactive_canaries(self, tmp_path):
        """Test that inactive canaries are skipped."""
        schema = [
            {
                "canary_id": "aws-key-000",
                "kind": "credential",
                "service": "aws",
                "marker_rule": r"^AKIA[A-Z0-9]{16}$",
                "active": True,
                "created_at": "2026-05-05T00:00:00Z",
            },
            {
                "canary_id": "aws-key-001",
                "kind": "credential",
                "service": "aws",
                "marker_rule": r"^AKIA[A-Z0-9]{16}$",
                "active": False,
                "created_at": "2026-05-05T00:00:00Z",
            },
        ]
        schema_file = tmp_path / "schema.json"
        with open(schema_file, "w") as f:
            json.dump(schema, f)

        values = generate_values(schema_file)
        assert len(values) == 1
        assert values[0]["canary_id"] == "aws-key-000"

    def test_missing_schema_file(self, tmp_path):
        """Test that missing schema file raises FileNotFoundError."""
        nonexistent = tmp_path / "nonexistent.json"
        with pytest.raises(FileNotFoundError):
            generate_values(nonexistent)

    def test_invalid_schema_format(self, tmp_path):
        """Test that invalid schema format raises ValueError."""
        bad_schema = {"not": "a list"}
        schema_file = tmp_path / "bad_schema.json"
        with open(schema_file, "w") as f:
            json.dump(bad_schema, f)

        with pytest.raises(ValueError, match="Schema must be a JSON array"):
            generate_values(schema_file)

    def test_missing_marker_rule(self, tmp_path):
        """Test that missing marker_rule raises ValueError."""
        schema = [
            {
                "canary_id": "aws-key-000",
                "kind": "credential",
                "service": "aws",
                "active": True,
            },
        ]
        schema_file = tmp_path / "schema.json"
        with open(schema_file, "w") as f:
            json.dump(schema, f)

        with pytest.raises(ValueError, match="missing canary_id or marker_rule"):
            generate_values(schema_file)


class TestWriteValuesFile:
    """Tests for write_values_file function."""

    def test_write_values_file_permissions(self, tmp_path):
        """Test that written file has mode 0o600. TC-015-03"""
        schema = [
            {
                "canary_id": "aws-key-000",
                "kind": "credential",
                "service": "aws",
                "marker_rule": r"^AKIA[A-Z0-9]{16}$",
                "active": True,
                "created_at": "2026-05-05T00:00:00Z",
            },
        ]
        schema_file = tmp_path / "schema.json"
        with open(schema_file, "w") as f:
            json.dump(schema, f)

        output_file = tmp_path / "values.json"
        write_values_file(output_file, schema_file, seed=0xCAFEBABE)

        # Check file mode
        file_stat = os.stat(output_file)
        # File mode should be -rw------- (0o600)
        assert stat.S_IMODE(file_stat.st_mode) == 0o600

    def test_write_values_file_content(self, tmp_path):
        """Test that written file contains merged schema + values."""
        schema = [
            {
                "canary_id": "aws-key-000",
                "kind": "credential",
                "service": "aws",
                "marker_rule": r"^AKIA[A-Z0-9]{16}$",
                "active": True,
                "created_at": "2026-05-05T00:00:00Z",
            },
        ]
        schema_file = tmp_path / "schema.json"
        with open(schema_file, "w") as f:
            json.dump(schema, f)

        output_file = tmp_path / "values.json"
        write_values_file(output_file, schema_file, seed=0xCAFEBABE)

        # Load the written file
        with open(output_file) as f:
            content = json.load(f)

        assert len(content) == 1
        assert content[0]["canary_id"] == "aws-key-000"
        assert "value" in content[0]
        assert re.match(r"^AKIA[A-Z0-9]{16}$", content[0]["value"])

    def test_write_values_file_creates_parent_dirs(self, tmp_path):
        """Test that write_values_file creates parent directories."""
        schema = [
            {
                "canary_id": "aws-key-000",
                "kind": "credential",
                "service": "aws",
                "marker_rule": r"^AKIA[A-Z0-9]{16}$",
                "active": True,
                "created_at": "2026-05-05T00:00:00Z",
            },
        ]
        schema_file = tmp_path / "schema.json"
        with open(schema_file, "w") as f:
            json.dump(schema, f)

        output_file = tmp_path / "subdir1" / "subdir2" / "values.json"
        write_values_file(output_file, schema_file)

        assert output_file.exists()


class TestCatalogueLoadWithValues:
    """Tests for loading catalogues with separate schema and values files. TC-015-04"""

    def test_load_schema_and_values(self, tmp_path):
        """Test loading catalogue with separate schema and values files."""
        schema = [
            {
                "canary_id": "aws-key-000",
                "kind": "credential",
                "service": "aws",
                "marker_rule": r"^AKIA[A-Z0-9]{16}$",
                "active": True,
                "created_at": "2026-05-05T00:00:00Z",
            },
        ]
        values = [
            {
                "canary_id": "aws-key-000",
                "value": "AKIAAAAAAAAAAAAA1234",
            },
        ]

        schema_file = tmp_path / "schema.json"
        with open(schema_file, "w") as f:
            json.dump(schema, f)

        values_file = tmp_path / "values.json"
        with open(values_file, "w") as f:
            json.dump(values, f)

        catalogue = Catalogue.load(schema_file, values_file)
        assert len(catalogue.entries) == 1
        assert catalogue.entries[0].canary_id == "aws-key-000"
        assert catalogue.entries[0].value == "AKIAAAAAAAAAAAAA1234"

    def test_load_merged_file_backward_compat(self, tmp_path):
        """Test loading a file with both schema and values (backward compat)."""
        merged = [
            {
                "canary_id": "aws-key-000",
                "kind": "credential",
                "service": "aws",
                "value": "AKIAAAAAAAAAAAAA1234",
                "marker_rule": r"^AKIA[A-Z0-9]{16}$",
                "active": True,
                "created_at": "2026-05-05T00:00:00Z",
            },
        ]

        merged_file = tmp_path / "catalogue.json"
        with open(merged_file, "w") as f:
            json.dump(merged, f)

        catalogue = Catalogue.load(merged_file)
        assert len(catalogue.entries) == 1
        assert catalogue.entries[0].value == "AKIAAAAAAAAAAAAA1234"

    def test_missing_values_file_raises(self, tmp_path):
        """Test that missing values file raises FileNotFoundError. TC-015-06"""
        schema = [
            {
                "canary_id": "aws-key-000",
                "kind": "credential",
                "service": "aws",
                "marker_rule": r"^AKIA[A-Z0-9]{16}$",
                "active": True,
                "created_at": "2026-05-05T00:00:00Z",
            },
        ]

        schema_file = tmp_path / "schema.json"
        with open(schema_file, "w") as f:
            json.dump(schema, f)

        nonexistent_values = tmp_path / "nonexistent.json"

        with pytest.raises(FileNotFoundError):
            Catalogue.load(schema_file, nonexistent_values)

    def test_value_validation_fails_on_mismatch(self, tmp_path):
        """Test that invalid values raise ValueError. TC-015-07"""
        schema = [
            {
                "canary_id": "aws-key-000",
                "kind": "credential",
                "service": "aws",
                "marker_rule": r"^AKIA[A-Z0-9]{16}$",
                "active": True,
                "created_at": "2026-05-05T00:00:00Z",
            },
        ]
        values = [
            {
                "canary_id": "aws-key-000",
                "value": "INVALID",  # Does not match marker_rule
            },
        ]

        schema_file = tmp_path / "schema.json"
        with open(schema_file, "w") as f:
            json.dump(schema, f)

        values_file = tmp_path / "values.json"
        with open(values_file, "w") as f:
            json.dump(values, f)

        with pytest.raises(ValueError, match="value does not match marker_rule"):
            Catalogue.load(schema_file, values_file)

    def test_missing_value_for_active_canary(self, tmp_path):
        """Test that missing values for active canaries raise ValueError."""
        schema = [
            {
                "canary_id": "aws-key-000",
                "kind": "credential",
                "service": "aws",
                "marker_rule": r"^AKIA[A-Z0-9]{16}$",
                "active": True,
                "created_at": "2026-05-05T00:00:00Z",
            },
        ]
        values = []  # No values

        schema_file = tmp_path / "schema.json"
        with open(schema_file, "w") as f:
            json.dump(schema, f)

        values_file = tmp_path / "values.json"
        with open(values_file, "w") as f:
            json.dump(values, f)

        with pytest.raises(ValueError, match="no value provided"):
            Catalogue.load(schema_file, values_file)
