# SPDX-License-Identifier: Apache-2.0
"""Fitness check: ensure canary kinds in catalogue match ADR-031 §3 recipe table.

This function asserts that:
1. Every kind listed in ADR-031 §3's recipe table appears in the default catalogue
2. Every kind in the catalogue has a corresponding recipe in ADR-031 §3
3. No unexpected kinds appear in the catalogue

Reference: ADR-031 §3 recipe table (lines 66-91)
           ADR-032 Q5 — catalogue/recipe-table sync fitness function
"""

import json
from pathlib import Path


def test_catalogue_kinds_match_recipe_table():
    """Verify every catalogue kind maps to an ADR-031 recipe."""

    # Load the default catalogue schema
    catalogue_path = Path(__file__).parent.parent.parent / "src" / "armor" / "canaries" / "default_catalogue.json"
    with open(catalogue_path, encoding="utf-8") as f:
        catalogue = json.load(f)

    # Extract unique kinds from the catalogue
    catalogue_kinds = set()
    for entry in catalogue:
        if entry.get("active", True):
            kind = entry.get("kind")
            if kind:
                catalogue_kinds.add(kind)

    # ADR-031 §3 recipe table kinds (the source of truth)
    # These are the kinds that appear in the recipe table
    recipe_table_kinds = {
        "credential",  # aws-key-*, github-pat-*, stripe-key-*, etc.
        "url",  # generic URLs, slack webhooks, discord webhooks
        "path",  # file paths
        "hostname",  # DNS hostnames
        "wallet",  # crypto wallets (bitcoin, ethereum, solana, bip39, metamask)
        "email",  # email addresses
        "jwt",  # JWT tokens
        "ssh-key",  # SSH private keys
        "cert",  # TLS certificates
        "kube-config",  # Kubernetes config tokens
        "db-connection",  # Database connection strings
        "pii",  # fake PII identity records (name, email, DOB, SIN) seeded via armor canary pii-context
    }

    # All catalogue kinds must appear in the recipe table
    unexpected_kinds = catalogue_kinds - recipe_table_kinds
    assert not unexpected_kinds, f"Catalogue contains kinds not in ADR-031 recipe table: {unexpected_kinds}"

    # All recipe table kinds should appear in the catalogue
    missing_kinds = recipe_table_kinds - catalogue_kinds
    assert not missing_kinds, f"ADR-031 recipe table kinds missing from catalogue: {missing_kinds}"

    # Both sets should be equal
    assert catalogue_kinds == recipe_table_kinds


def test_canary_kinds_have_active_entries():
    """Verify each kind has at least 3 active entries (5 for LLM providers)."""

    # Load the default catalogue schema
    catalogue_path = Path(__file__).parent.parent.parent / "src" / "armor" / "canaries" / "default_catalogue.json"
    with open(catalogue_path, encoding="utf-8") as f:
        catalogue = json.load(f)

    # Group by kind
    by_kind = {}
    for entry in catalogue:
        kind = entry.get("kind")
        if kind:
            if kind not in by_kind:
                by_kind[kind] = []
            by_kind[kind].append(entry)

    # Check minimum counts per kind
    llm_provider_services = {"openai", "anthropic", "cohere", "huggingface"}
    for kind, entries in by_kind.items():
        active_entries = [e for e in entries if e.get("active", True)]
        # LLM-provider kinds need 5 entries each
        has_llm_provider = any(e.get("service") in llm_provider_services for e in active_entries)
        if has_llm_provider:
            assert len(active_entries) >= 5, (
                f"Kind '{kind}' with LLM provider must have ≥5 active entries; got {len(active_entries)}"
            )
        else:
            assert len(active_entries) >= 3, f"Kind '{kind}' must have ≥3 active entries; got {len(active_entries)}"


def test_false_positive_risk_field_on_llm_providers():
    """Verify LLM-provider kinds carry false_positive_risk=high."""

    # Load the default catalogue schema
    catalogue_path = Path(__file__).parent.parent.parent / "src" / "armor" / "canaries" / "default_catalogue.json"
    with open(catalogue_path, encoding="utf-8") as f:
        catalogue = json.load(f)

    llm_provider_services = {"openai", "anthropic", "cohere", "huggingface"}

    for entry in catalogue:
        service = entry.get("service")
        if service in llm_provider_services:
            assert "false_positive_risk" in entry, (
                f"LLM-provider entry {entry['canary_id']} missing false_positive_risk field"
            )
            assert entry["false_positive_risk"] == "high", (
                f"LLM-provider entry {entry['canary_id']} has false_positive_risk={entry['false_positive_risk']}, expected 'high'"
            )
