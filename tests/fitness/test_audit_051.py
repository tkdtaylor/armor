"""Fitness tests for task 051: README and CLAUDE.md doc fixes."""

import re
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent.parent


def test_tc_051_01_readme_uses_socket_not_socket_path():
    """TC-051-01: README quick-start uses `--socket`, not `--socket-path`."""
    text = (REPO_ROOT / "README.md").read_text()
    assert "--socket-path" not in text, "README still uses --socket-path"


def test_tc_051_02_readme_canary_location_corrected():
    """TC-051-02: README canary-location wording matches ADR-010."""
    text = (REPO_ROOT / "README.md").read_text()
    text_lower = text.lower()

    # The old broken wording must be gone
    banned = "canary values live only in"
    assert banned not in text_lower, "README still inverts the canary storage invariant"

    # The corrected wording must reference the runtime path or ADR
    assert "daemon.canary_values_path" in text or "ADR-010" in text or "adr-010" in text, (
        "README does not reference daemon.canary_values_path or ADR-010"
    )


def test_tc_051_03_readme_no_unguarded_ghcr_image():
    """TC-051-03: README does not promise the unpublished GHCR image without a guard."""
    text = (REPO_ROOT / "README.md").read_text()
    lines = text.splitlines()
    guard_phrases = ("coming with", "v0.3", "not yet published")

    violations = []
    for i, line in enumerate(lines):
        if "ghcr.io/tkdtaylor/armor" in line:
            ctx = "\n".join(lines[max(0, i - 3) : i + 4]).lower()
            if not any(p in ctx for p in guard_phrases):
                violations.append(f"README.md:{i + 1}: unguarded GHCR image reference")

    assert violations == [], violations


def test_tc_051_05_claudemd_smoke_test_includes_socket():
    """TC-051-05: CLAUDE.md smoke-test example passes `--socket`."""
    text = (REPO_ROOT / "CLAUDE.md").read_text()

    # Find the armor check input line in the Commands section
    m = re.search(r"armor check input[^\n]*", text)
    assert m is not None, "CLAUDE.md missing 'armor check input' example"
    assert "--socket" in m.group(0), f"CLAUDE.md smoke-test missing --socket: {m.group(0)}"


def test_tc_051_04_claudemd_project_tree_matches_repo():
    """TC-051-04: CLAUDE.md project tree includes all major top-level entries."""
    text = (REPO_ROOT / "CLAUDE.md").read_text()

    # Extract the tree block (between the ``` markers in the Project structure section)
    tree_start = text.find("## Project structure")
    assert tree_start != -1, "Project structure section not found"

    tree_block_start = text.find("```", tree_start)
    tree_block_end = text.find("```", tree_block_start + 3)
    tree_text = text[tree_block_start : tree_block_end + 3]

    # Check for required top-level entries
    required_entries = [
        "src/",
        "artifacts/",
        "tests/",
        "docs/",
        "archive/",
        "docker/",
        "examples/",
        "scripts/",
        "armor.toml",
        "CLAUDE.md",
        "ruff.toml",
        "requirements.txt",
        "discussion.md",
    ]

    for entry in required_entries:
        assert entry in tree_text, f"Project structure tree missing '{entry}'"
