"""Fitness checks for task 048 — Spec drift cluster.

This module encodes spec audit checks as runnable assertions that prevent
drift between the spec files and codebase state.

Spec markers:
    TC-048-01 — No future-tense violations in affected spec files
    TC-048-02 — quarantine.ttl_hours is the canonical key in data-model.md
    TC-048-03 — behaviors.md corpus path for topic_pivot resolves
    TC-048-04 — from armor import DaemonUnreachableError works
    TC-048-05 — make check passes (operator-verified)
"""

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_no_future_tense_violations():
    """TC-048-01: No future-tense violations in affected spec files.

    Check that the four spec files contain no banned phrases like
    'future variants', 'reserved for a future', 'and any future'.
    """
    banned = ["future variants", "reserved for a future", "and any future"]
    spec_files = [
        "configuration.md",
        "data-model.md",
        "behaviors.md",
        "interfaces.md",
    ]

    for fname in spec_files:
        fpath = ROOT / "docs" / "spec" / fname
        text = fpath.read_text()
        for phrase in banned:
            assert phrase not in text, f"{fname}: still contains banned future-tense phrase {phrase!r}"


def test_quarantine_ttl_hours_canonical():
    """TC-048-02: quarantine.ttl_hours is canonical in data-model.md.

    The key name must be 'quarantine.ttl_hours' (matching TOML dotted notation),
    not the underscore variant 'quarantine_ttl_hours'.
    """
    dpath = ROOT / "docs" / "spec" / "data-model.md"
    text = dpath.read_text()
    assert "quarantine.ttl_hours" in text, "data-model.md missing quarantine.ttl_hours"
    assert "quarantine_ttl_hours" not in text, "data-model.md still contains old quarantine_ttl_hours key"


def test_behaviors_corpus_path_resolves():
    """TC-048-03: behaviors.md corpus path for topic_pivot resolves.

    Extract the corpus path referenced in the topic_pivot behavior entry
    and verify it exists on disk.
    """
    bpath = ROOT / "docs" / "spec" / "behaviors.md"
    text = bpath.read_text()

    # Look for the topic_pivot reference and extract the corpus path nearby
    for line in text.splitlines():
        if "topic_pivot" in line:
            # Try to extract tests/eval/corpus/*.yaml path
            m = re.search(r"tests/eval/corpus/[\w_]+\.yaml", line)
            if m:
                corpus_path = m.group(0)
                full_path = ROOT / corpus_path
                assert full_path.exists(), f"behaviors.md references nonexistent corpus path: {corpus_path}"
                return

    # If we get here, we didn't find the pattern. That's an error.
    raise AssertionError("Could not find topic_pivot corpus reference in behaviors.md")


def test_daemon_unreachable_error_exported():
    """TC-048-04: from armor import DaemonUnreachableError works.

    Verify the exception is re-exported from the top-level armor package.
    """
    res = subprocess.run(
        [sys.executable, "-c", "from armor import DaemonUnreachableError"],
        capture_output=True,
        text=True,
        cwd=str(ROOT),
    )
    assert res.returncode == 0, f"DaemonUnreachableError not re-exported from armor: {res.stderr}"
