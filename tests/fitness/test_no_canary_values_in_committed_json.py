"""Fitness check: no ``"value":`` field in committed canary JSON files.

Per ADR-010, the canary catalogue ships as a *schema* — entries describe what
shape a canary takes, but the actual ``value`` field is generated at install
time and never committed. Committing a value would make every clone of the
repo carry the same canary, defeating the trap.

Spec markers:
    AC-010-01 — committed catalogue carries no ``value`` field.
    TC-091-05 — replaces the inline ``git ls-files | xargs grep`` check that
                used to live in ``scripts/fitness.sh``.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
CANARY_GLOB = "src/armor/canaries/*.json"


@pytest.mark.smoke
def test_no_value_field_in_committed_canary_json() -> None:
    """No file under ``src/armor/canaries/*.json`` may contain a ``"value":`` key."""
    listing = subprocess.run(
        ["git", "ls-files", CANARY_GLOB],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    files = [REPO_ROOT / line for line in listing.stdout.strip().splitlines() if line]
    if not files:
        pytest.skip(f"no committed files match {CANARY_GLOB}")

    offenders: list[str] = []
    for path in files:
        text = path.read_text(encoding="utf-8")
        if '"value":' in text:
            offenders.append(str(path.relative_to(REPO_ROOT)))

    assert not offenders, (
        "Canary 'value' field found in committed catalogue files (must be generated, "
        "never committed — see ADR-010):\n  " + "\n  ".join(offenders)
    )
