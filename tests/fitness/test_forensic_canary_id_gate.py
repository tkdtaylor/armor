# SPDX-License-Identifier: Apache-2.0
"""Fitness check: forensic logger never writes canary values.

Per ADR-021, the forensic log must store only canary IDs, never the
plaintext canary values. This check scans forensic.py and the daemon
code paths to verify that triggered_canary is only assigned canary_id
values, not canary.value.

Spec markers:
    TC-127-03 — forensic logger never stores canary values.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
FORENSIC_PATH = REPO_ROOT / "src" / "armor" / "db" / "forensic.py"
DAEMON_DIR = REPO_ROOT / "src" / "armor" / "daemon"

# Pattern to detect triggered_canary assignment
TRIGGERED_CANARY_ASSIGNMENT = re.compile(r"triggered_canary\s*=\s*(.+?)(?:\n|$)", re.MULTILINE)

# Pattern to detect .value attribute access (suspect)
VALUE_ATTR_ACCESS = re.compile(r"\.value\b")


@pytest.mark.smoke
def test_forensic_triggered_canary_never_stores_value() -> None:
    """TC-127-03: Static analysis rejects canary.value in forensic assignments.

    Spec marker: TC-127-03
    """
    violations: list[str] = []

    # Check forensic.py
    if FORENSIC_PATH.is_file():
        content = FORENSIC_PATH.read_text(encoding="utf-8")

        # Find all triggered_canary assignments
        for match in TRIGGERED_CANARY_ASSIGNMENT.finditer(content):
            assignment_rhs = match.group(1).strip()

            # Flag assignments that use .value
            if ".value" in assignment_rhs:
                line_num = content[: match.start()].count("\n") + 1
                violations.append(f"{FORENSIC_PATH.name}:{line_num}: triggered_canary = {assignment_rhs}")

            # Also flag suspicious patterns like accessing .value on a canary object
            if "canary.value" in assignment_rhs or "entry.value" in assignment_rhs:
                line_num = content[: match.start()].count("\n") + 1
                violations.append(
                    f"{FORENSIC_PATH.name}:{line_num}: triggered_canary assignment uses .value: {assignment_rhs}"
                )

    # Check daemon directory for any triggered_canary writes
    if DAEMON_DIR.is_dir():
        for daemon_file in sorted(DAEMON_DIR.glob("*.py")):
            if daemon_file.name == "__pycache__":
                continue

            try:
                content = daemon_file.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue

            # Find triggered_canary references (should be rare in daemon code)
            for match in TRIGGERED_CANARY_ASSIGNMENT.finditer(content):
                assignment_rhs = match.group(1).strip()

                # Flag any .value usage in daemon triggered_canary writes
                if ".value" in assignment_rhs:
                    line_num = content[: match.start()].count("\n") + 1
                    violations.append(f"{daemon_file.name}:{line_num}: triggered_canary uses .value: {assignment_rhs}")

    assert not violations, "Forensic logger writes canary values (not IDs):\n  " + "\n  ".join(violations)
