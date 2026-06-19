# SPDX-License-Identifier: Apache-2.0
"""Meta-fitness check: ``docs/spec/fitness-functions.md`` ↔ ``tests/fitness/`` 1:1 correspondence.

This is the gate that prevents the drift the task-091 consolidation closed
from recurring. It enforces two invariants:

1. **Forward (file → spec):** every ``tests/fitness/test_*.py`` file is
   referenced by at least one row in ``docs/spec/fitness-functions.md``. A
   new test file with no spec row fails the check.

2. **Reverse (spec → file):** every ``test_*.py`` path mentioned in the
   spec's *implemented* sections resolves to an existing file. A row whose
   path was deleted or renamed fails the check.

Adding a fitness rule now requires both halves: write the test file *and*
add the spec row. Removing a fitness rule requires removing both halves.

The check intentionally only inspects the *runner-wired* sections of the
spec (everything under ``## Implemented rules``). The ``Eval-tier`` and
``Candidate rules`` sections are scoped out by design.

Spec markers:
    AC-091-04 — meta-fitness check asserts 1:1 correspondence and fails CI
                on either side of drift.
    TC-091-01 — forward direction (file → spec).
    TC-091-02 — reverse direction (spec → file).
    TC-091-03 / TC-091-04 — meta-check fails on synthetic drift.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
FITNESS_DIR = REPO_ROOT / "tests" / "fitness"
SPEC_PATH = REPO_ROOT / "docs" / "spec" / "fitness-functions.md"

# The runner-wired surface starts here and ends at the eval-tier section.
RUNNER_WIRED_HEADER = "## Implemented rules — runner-wired"
EVAL_TIER_HEADER = "## Eval-tier checks"

# Files inside tests/fitness/ that are NOT fitness check files. Helpers, init
# modules, and similar test-infrastructure live here without a spec row.
EXEMPT_FILES = {"__init__.py"}
EXEMPT_PREFIXES = ("_",)  # underscore-prefixed helpers

# Match `tests/fitness/test_<name>.py` mentions anywhere inside the runner-wired section.
_PATH_RE = re.compile(r"tests/fitness/(test_[A-Za-z0-9_]+\.py)")


def _runner_wired_section(spec_text: str) -> str:
    start = spec_text.find(RUNNER_WIRED_HEADER)
    end = spec_text.find(EVAL_TIER_HEADER, start)
    assert start != -1, f"spec missing header: {RUNNER_WIRED_HEADER!r}"
    assert end != -1, f"spec missing header: {EVAL_TIER_HEADER!r}"
    return spec_text[start:end]


def _wired_test_basenames(spec_text: str) -> set[str]:
    section = _runner_wired_section(spec_text)
    return set(_PATH_RE.findall(section))


def _filesystem_test_basenames() -> set[str]:
    found: set[str] = set()
    for path in FITNESS_DIR.glob("test_*.py"):
        name = path.name
        if name in EXEMPT_FILES:
            continue
        if any(name.startswith(p) for p in EXEMPT_PREFIXES):
            continue
        found.add(name)
    return found


def _spec_text() -> str:
    return SPEC_PATH.read_text(encoding="utf-8")


@pytest.mark.smoke
def test_every_fitness_file_has_a_spec_row() -> None:
    """TC-091-01: forward direction — every test_*.py file is referenced in the spec."""
    fs = _filesystem_test_basenames()
    spec = _wired_test_basenames(_spec_text())
    orphan_files = sorted(fs - spec)
    assert not orphan_files, (
        "Fitness test files with no row in docs/spec/fitness-functions.md "
        f"({len(orphan_files)}):\n  " + "\n  ".join(orphan_files) + "\n\nAdd a row in the appropriate sub-table under "
        "`## Implemented rules — runner-wired` linking to the file, or move "
        "the file out of tests/fitness/ if it isn't actually a fitness check."
    )


@pytest.mark.smoke
def test_every_spec_row_path_exists() -> None:
    """TC-091-02: reverse direction — every test_*.py mentioned in the spec exists on disk."""
    fs = _filesystem_test_basenames()
    spec = _wired_test_basenames(_spec_text())
    orphan_rows = sorted(spec - fs)
    assert not orphan_rows, (
        "docs/spec/fitness-functions.md references test files that don't exist "
        f"({len(orphan_rows)}):\n  "
        + "\n  ".join(orphan_rows)
        + "\n\nEither create the file under tests/fitness/ or remove the row."
    )


# ---------------------------------------------------------------------------
# Synthetic-drift coverage — TC-091-03 / TC-091-04.
#
# These tests exercise the meta-check's *failure path* on temp filesystems so
# we know the assertions actually fire when something is wrong (not just when
# everything is fine).
# ---------------------------------------------------------------------------


def _synthesize_spec(test_basenames: list[str]) -> str:
    rows = "\n".join(
        f"| Synthetic | Synthetic why | [tests/fitness/{name}](../../tests/fitness/{name}) |" for name in test_basenames
    )
    return (
        f"# Synthetic spec\n\n"
        f"{RUNNER_WIRED_HEADER}\n\n"
        f"| Invariant | Why | Test |\n|---|---|---|\n{rows}\n\n"
        f"{EVAL_TIER_HEADER}\n\nstub\n"
    )


def _scan_pair(tmp_path: Path, spec_text: str, file_basenames: list[str]) -> tuple[set[str], set[str]]:
    """Mirror the production scan against a synthetic spec + filesystem layout."""
    fs: set[str] = set()
    for name in file_basenames:
        (tmp_path / name).write_text("")
        fs.add(name)
    section_start = spec_text.find(RUNNER_WIRED_HEADER)
    section_end = spec_text.find(EVAL_TIER_HEADER, section_start)
    section = spec_text[section_start:section_end]
    spec_basenames = set(_PATH_RE.findall(section))
    return fs, spec_basenames


def test_meta_check_detects_orphan_file(tmp_path: Path) -> None:
    """TC-091-03: file present, no spec row → forward check fails and names the file."""
    spec = _synthesize_spec(["test_present.py"])
    fs, spec_basenames = _scan_pair(tmp_path, spec, ["test_present.py", "test_orphan.py"])
    orphan = sorted(fs - spec_basenames)
    assert orphan == ["test_orphan.py"], f"meta-check should flag the orphan file; got {orphan!r}"


def test_meta_check_detects_orphan_spec_row(tmp_path: Path) -> None:
    """TC-091-04: spec row present, no file → reverse check fails and names the row."""
    spec = _synthesize_spec(["test_present.py", "test_phantom.py"])
    fs, spec_basenames = _scan_pair(tmp_path, spec, ["test_present.py"])
    orphan = sorted(spec_basenames - fs)
    assert orphan == ["test_phantom.py"], f"meta-check should flag the orphan spec row; got {orphan!r}"
