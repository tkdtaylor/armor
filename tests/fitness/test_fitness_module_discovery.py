# SPDX-License-Identifier: Apache-2.0
"""Fitness module discovery checks (tasks 040 + 041).

Pins the renames of `tests/fitness/public_release.py` (task 040) and
`tests/fitness/structured_logs.py` (task 041), and asserts the broader
invariant that no file under `tests/` contains pytest test definitions
in a name pytest's default `test_*.py` glob would skip.

Spec markers:
    TC-040-01 — public_release.py renamed (file exists at new path)
    TC-040-02 — Importer in test_security_md_matchers.py points at new filename
    TC-041-01 — structured_logs.py renamed (file exists at new path)
    TC-041-02 — No pytest tests in misnamed modules anywhere under tests/
    TC-041-03 — Renamed structured_logs module is collected by default discovery
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

# 040 — public_release.py rename pins
PUBLIC_RELEASE_NEW = REPO_ROOT / "tests" / "fitness" / "test_public_release.py"
PUBLIC_RELEASE_OLD = REPO_ROOT / "tests" / "fitness" / "public_release.py"
IMPORTER_PATH = REPO_ROOT / "tests" / "unit" / "test_security_md_matchers.py"

# 041 — structured_logs.py rename pins
STRUCTURED_LOGS_NEW = REPO_ROOT / "tests" / "fitness" / "test_structured_logs.py"
STRUCTURED_LOGS_OLD = REPO_ROOT / "tests" / "fitness" / "structured_logs.py"

# 041 — generalised scan
PYTEST_FN_RE = re.compile(r"^def test_\w+\s*\(", re.MULTILINE)
PYTEST_CLS_RE = re.compile(r"^class Test\w+\b", re.MULTILINE)


def _is_discovered_by_default(name: str) -> bool:
    """True if pytest's default collection glob would include a file by basename.

    Pytest defaults: ``python_files = test_*.py *_test.py``. ``conftest.py`` and
    ``__init__.py`` are special files pytest handles separately, not test
    modules in the discovery sense.
    """
    return name.startswith("test_") or name.endswith("_test.py") or name in ("conftest.py", "__init__.py")


def test_public_release_renamed_file_exists_and_old_filename_is_gone() -> None:
    """TC-040-01: public_release.py rename pin — new path present, old absent."""
    assert PUBLIC_RELEASE_NEW.is_file(), f"missing renamed fitness module at {PUBLIC_RELEASE_NEW}"
    assert not PUBLIC_RELEASE_OLD.exists(), f"old fitness module still present at {PUBLIC_RELEASE_OLD}"


def test_security_md_matcher_importer_points_at_renamed_file() -> None:
    """TC-040-02: tests/unit/test_security_md_matchers.py loads the matcher
    from the renamed public_release file (not the pre-rename path)."""
    text = IMPORTER_PATH.read_text(encoding="utf-8")
    assert "test_public_release.py" in text, f"{IMPORTER_PATH} does not reference the renamed fitness module"
    assert '/ "fitness" / "public_release.py"' not in text, f"{IMPORTER_PATH} still has the pre-rename path expression"


def test_structured_logs_renamed_file_exists_and_old_filename_is_gone() -> None:
    """TC-041-01: structured_logs.py rename pin — new path present, old absent."""
    assert STRUCTURED_LOGS_NEW.is_file(), f"missing renamed fitness module at {STRUCTURED_LOGS_NEW}"
    assert not STRUCTURED_LOGS_OLD.exists(), f"old fitness module still present at {STRUCTURED_LOGS_OLD}"


def test_no_pytest_tests_in_misnamed_modules() -> None:
    """TC-041-02: scan tests/ for any *.py file that contains pytest test
    definitions (``def test_...`` or ``class Test...``) but has a basename
    pytest's default glob would skip. Such files are silently uncollected and
    represent the bug class fixed by 040 and 041.
    """
    misnamed: list[str] = []
    for path in (REPO_ROOT / "tests").rglob("*.py"):
        if _is_discovered_by_default(path.name):
            continue
        text = path.read_text(encoding="utf-8")
        if PYTEST_FN_RE.search(text) or PYTEST_CLS_RE.search(text):
            misnamed.append(str(path.relative_to(REPO_ROOT)))
    assert not misnamed, (
        "files contain pytest tests but pytest's default glob would skip them "
        "(rename to test_<name>.py or remove the test definitions):\n  " + "\n  ".join(misnamed)
    )


def test_pytest_default_collection_picks_up_structured_logs() -> None:
    """TC-041-03: `pytest --collect-only tests/fitness/` includes
    test_structured_logs.py under default discovery."""
    result = subprocess.run(
        ["uv", "run", "pytest", "--collect-only", "-q", "tests/fitness/"],
        cwd=REPO_ROOT,
        capture_output=True,
        check=False,
    )
    assert b"tests/fitness/test_structured_logs.py::" in result.stdout, (
        "renamed structured_logs module not discovered by default pytest glob:\n" + result.stdout.decode()
    )
