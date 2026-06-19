"""Project email rebrand fitness checks (task 039).

Asserts that all shipped contact-info files and the canonical-email
references inside the task 038 planning docs cite the post-rebrand
address (`tools@taylorguard.me` for general/security/CoC/enterprise contact)
and contain no occurrences of the pre-rebrand addresses (the maintainer's
former personal-mailbox address and the former personal-domain
licensing alias; both held internally as `<REDACTED-OLD-GENERAL>` and
`<REDACTED-OLD-LICENSING>` placeholders).

Spec markers:
    TC-039-01 — SECURITY.md uses tools@taylorguard.me
    TC-039-02 — pyproject.toml authors email is tools@taylorguard.me
    TC-039-03 — CODE_OF_CONDUCT.md enforcement contact is tools@taylorguard.me
    TC-039-05 — No regressions in shipped contact files
    TC-039-06 — Task 038 planning docs reference the new canonical email
    TC-039-07 — No new occurrences of the old emails outside excluded paths
    TC-039-08 — ADR not required (no test, documented in spec)
"""

from __future__ import annotations

import subprocess
import tomllib
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]

OLD_GENERAL = "<REDACTED-OLD-GENERAL>"
OLD_LICENSING = "<REDACTED-OLD-LICENSING>"
NEW_GENERAL = "tools@taylorguard.me"


def test_security_md_uses_new_general_email() -> None:
    """TC-039-01: SECURITY.md cites tools@taylorguard.me, not the old address."""
    text = (REPO_ROOT / "SECURITY.md").read_text(encoding="utf-8")
    assert NEW_GENERAL in text, f"SECURITY.md missing {NEW_GENERAL!r}"
    assert OLD_GENERAL not in text, f"SECURITY.md still references {OLD_GENERAL!r}"


def test_pyproject_authors_email_is_new_general() -> None:
    """TC-039-02: pyproject.toml [project].authors[0].email == tools@taylorguard.me."""
    path = REPO_ROOT / "pyproject.toml"
    text = path.read_text(encoding="utf-8")
    data = tomllib.loads(text)
    authors = data["project"]["authors"]
    assert len(authors) >= 1, "pyproject.toml [project].authors is empty"
    assert authors[0]["email"] == NEW_GENERAL, f"authors[0].email is {authors[0]['email']!r}, expected {NEW_GENERAL!r}"
    assert OLD_GENERAL not in text, f"pyproject.toml still references {OLD_GENERAL!r}"


def test_code_of_conduct_uses_new_general_email() -> None:
    """TC-039-03: CODE_OF_CONDUCT.md enforcement contact is tools@taylorguard.me."""
    text = (REPO_ROOT / "CODE_OF_CONDUCT.md").read_text(encoding="utf-8")
    assert NEW_GENERAL in text, f"CODE_OF_CONDUCT.md missing {NEW_GENERAL!r}"
    assert OLD_GENERAL not in text, f"CODE_OF_CONDUCT.md still references {OLD_GENERAL!r}"


def test_no_old_emails_in_shipped_contact_files() -> None:
    """TC-039-05: zero matches for either old email in the shipped contact set."""
    paths = [
        "SECURITY.md",
        "pyproject.toml",
        "CODE_OF_CONDUCT.md",
        "README.md",
        ".github",
        "CONTRIBUTING.md",
        "CHANGELOG.md",
    ]
    pattern = rf"({OLD_GENERAL.replace('.', chr(92) + '.')}|{OLD_LICENSING.replace('.', chr(92) + '.')})"
    result = subprocess.run(
        ["git", "grep", "-nE", pattern, "--", *paths],
        cwd=REPO_ROOT,
        capture_output=True,
        check=False,
    )
    assert result.stdout == b"", f"unexpected matches in shipped files:\n{result.stdout.decode()}"


def test_task_038_planning_docs_use_new_canonical_email() -> None:
    """TC-039-06: task 038's task file and test spec cite tools@taylorguard.me.

    Task 038 may live in any of backlog/active/completed at the time this test
    runs; the test follows whichever copy exists. If none exist (post-038
    cleanup), the test SKIPS.
    """
    task_candidates = [
        REPO_ROOT / "docs/tasks/backlog/038-public-release-history-rewrite.md",
        REPO_ROOT / "docs/tasks/active/038-public-release-history-rewrite.md",
        REPO_ROOT / "docs/tasks/completed/038-public-release-history-rewrite.md",
    ]
    spec_candidates = [
        REPO_ROOT / "docs/tasks/test-specs/038-public-release-history-rewrite-test-spec.md",
    ]
    found = [p for p in (*task_candidates, *spec_candidates) if p.exists()]
    if not found:
        pytest.skip("task 038 files no longer present")
    for path in found:
        text = path.read_text(encoding="utf-8")
        assert NEW_GENERAL in text, f"{path} missing {NEW_GENERAL!r}"
        assert OLD_GENERAL not in text, f"{path} still references {OLD_GENERAL!r}"


def test_no_old_emails_outside_excluded_paths() -> None:
    """TC-039-07: zero matches for either old email outside historical / fixture paths.

    Exclusions:
      - docs/tasks/completed/ — historical task descriptions, accurate to their time.
      - tests/eval/, tests/unit/ — red-team fixtures; never contained the real
        addresses but excluded as defence in depth.
      - docs/tasks/test-specs/005-, /006-, /011- — destination-extractor fixture refs.
      - docs/tasks/{backlog,active,completed}/039-*, docs/tasks/test-specs/039-* —
        this task's own task file and spec describe the from-to mapping and
        legitimately mention both addresses.
      - docs/tasks/{backlog,active,completed}/044-*, docs/tasks/test-specs/044-* —
        task 044 (tree redaction) planning documents legitimately reference the
        old addresses as context for the work.
      - tests/fitness/test_email_rebrand.py — this file holds the old addresses
        as comparison constants.
    """
    pattern = rf"({OLD_GENERAL.replace('.', chr(92) + '.')}|{OLD_LICENSING.replace('.', chr(92) + '.')})"
    result = subprocess.run(
        [
            "git",
            "grep",
            "-nE",
            pattern,
            "--",
            ".",
            ":!docs/tasks/completed",
            ":!tests/eval",
            ":!tests/unit",
            ":!docs/tasks/test-specs/005-*",
            ":!docs/tasks/test-specs/006-*",
            ":!docs/tasks/test-specs/011-*",
            ":!docs/tasks/backlog/039-*",
            ":!docs/tasks/active/039-*",
            ":!docs/tasks/completed/039-*",
            ":!docs/tasks/test-specs/039-*",
            ":!docs/tasks/backlog/044-*",
            ":!docs/tasks/active/044-*",
            ":!docs/tasks/completed/044-*",
            ":!docs/tasks/test-specs/044-*",
            ":!tests/fitness/test_email_rebrand.py",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        check=False,
    )
    assert result.stdout == b"", f"unexpected matches outside excluded paths:\n{result.stdout.decode()}"
