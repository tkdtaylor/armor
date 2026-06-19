# SPDX-License-Identifier: Apache-2.0
"""Fitness check: ``CHANGELOG.md`` is updated when user-visible source changes.

When a PR touches user-facing surfaces (CLI, SDK, daemon, public types, examples,
docs/spec, docs/architecture, ...), it must add an entry under ``[Unreleased]``.
The check is skip-friendly so docs-only or formatting PRs can opt out:

- ``SKIP_CHANGELOG=1`` env var → unconditional skip
- PR labelled ``skip-changelog`` (via ``PR_LABELS`` env var) → unconditional skip
- No git diff against the base ref reachable → skip (e.g. shallow clone)
- No user-visible files changed → skip

Spec markers:
    AC-029-* — CHANGELOG fitness rules under task 029.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]

USER_VISIBLE_FILES = {
    "src/armor/cli.py",
    "src/armor/sdk.py",
    "src/armor/types.py",
    "src/armor/__init__.py",
    "src/armor/client.py",
    "README.md",
    "pyproject.toml",
    "docker/Dockerfile",
}

USER_VISIBLE_PREFIXES = (
    "src/armor/detectors/",
    "src/armor/daemon/",
    "docs/spec/",
    "docs/architecture/",
    "examples/",
)


def _is_user_visible(filepath: str) -> bool:
    if filepath in USER_VISIBLE_FILES:
        return True
    return any(filepath.startswith(prefix) for prefix in USER_VISIBLE_PREFIXES)


def _pr_labels() -> set[str]:
    labels_env = os.environ.get("PR_LABELS", "")
    if labels_env:
        return {label.strip() for label in labels_env.split(",") if label.strip()}
    return set()


def _changed_files(base_ref: str = "origin/main") -> set[str] | None:
    """Return the set of changed paths vs. the base ref, or ``None`` if undeterminable."""
    try:
        result = subprocess.run(
            ["git", "diff", "--name-only", "--diff-filter=ACMRT", f"{base_ref}...HEAD"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None
    return {line for line in result.stdout.strip().splitlines() if line}


@pytest.mark.smoke
def test_changelog_updated_when_user_visible_source_changes() -> None:
    """Skip when no PR context is available; otherwise enforce CHANGELOG updates."""
    if os.environ.get("SKIP_CHANGELOG") == "1":
        pytest.skip("SKIP_CHANGELOG=1: skipping CHANGELOG check")

    if "skip-changelog" in _pr_labels():
        pytest.skip("PR labelled skip-changelog")

    base_ref = os.environ.get("CHANGELOG_BASE_REF", "origin/main")
    changed = _changed_files(base_ref)
    if changed is None:
        pytest.skip(f"git diff vs {base_ref} unavailable (no PR context)")

    if not changed:
        pytest.skip("no changed files detected")

    user_visible = sorted(f for f in changed if _is_user_visible(f))
    if not user_visible:
        pytest.skip(f"no user-visible changes; changed: {sorted(changed)}")

    assert "CHANGELOG.md" in changed, (
        "CHANGELOG.md not updated, but user-visible sources changed:\n  "
        + "\n  ".join(user_visible)
        + "\n\nAdd an entry under [Unreleased] in CHANGELOG.md, or set the "
        "skip-changelog label / SKIP_CHANGELOG=1 for docs-only PRs."
    )
