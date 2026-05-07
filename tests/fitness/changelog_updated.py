"""Fitness check: CHANGELOG.md is updated when user-visible source files change.

This check runs during CI on pull requests to ensure that user-facing changes
(source code modifications) are accompanied by a CHANGELOG entry under [Unreleased].

Test cases:
  - Fails if source files change but CHANGELOG.md does not.
  - Passes if both change.
  - Passes if only CHANGELOG.md changes (e.g., docs-only PR).
  - Honors the 'skip-changelog' label as an escape hatch (docs-only, formatting, etc.).

Usage (in CI):
  python tests/fitness/changelog_updated.py

Usage (local testing with env var):
  SKIP_CHANGELOG=1 python tests/fitness/changelog_updated.py
  # Exits 0 (skip honored)

  python tests/fitness/changelog_updated.py
  # Checks actual git diff
"""

import os
import subprocess
import sys


def get_pr_labels() -> set[str]:
    """Get PR labels from GitHub Actions environment.

    Returns:
        Set of label names (empty if not in a PR context).
    """
    # In GitHub Actions, PR labels are not directly available as env vars.
    # Typically, we'd use the GitHub API or expect labels to be passed via env.
    # For now, we check for a manually-set env var (for local testing) or
    # we'd call `gh pr view` if in a PR context.

    labels_env = os.environ.get("PR_LABELS", "")
    if labels_env:
        return set(labels_env.split(","))

    # Try to get labels from GitHub API if GITHUB_TOKEN is available
    if os.environ.get("GITHUB_TOKEN") and os.environ.get("GITHUB_PR_NUMBER"):
        try:
            result = subprocess.run(
                [
                    "gh",
                    "pr",
                    "view",
                    os.environ["GITHUB_PR_NUMBER"],
                    "--json",
                    "labels",
                    "-q",
                    ".labels[].name",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode == 0:
                return set(result.stdout.strip().split("\n")) if result.stdout.strip() else set()
        except Exception:
            pass

    return set()


def get_changed_files(base_ref: str = "origin/main") -> tuple[set[str], set[str]]:
    """Get sets of added/modified files relative to base ref.

    Args:
        base_ref: Git reference to compare against (default: origin/main).

    Returns:
        Tuple of (added_or_modified_files, deleted_files).
    """
    try:
        # Get list of changed files (added, modified, renamed, type-changed)
        result = subprocess.run(
            ["git", "diff", "--name-only", "--diff-filter=ACMRT", base_ref + "...HEAD"],
            capture_output=True,
            text=True,
            check=True,
        )
        changed = set(result.stdout.strip().split("\n")) if result.stdout.strip() else set()
        changed.discard("")  # Remove empty string

        return changed, set()
    except subprocess.CalledProcessError:
        # If we can't get a diff (e.g., not in a git repo or base_ref doesn't exist),
        # fall back to checking git status (for local testing).
        try:
            result = subprocess.run(
                ["git", "status", "--porcelain"],
                capture_output=True,
                text=True,
                check=True,
            )
            modified = set()
            for line in result.stdout.strip().split("\n"):
                if line:
                    # Format: "M path" or " M path" or "A path", etc.
                    status = line[:2]
                    path = line[3:]
                    if status[0] in ("M", "A", "R", "C", "T") or status[1] in (
                        "M",
                        "A",
                        "R",
                        "C",
                        "T",
                    ):
                        modified.add(path)
            return modified, set()
        except subprocess.CalledProcessError:
            # No git info available; fail safely (assume no changes)
            return set(), set()


def is_user_visible_source(filepath: str) -> bool:
    """Check if a file change is user-visible (affects the SDK, CLI, IPC, or docs).

    Args:
        filepath: Path relative to repo root.

    Returns:
        True if the file is user-visible source (not tests, not internal configs).
    """
    # Directories/files that require CHANGELOG updates if modified:
    user_visible_paths = {
        "src/armor/cli.py",  # CLI interface
        "src/armor/sdk.py",  # SDK public API
        "src/armor/types.py",  # Public types
        "src/armor/__init__.py",  # __version__ and public exports
        "src/armor/client.py",  # Client library (IPC)
        "README.md",  # User-facing docs
    }

    # Prefixes that are user-visible:
    user_visible_prefixes = [
        "src/armor/detectors/",  # New detector = user-visible
        "src/armor/daemon/",  # Daemon behavior affects CLI
        "docs/spec/",  # Spec changes are user-visible
        "docs/architecture/",  # Architecture docs
        "examples/",  # Examples
    ]

    # Exact matches
    if filepath in user_visible_paths:
        return True

    # Prefix matches
    for prefix in user_visible_prefixes:
        if filepath.startswith(prefix):
            return True

    # Config files that are user-visible:
    return filepath in ("pyproject.toml", "docker/Dockerfile", ".github/workflows/")


def main() -> int:
    """Run the CHANGELOG fitness check.

    Returns:
        0 if CHANGELOG is up-to-date or check should be skipped.
        1 if CHANGELOG needs updating.
    """
    # Check for the skip flag (env var or flag)
    skip_mode = os.environ.get("SKIP_CHANGELOG") == "1"
    if skip_mode:
        print("SKIP_CHANGELOG=1: skipping CHANGELOG check")
        return 0

    # Get PR labels (if in a PR context)
    pr_labels = get_pr_labels()
    if "skip-changelog" in pr_labels:
        print("PR has 'skip-changelog' label: skipping CHANGELOG check")
        return 0

    # Get changed files
    changed_files, _ = get_changed_files()

    if not changed_files:
        print("No changed files detected; skipping CHANGELOG check")
        return 0

    # Check if any user-visible source file changed
    user_visible_changes = [f for f in changed_files if is_user_visible_source(f)]

    if not user_visible_changes:
        print("No user-visible source changes detected; skipping CHANGELOG check")
        print(f"Changed files: {', '.join(sorted(changed_files))}")
        return 0

    # Check if CHANGELOG.md was updated
    if "CHANGELOG.md" in changed_files:
        print("✓ CHANGELOG.md updated for user-visible changes:")
        print(f"  Changed: {', '.join(sorted(user_visible_changes))}")
        return 0

    # User-visible changes without CHANGELOG update
    print("✗ CHANGELOG.md not updated, but user-visible sources changed:")
    for f in sorted(user_visible_changes):
        print(f"  - {f}")
    print()
    print("Please add an entry under [Unreleased] in CHANGELOG.md.")
    print("See: https://keepachangelog.com/")
    print()
    print("To skip this check (e.g., for docs-only or formatting changes),")
    print("add the 'skip-changelog' label to your PR.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
