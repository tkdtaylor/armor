"""Fitness checks for the make release-check target + RELEASE_CHECKLIST.md (task 054).

Spec markers:
    TC-054-01 — release-check target exists in Makefile and is in .PHONY
    TC-054-02 — make help lists release-check
    TC-054-03 — recipe references check, fitness, demo, and --offline-smoke
    TC-054-04 — Docker stage is gated on $(DOCKER) / ifdef DOCKER
    TC-054-05 — RELEASE_CHECKLIST.md exists with all five required sections
    TC-054-06 — CONTRIBUTING.md (or CLAUDE.md) references make release-check
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
MAKEFILE = REPO_ROOT / "Makefile"


@pytest.fixture(scope="module")
def makefile_text() -> str:
    return MAKEFILE.read_text()


def _release_check_recipe(text: str) -> str:
    """Return the release-check recipe block (target + all indented lines)."""
    lines = text.splitlines()
    in_recipe = False
    out: list[str] = []
    for line in lines:
        if line.startswith("release-check:"):
            in_recipe = True
            out.append(line)
            continue
        if in_recipe:
            # Recipe lines start with TAB or are blank; a non-tab non-blank line
            # ends the recipe (next target or top-level directive).
            if line and not line.startswith(("\t", " ", "ifdef", "ifndef", "endif", "else")):
                break
            out.append(line)
    return "\n".join(out)


def test_tc_054_01_release_check_target_exists(makefile_text: str) -> None:
    """TC-054-01: release-check: target defined and in .PHONY line."""
    assert "\nrelease-check:" in makefile_text, "Makefile missing release-check target"
    phony_line = next(line for line in makefile_text.splitlines() if line.startswith(".PHONY:"))
    assert "release-check" in phony_line, "release-check not in .PHONY"


def test_tc_054_02_make_help_lists_release_check() -> None:
    """TC-054-02: make help mentions release-check."""
    out = subprocess.run(["make", "help"], cwd=REPO_ROOT, capture_output=True, text=True, timeout=10)
    assert "release-check" in out.stdout, f"'release-check' not in make help output:\n{out.stdout}"


def test_tc_054_03_recipe_references_staged_sequence(makefile_text: str) -> None:
    """TC-054-03: recipe references check, fitness, demo, and --offline-smoke."""
    recipe = _release_check_recipe(makefile_text)
    assert recipe, "release-check recipe not extractable"
    for needle in ("check", "fitness", "demo", "--offline-smoke"):
        assert needle in recipe, f"release-check recipe missing reference to {needle!r}"


def test_tc_054_04_docker_stage_gated_on_env_var(makefile_text: str) -> None:
    """TC-054-04: any docker invocation in the recipe is conditional on DOCKER."""
    recipe = _release_check_recipe(makefile_text)
    docker_lines = [line for line in recipe.splitlines() if "docker" in line.lower()]
    if not docker_lines:
        pytest.skip("recipe has no docker lines to gate")
    # Either the lines are inside an `ifdef DOCKER` block, or each references DOCKER explicitly.
    assert "ifdef DOCKER" in recipe or "$(DOCKER)" in recipe, (
        "docker stage not gated on DOCKER env var (use ifdef DOCKER or $(DOCKER))"
    )


def test_tc_054_05_release_checklist_exists_with_required_sections() -> None:
    """TC-054-05: RELEASE_CHECKLIST.md exists with all five required headers."""
    p = REPO_ROOT / "RELEASE_CHECKLIST.md"
    assert p.exists(), "RELEASE_CHECKLIST.md missing"
    text = p.read_text()
    for section in ("Pre-flight", "Automated verification", "Manual verification", "Tag and push", "Post-tag"):
        assert section in text, f"checklist missing section: {section}"
    assert "make release-check" in text, "checklist does not reference make release-check"


def test_tc_054_06_contributing_or_claudemd_references_release_check() -> None:
    """TC-054-06: CONTRIBUTING.md or CLAUDE.md references make release-check."""
    matches = []
    for fname in ("CONTRIBUTING.md", "CLAUDE.md"):
        p = REPO_ROOT / fname
        if p.exists() and "make release-check" in p.read_text():
            matches.append(fname)
    assert matches, "Neither CONTRIBUTING.md nor CLAUDE.md references make release-check"
