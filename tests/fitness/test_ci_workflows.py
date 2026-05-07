"""Fitness checks for the GitHub Actions CI workflows + README badges (task 058).

The existing ci.yml splits `make check`'s components into separate jobs (lint,
format-check, typecheck, unit, eval, fitness) which is better practice than a
single monolithic step — surfaces failures on distinct PR check rows. The
fitness assertion below validates the *invariant* (all components covered),
not the specific implementation shape.

Spec markers:
    TC-058-01 — ci.yml exists and is valid YAML
    TC-058-02 — ci.yml runs the equivalent of `make check` and `make fitness`
    TC-058-03 — ci.yml triggers on pull_request and push to main
    TC-058-04 — release-check.yml exists and references make release-check
    TC-058-05 — README has 4 badges in the header
    TC-058-06 — README CI badge points to ci.yml
    TC-058-07 — README release-check badge points to release-check.yml
    TC-058-08 — ci.yml uses uv sync --frozen for reproducible deps
    TC-058-09 — CONTRIBUTING.md notes CI must pass before merge
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = REPO_ROOT / ".github" / "workflows"


def _load_yaml(path: Path) -> dict[str, Any]:
    return yaml.safe_load(path.read_text())


def _on_block(data: dict[str, Any]) -> dict[str, Any]:
    """PyYAML quirk: the 'on' key may parse as Python True. Handle both."""
    return data.get("on", data.get(True, {}))


def _all_run_steps(data: dict[str, Any]) -> str:
    """Concatenate every job step's `run` string for substring assertions."""
    chunks: list[str] = []
    for job in data.get("jobs", {}).values():
        for step in job.get("steps", []):
            run = step.get("run", "")
            if isinstance(run, str):
                chunks.append(run)
    return "\n".join(chunks)


@pytest.fixture(scope="module")
def ci() -> dict[str, Any]:
    return _load_yaml(WORKFLOWS / "ci.yml")


def test_tc_058_01_ci_yml_exists_and_valid() -> None:
    """TC-058-01: ci.yml is valid YAML with a jobs block."""
    p = WORKFLOWS / "ci.yml"
    assert p.exists(), "ci.yml missing"
    data = _load_yaml(p)
    assert isinstance(data, dict) and "jobs" in data


def test_tc_058_02_ci_covers_check_and_fitness(ci: dict[str, Any]) -> None:
    """TC-058-02: ci.yml runs `make check` equivalents and `make fitness`.

    `make check` decomposes to lint + format + typecheck + unit tests + eval.
    Either accept the literal `make check` invocation OR all five components
    individually. `make fitness` must be present literally (or as an
    equivalent pytest tests/fitness/ invocation).
    """
    runs = _all_run_steps(ci)

    # Either the unified target or all five components
    has_unified_check = "make check" in runs
    components = ("ruff check", "ruff format", "mypy", "pytest tests/unit", "pytest tests/eval")
    has_split_check = all(c in runs for c in components)
    assert has_unified_check or has_split_check, (
        f"ci.yml does not cover make check (need either `make check` or {components!r})"
    )

    # Fitness coverage
    has_make_fitness = "make fitness" in runs
    has_pytest_fitness = "pytest tests/fitness" in runs
    assert has_make_fitness or has_pytest_fitness, "ci.yml does not run make fitness or pytest tests/fitness/"


def test_tc_058_03_ci_triggers_on_pr_and_push_main(ci: dict[str, Any]) -> None:
    """TC-058-03: workflow runs on pull_request and push (with main branch)."""
    on = _on_block(ci)
    assert "pull_request" in on, "ci.yml missing pull_request trigger"
    assert "push" in on, "ci.yml missing push trigger"
    push = on["push"]
    if isinstance(push, dict):
        branches = push.get("branches", [])
        assert "main" in branches, "ci.yml push trigger does not include main"


def test_tc_058_04_release_check_workflow_exists() -> None:
    """TC-058-04: release-check.yml exists and references make release-check."""
    p = WORKFLOWS / "release-check.yml"
    assert p.exists(), "release-check.yml missing"
    text = p.read_text()
    assert "make release-check" in text, "release-check.yml does not run make release-check"


def test_tc_058_05_readme_has_four_badges() -> None:
    """TC-058-05: README header contains at least 4 badges."""
    text = (REPO_ROOT / "README.md").read_text()
    head = "\n".join(text.splitlines()[:30])
    badges = re.findall(r"!\[[^\]]*\]\([^)]*(?:badge\.svg|shields\.io)[^)]*\)", head)
    assert len(badges) >= 4, f"README has fewer than 4 badges in header: {len(badges)}"


def test_tc_058_06_readme_ci_badge_present() -> None:
    """TC-058-06: README references the ci.yml workflow badge."""
    text = (REPO_ROOT / "README.md").read_text()
    assert "ci.yml/badge.svg" in text, "README missing CI workflow badge"


def test_tc_058_07_readme_release_check_badge_present() -> None:
    """TC-058-07: README references the release-check.yml workflow badge."""
    text = (REPO_ROOT / "README.md").read_text()
    assert "release-check.yml/badge.svg" in text, "README missing release-check workflow badge"


def test_tc_058_08_ci_uses_frozen_uv_sync(ci: dict[str, Any]) -> None:
    """TC-058-08: ci.yml uses `uv sync --frozen` for reproducible deps."""
    runs = _all_run_steps(ci)
    assert "uv sync" in runs, "ci.yml missing uv sync"
    assert "--frozen" in runs, "ci.yml missing --frozen flag for reproducible deps"


def test_tc_058_09_contributing_requires_ci_to_pass() -> None:
    """TC-058-09: CONTRIBUTING.md notes CI must pass before merge."""
    text = (REPO_ROOT / "CONTRIBUTING.md").read_text().lower()
    assert "ci" in text, "CONTRIBUTING.md does not mention CI"
    assert re.search(r"ci.{0,40}(pass|merge)", text), "CONTRIBUTING.md does not require CI to pass before merge"
