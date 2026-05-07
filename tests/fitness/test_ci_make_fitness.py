"""CI wiring assertions for the make-fitness job (tasks 042 & 043).

Asserts that .github/workflows/ci.yml has a top-level make-fitness job that
runs scripts/fitness.sh and is blocking (no continue-on-error: true).

Task 042 wired the job (advisory); Task 043 resolved the honeypot P95 latency
regression and promoted it to blocking.

Spec markers:
    TC-042-01 — ci.yml has a top-level make-fitness job
    TC-042-02 — that job invokes make fitness or scripts/fitness.sh
    TC-042-04 — scripts/fitness.sh is executable
    TC-043-03 — that job is blocking (no continue-on-error: true)
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, cast

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
CI_YAML_PATH = REPO_ROOT / ".github" / "workflows" / "ci.yml"
FITNESS_SCRIPT_PATH = REPO_ROOT / "scripts" / "fitness.sh"


def _ci_jobs() -> dict[str, Any]:
    data = cast(dict[str, Any], yaml.safe_load(CI_YAML_PATH.read_text(encoding="utf-8")))
    return cast(dict[str, Any], data["jobs"])


def test_tc_042_01_make_fitness_job_exists() -> None:
    """TC-042-01: ci.yml has a top-level make-fitness job."""
    jobs = _ci_jobs()
    assert "make-fitness" in jobs, f"make-fitness job missing from ci.yml; jobs present: {sorted(jobs)}"
    assert isinstance(jobs["make-fitness"], dict), (
        f"make-fitness job is not a dict; got {type(jobs['make-fitness']).__name__}"
    )


def test_tc_042_02_make_fitness_invokes_fitness_entry_point() -> None:
    """TC-042-02: at least one step runs `make fitness` or `scripts/fitness.sh`."""
    job = _ci_jobs()["make-fitness"]
    steps = job.get("steps", [])
    runs = [step.get("run", "").strip() for step in steps if isinstance(step, dict)]
    matched = [r for r in runs if r.startswith("make fitness") or "scripts/fitness.sh" in r]
    assert matched, (
        f"make-fitness job does not invoke `make fitness` or `scripts/fitness.sh`; step `run` values seen: {runs}"
    )


def test_tc_043_03_make_fitness_is_blocking() -> None:
    """TC-043-03: make-fitness no longer has continue-on-error: true.

    Promoted to blocking after task 043 closes the honeypot P95 latency regression
    (resolved by updating budget from 12,000 ms to 16,000 ms per empirical measurement).

    Replaces TC-042-03 (which asserted advisory mode).
    """
    job = _ci_jobs()["make-fitness"]
    val = job.get("continue-on-error")
    assert val is not True, f"make-fitness should be blocking (not advisory); got continue-on-error={val!r}"


def test_tc_042_04_fitness_script_is_executable() -> None:
    """TC-042-04: scripts/fitness.sh exists and is executable."""
    assert FITNESS_SCRIPT_PATH.is_file(), f"missing {FITNESS_SCRIPT_PATH}"
    assert os.access(FITNESS_SCRIPT_PATH, os.X_OK), f"{FITNESS_SCRIPT_PATH} is not executable; run `chmod +x` to fix"
