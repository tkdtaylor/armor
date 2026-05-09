"""Fitness check: validator soft-fails to ``advisory(confidence=0)`` on timeout.

Per ADR-023, a validator timeout must produce a soft-fail advisory rather than
blocking or escalating session state. This is enforced unit-by-unit in
``tests/unit/llm/test_soft_fail.py``; the fitness check re-runs that suite via
pytest as a subprocess so a green ``make fitness`` is sufficient signal that the
soft-fail invariant still holds end-to-end.

Spec markers:
    TC-021-01 — validator timeout returns ``advisory(confidence=0)``.
    TC-021-09 — ``LLMSession`` stores ``validator_budget_ms``.
    TC-091-11 — soft-fail check still fires after the consolidation.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SOFT_FAIL_SUITE = "tests/unit/llm/test_soft_fail.py"


def test_validator_soft_fail_unit_suite_passes() -> None:
    """TC-021-01 / TC-091-11: soft-fail unit tests must pass under default config."""
    result = subprocess.run(
        ["uv", "run", "pytest", SOFT_FAIL_SUITE, "-v", "-p", "no:cacheprovider"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert result.returncode == 0, (
        f"validator soft-fail suite failed (exit {result.returncode})\n"
        f"stdout:\n{result.stdout}\n"
        f"stderr:\n{result.stderr}"
    )
