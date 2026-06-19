# SPDX-License-Identifier: Apache-2.0
"""Fitness checks for the v1.0 readiness gate (task 099).

Spec markers:
    TC-099-01 — docs/v1-readiness.md exists with the five required sections
    TC-099-02 — detection floor is concrete
    TC-099-03 — performance gates are concrete
    TC-099-04 — integration gates list the verification tasks
    TC-099-05 — external-validation plan picks an option with a date/condition
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
READINESS_DOC = ROOT / "docs" / "v1-readiness.md"


def _readiness_text() -> str:
    assert READINESS_DOC.is_file(), "docs/v1-readiness.md is missing"
    return READINESS_DOC.read_text(encoding="utf-8")


def test_tc_099_01_readiness_doc_has_required_sections() -> None:
    """TC-099-01: readiness doc exists and includes all required sections."""
    text = _readiness_text()
    for heading in [
        "Detection Floor",
        "Performance Gates",
        "Integration Gates",
        "External Validation",
        "Pre-Tag Runbook Gate",
    ]:
        assert f"## {heading}" in text, f"missing readiness section: {heading}"


def test_tc_099_02_detection_floor_is_concrete() -> None:
    """TC-099-02: detection floor has numeric thresholds, not aspirations."""
    text = _readiness_text()
    section = text.split("## Detection Floor", 1)[1].split("## Performance Gates", 1)[0]
    for needle in ["100 labeled evaluation rows", ">= 90%", ">= 80%", "<= 5%", "25 rows"]:
        assert needle in section, f"detection floor missing concrete threshold: {needle}"
    assert "should" not in section.lower(), "detection floor contains vague 'should' language"


def test_tc_099_03_performance_gates_are_concrete() -> None:
    """TC-099-03: performance gates cite tests, hardware, and M-of-N policy."""
    text = _readiness_text()
    section = text.split("## Performance Gates", 1)[1].split("## Integration Gates", 1)[0]
    collapsed = re.sub(r"\s+", " ", section)
    for needle in [
        "Intel Core Ultra 9 185H",
        "n_threads=1",
        "5 of 5",
        "3 of 3",
        "test_llm_p95_under_budget_smoke",
        "test_cold_start_budget.py",
    ]:
        assert needle in collapsed, f"performance gate missing: {needle}"


def test_tc_099_04_integration_gates_reference_tasks_092_to_098() -> None:
    """TC-099-04: integration section references the implementation tasks."""
    text = _readiness_text()
    section = text.split("## Integration Gates", 1)[1].split("## External Validation", 1)[0]
    for task_id in range(92, 99):
        assert f"Task {task_id:03d}" in section, f"integration gates missing Task {task_id:03d}"


def test_tc_099_05_external_validation_has_concrete_completion_condition() -> None:
    """TC-099-05: external validation chooses a plan and completion condition."""
    text = _readiness_text()
    section = text.split("## External Validation", 1)[1].split("## Pre-Tag Runbook Gate", 1)[0]
    collapsed = re.sub(r"\s+", " ", section)
    assert "2 security reviewers" in section
    assert re.search(r"14 calendar days|200 guarded checks", section)
    assert "no unresolved" in collapsed
    assert "HIGH/CRITICAL" in collapsed
