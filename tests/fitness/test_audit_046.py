"""Fitness tests for task 046: Reconcile honeypot_budget_ms."""

import re
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent.parent


def test_tc_046_01_single_canonical_honeypot_budget():
    """TC-046-01: Single canonical honeypot budget value across all surfaces."""
    files = [
        "src/armor/llm/loader.py",
        "src/armor/llm/honeypot.py",
        "tests/fitness/_llm_p95_helpers.py",
        "docs/spec/configuration.md",
        "docs/spec/fitness-functions.md",
        "armor.toml",
    ]

    pat = re.compile(r"(?:honeypot_budget_ms|HONEYPOT_BUDGET_MS)\s*[:=]\s*(\d+)")
    values = set()
    hits = {}

    for f in files:
        file_path = REPO_ROOT / f
        if not file_path.exists():
            continue
        text = file_path.read_text()
        for m in pat.finditer(text):
            value = int(m.group(1))
            values.add(value)
            if value not in hits:
                hits[value] = []
            hits[value].append(f"{f}:{m.start()}")

    assert len(values) == 1, f"honeypot budget value drift: {values}, hits: {hits}"


def test_tc_046_02_adr_023_body_and_amendment_consistent():
    """TC-046-02: ADR-023 body and amendment are internally consistent."""
    adr_path = REPO_ROOT / "docs/architecture/decisions/023-llm-budget-soft-fail.md"
    text = adr_path.read_text()

    # Extract the canonical value from the code (should be 16000 after this task)
    loader_path = REPO_ROOT / "src/armor/llm/loader.py"
    loader_text = loader_path.read_text()
    # Look for the parameter with or without spaces around the =
    pat = re.compile(r"honeypot_budget_ms\s*:\s*int\s*=\s*(\d+)")
    m = pat.search(loader_text)
    assert m is not None, "honeypot_budget_ms not found in loader.py function signature"
    canonical_value = int(m.group(1))

    # If code value is 16000, ensure "no code changes required" line is gone or reworded
    if canonical_value == 16000:
        assert "no code changes required" not in text.lower(), (
            "ADR-023 still claims 'no code changes required' but code was updated to 16000"
        )


def test_tc_046_03_fitness_script_runs():
    """TC-046-03: scripts/fitness.sh is present and executable."""
    fitness_script = REPO_ROOT / "scripts/fitness.sh"
    assert fitness_script.exists(), "scripts/fitness.sh does not exist"
    assert fitness_script.stat().st_mode & 0o111, "scripts/fitness.sh is not executable"


def test_tc_046_04_make_check_target_exists():
    """TC-046-04: make check target is reachable (target exists in Makefile)."""
    makefile = REPO_ROOT / "Makefile"
    if not makefile.exists():
        makefile = REPO_ROOT / "makefile"

    if makefile.exists():
        text = makefile.read_text()
        assert "check:" in text or r"\.PHONY.*check" in text, "Makefile missing 'check' target"
