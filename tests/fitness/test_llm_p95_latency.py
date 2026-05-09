"""Fitness check: P95 LLM latency under budget (validator and honeypot).

Per ADR-023 (amended by task 043), enforce two latency budgets:

- Validator P95 ≤ 500 ms (empirical baseline 486 ms per ADR-018).
- Honeypot P95 ≤ 16,000 ms (task 043 amendment from the original 12,000 ms,
  reflecting empirical 15,000-15,500 ms on developer machines).

The check pulls helper logic from ``_llm_p95_helpers.py`` (underscore-prefixed
so pytest's default glob skips it). Two tests are exposed:

- ``test_llm_p95_under_budget_smoke`` (``smoke`` marker): the default fitness
  gate, runs against ~20 validator + ~5 honeypot rows.
- ``test_llm_p95_under_budget_full`` (``slow`` marker): nightly / opt-in,
  runs against the full ≥100 / ≥30 row corpora via ``ARMOR_FITNESS_FULL=1``.

Either test cleanly skips when the model weights or ``llama-cpp-python`` are
unavailable, or when ``ARMOR_DISABLE_LLM=true``.

Spec markers:
    TC-033-01..06 — original LLM P95 fitness behaviours.
    TC-043-03/04/05 — honeypot budget post-amendment, CI blocking, ADR amend.
    TC-091-09 — ``make fitness-full`` runs the full corpus.
"""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]

# Make src/ importable so the helper module can resolve `armor.*` imports.
sys.path.insert(0, str(REPO_ROOT / "src"))

# Load the helper module by file path so the underscore prefix doesn't conflict
# with pytest discovery (which only looks at top-level names).
_helpers_path = Path(__file__).parent / "_llm_p95_helpers.py"
_spec = importlib.util.spec_from_file_location("_llm_p95_helpers", _helpers_path)
assert _spec is not None and _spec.loader is not None
_helpers = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_helpers)

VALIDATOR_BUDGET_MS = _helpers.VALIDATOR_BUDGET_MS
HONEYPOT_BUDGET_MS = _helpers.HONEYPOT_BUDGET_MS
SMOKE_VALIDATOR_ROWS = _helpers.SMOKE_VALIDATOR_ROWS
SMOKE_HONEYPOT_ROWS = _helpers.SMOKE_HONEYPOT_ROWS
FULL_VALIDATOR_ROWS = _helpers.FULL_VALIDATOR_ROWS
FULL_HONEYPOT_ROWS = _helpers.FULL_HONEYPOT_ROWS
_find_model_path = _helpers._find_model_path
_percentile = _helpers._percentile
check_llm_p95_latency = _helpers.check_llm_p95_latency


# ---------------------------------------------------------------------------
# Pure-function tests (no model required).
# ---------------------------------------------------------------------------


@pytest.mark.smoke
def test_percentile_basic() -> None:
    """TC-033-03: P95 percentile computation matches expectation."""
    p95 = _percentile(list(range(1, 101)), 0.95)
    assert 94 <= p95 <= 96, f"P95 of [1..100] should be ~95, got {p95}"


@pytest.mark.smoke
def test_percentile_empty() -> None:
    """Empty input returns 0.0 rather than raising."""
    assert _percentile([], 0.95) == 0.0


@pytest.mark.smoke
def test_armor_model_env_override() -> None:
    """TC-033-05: ARMOR_MODEL env var pins the discovered path."""
    test_model = "/tmp/test-model.gguf"
    with patch.dict(os.environ, {"ARMOR_MODEL": test_model}):
        assert _find_model_path() == Path(test_model)


@pytest.mark.smoke
def test_budgets_constants_match_spec() -> None:
    """TC-033-03 / TC-043-04: hardcoded budgets match ADR-023 (post-amendment)."""
    assert VALIDATOR_BUDGET_MS == 500, f"Validator budget should be 500 ms per ADR-023, got {VALIDATOR_BUDGET_MS}"
    assert HONEYPOT_BUDGET_MS == 16000, (
        f"Honeypot budget should be 16,000 ms (task 043 amendment), got {HONEYPOT_BUDGET_MS}"
    )


@pytest.mark.smoke
def test_smoke_variant_row_counts() -> None:
    """TC-033-06: smoke variant uses smaller row counts than full."""
    assert SMOKE_VALIDATOR_ROWS < FULL_VALIDATOR_ROWS
    assert SMOKE_HONEYPOT_ROWS < FULL_HONEYPOT_ROWS


# ---------------------------------------------------------------------------
# CI wiring tests (read .github/ + ADR text).
# ---------------------------------------------------------------------------


@pytest.mark.smoke
def test_tc_043_03_make_fitness_job_not_advisory() -> None:
    """TC-043-03: ci.yml ``make-fitness`` job is no longer advisory."""
    ci_path = REPO_ROOT / ".github" / "workflows" / "ci.yml"
    data = yaml.safe_load(ci_path.read_text(encoding="utf-8"))
    assert "make-fitness" in data["jobs"], "make-fitness job not found in CI"
    continue_on_error = data["jobs"]["make-fitness"].get("continue-on-error")
    assert continue_on_error is not True, (
        f"make-fitness should not be advisory; got continue-on-error={continue_on_error!r}"
    )


@pytest.mark.smoke
def test_tc_043_05_adr_023_amended() -> None:
    """TC-043-05: ADR-023 carries an Amendment section referencing task 043 + 16,000 ms."""
    adr_path = REPO_ROOT / "docs" / "architecture" / "decisions" / "023-llm-budget-soft-fail.md"
    adr_content = adr_path.read_text(encoding="utf-8")
    assert "Amendment" in adr_content
    assert "Task 043" in adr_content or "task 043" in adr_content
    assert "16000" in adr_content or "16,000" in adr_content


# ---------------------------------------------------------------------------
# Real LLM measurements — gated by model availability and ARMOR_FITNESS_FULL.
# ---------------------------------------------------------------------------


def _llm_disabled() -> bool:
    return os.environ.get("ARMOR_DISABLE_LLM", "false").lower() in ("true", "1", "yes")


def _model_available() -> bool:
    if _llm_disabled():
        return False
    path = _find_model_path()
    return path is not None and path.exists()


@pytest.mark.requires_llm
def test_llm_p95_under_budget_smoke() -> None:
    """TC-033-01..03 / TC-091-12: validator + honeypot P95 within budget (smoke variant).

    Not marked ``smoke`` because loading model weights pushes runtime past the
    pre-push budget. Runs under default ``make fitness`` (≤ ~60 s when model
    weights are present), gets skipped cleanly otherwise, and is excluded from
    ``make fitness-smoke``.
    """
    if not _model_available():
        pytest.skip("LLM model weights not available (ARMOR_DISABLE_LLM=true or model missing)")
    # Force smoke variant regardless of ambient env.
    with patch.dict(os.environ, {"ARMOR_FITNESS_FULL": "false"}):
        ok = check_llm_p95_latency()
    assert ok, "LLM P95 latency exceeded budget — see captured stdout for measurements"


@pytest.mark.slow
@pytest.mark.requires_llm
def test_llm_p95_under_budget_full() -> None:
    """TC-091-09: full corpus run (≥100 validator / ≥30 honeypot rows)."""
    if not _model_available():
        pytest.skip("LLM model weights not available (ARMOR_DISABLE_LLM=true or model missing)")
    with patch.dict(os.environ, {"ARMOR_FITNESS_FULL": "true"}):
        ok = check_llm_p95_latency()
    assert ok, "LLM P95 latency exceeded budget on full corpus"
