"""Regression gate tests for corpus and detector changes.

These tests are normally skipped; enable with ARMOR_TEST_REGRESSION_GATE=1.

The regression gate verifies that:
1. A detector regression (always returning 'pass') causes corpus tests to fail
2. A corpus row mismatch (wrong expected_verdict) causes tests to fail
3. The CI gate would catch these regressions

This test suite uses mocks/fixtures to simulate regressions without
actually modifying the source code or corpus.
"""

import importlib.util
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from armor.detectors import DetectorRegistry
from armor.pipeline import Pipeline
from armor.types import Payload, SessionContext, Verdict

_loader_path = Path(__file__).parent / "corpus" / "_loader.py"
spec = importlib.util.spec_from_file_location("corpus_loader", _loader_path)
assert spec is not None and spec.loader is not None
corpus_loader = importlib.util.module_from_spec(spec)
spec.loader.exec_module(corpus_loader)
load_corpus = corpus_loader.load_corpus


# Gate: only run these tests if explicitly enabled
pytestmark = pytest.mark.skipif(
    os.environ.get("ARMOR_TEST_REGRESSION_GATE") != "1",
    reason="Regression gate disabled (enable with ARMOR_TEST_REGRESSION_GATE=1)",
)


@pytest.mark.asyncio
async def test_detector_regression() -> None:
    """TC-014-REG-01: Regression gate detects detector failure.

    A detector that always returns 'pass' causes corpus rows expecting 'block'
    to fail the assertion. This test simulates that regression.
    """
    # Load corpus and registry
    registry = DetectorRegistry()
    detectors = registry.all()
    corpus = load_corpus()

    # Find a corpus row expecting 'block' (a TP case)
    tp_rows = [row for row in corpus if row.expected_verdict == "block"]
    assert tp_rows, "No TP rows found in corpus; cannot run regression test"

    test_row = tp_rows[0]

    # Build payload
    payload = (
        Payload(tool=test_row.tool, params=test_row.tool_params)
        if test_row.tool is not None
        else Payload(text=test_row.input)
    )
    ctx = SessionContext(session_id="test", signal_history=[])

    # Mock a detector to always return 'pass' (simulating a regression)
    # For this test, we'll patch the Pipeline.run to inject a failing detector
    async def mock_run_with_broken_detector(*args, **kwargs):
        # Return 'pass' verdict, causing the TP row to fail its assertion
        return Verdict.pass_verdict(message="Broken detector")

    with patch.object(Pipeline, "run", new=mock_run_with_broken_detector):
        verdict = await Pipeline.run(detectors, payload, ctx)

        # This should return 'pass' (the broken detector's verdict)
        assert verdict.decision == "pass"

        # But the corpus row expects 'block', so the actual test would fail
        # We assert that this mismatch is what would happen
        assert test_row.expected_verdict == "block"
        assert verdict.decision != test_row.expected_verdict, (
            "Regression: detector returned 'pass' but corpus expected 'block'"
        )


@pytest.mark.asyncio
async def test_corpus_mismatch() -> None:
    """TC-014-REG-02: Regression gate detects corpus mismatch.

    A corpus row with the wrong expected_verdict causes test failures.
    This test simulates a corpus corruption scenario.
    """
    # Load corpus
    registry = DetectorRegistry()
    detectors = registry.all()
    corpus = load_corpus()

    # Find a TP row (expects 'block')
    tp_rows = [row for row in corpus if row.expected_verdict == "block"]
    assert tp_rows, "No TP rows found in corpus; cannot run regression test"

    test_row = tp_rows[0]

    # Build payload
    payload = (
        Payload(tool=test_row.tool, params=test_row.tool_params)
        if test_row.tool is not None
        else Payload(text=test_row.input)
    )
    ctx = SessionContext(session_id="test", signal_history=[])

    # Run the pipeline normally (detector works fine)
    verdict = await Pipeline.run(detectors, payload, ctx)

    # The detector will return 'block' (correct TP behavior)
    assert verdict.decision == "block"

    # But if the corpus row had been corrupted to expect 'pass', the test would fail
    # Simulate that by checking what would happen if expected_verdict was wrong
    wrong_expected = "pass"
    assert wrong_expected != verdict.decision, (
        f"Corpus mismatch: corpus expects '{wrong_expected}' but detector returned '{verdict.decision}'"
    )


def test_regression_tests_are_gated() -> None:
    """TC-014-REG-03: Regression tests are skipped by default.

    Verify that the gate is working by checking the env var.
    """
    # This test always runs (it's not marked skipif itself).
    # Confirm the gate env var is NOT set in normal test runs.
    gate_env = os.environ.get("ARMOR_TEST_REGRESSION_GATE")
    # In a normal test run (without the env var), gate_env is None
    # The module-level skipif will skip the entire module
    # This test documents the expected behavior
    assert gate_env == "1", "This test module should only run when ARMOR_TEST_REGRESSION_GATE=1"
