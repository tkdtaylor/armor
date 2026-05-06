"""Parametrized tests over the evaluation corpus.

This test suite loads all corpus YAML files and runs each row through
the pipeline, asserting that the verdict matches the expected value.
Includes latency measurement and per-detector coverage reporting.
"""

# Load corpus directly with absolute import
import importlib.util
import time
from collections import defaultdict
from pathlib import Path

import pytest

from armor.detectors import DetectorRegistry
from armor.pipeline import Pipeline
from armor.types import Payload, SessionContext

_loader_path = Path(__file__).parent / "corpus" / "_loader.py"
spec = importlib.util.spec_from_file_location("corpus_loader", _loader_path)
assert spec is not None and spec.loader is not None
corpus_loader = importlib.util.module_from_spec(spec)
spec.loader.exec_module(corpus_loader)
load_corpus = corpus_loader.load_corpus

# Load registry and corpus at collection time
registry = DetectorRegistry()
detectors = registry.all()
all_rows = load_corpus()

# Filter to single-shot rows only for the parametrized test
# Multi-turn rows are tested separately in test_runner_multi_turn.py
corpus = [r for r in all_rows if not r.is_multi_turn()]

# Latency budget in milliseconds (per detector, static-only for v0.2)
LATENCY_BUDGET_MS = 50

# Global stats collection for coverage report
_coverage_stats: dict[str, dict[str, int]] = defaultdict(lambda: {"tp": 0, "tn": 0})
_latency_records: list[tuple[str, float]] = []


def _extract_detector_signal_id(signal_id: str | None) -> str:
    """Extract detector name from signal_id (e.g., 'regex.instruction_override:override-001' -> 'regex.instruction_override')."""
    if signal_id is None:
        return "none"
    return signal_id.split(":")[0]


@pytest.mark.skipif(
    not corpus,
    reason="No corpus rows loaded",
)
@pytest.mark.asyncio
@pytest.mark.parametrize("row", corpus, ids=lambda r: r.id)
async def test_corpus_verdict(row: "corpus_loader.CorpusRow") -> None:
    """Run each corpus row through the pipeline and assert verdict matches.

    TC-014-CORPUS-01: P0 direct-injection rows pass.
    TC-014-CORPUS-02: P0 exfiltration rows pass.
    TC-014-CORPUS-03: P1 obfuscation rows pass.
    TC-014-CORPUS-04: P1 tool-abuse rows pass.
    TC-014-CORPUS-05: Scenario rows exercise multi-stage attacks.

    Args:
        row: A corpus row from the parametrize.
    """
    # Build payload based on row type
    payload = Payload(tool=row.tool, params=row.tool_params) if row.tool is not None else Payload(text=row.input)

    # Build session context
    ctx = SessionContext(session_id="test", signal_history=[])

    # Run pipeline with timing
    start_ns = time.perf_counter_ns()
    verdict = await Pipeline.run(detectors, payload, ctx)
    elapsed_ns = time.perf_counter_ns() - start_ns
    elapsed_ms = elapsed_ns / 1_000_000

    # Record latency
    _latency_records.append((row.id, elapsed_ms))

    # Record coverage stats
    detector_name = _extract_detector_signal_id(verdict.signal_id)
    is_tp = verdict.decision == "block"
    is_tn = verdict.decision == "pass"
    if is_tp:
        _coverage_stats[detector_name]["tp"] += 1
    elif is_tn:
        _coverage_stats[detector_name]["tn"] += 1

    # Assert verdict decision matches expected
    assert verdict.decision == row.expected_verdict, (
        f"Corpus {row.id}: expected verdict {row.expected_verdict}, got {verdict.decision}"
    )

    # If signal ID is expected, assert it matches
    if row.expected_signal_id is not None:
        assert verdict.signal_id == row.expected_signal_id, (
            f"Corpus {row.id}: expected signal {row.expected_signal_id}, got {verdict.signal_id}"
        )


@pytest.fixture(scope="session", autouse=True)
def report_corpus_stats() -> None:
    """Print coverage and latency report after all corpus tests complete.

    TC-014-COVERAGE-01: Coverage report includes all detectors.
    TC-014-LATENCY-01: P95 corpus latency is within budget.
    """
    yield

    if not _latency_records:
        return

    # Compute latency stats
    latencies = sorted([lat for _, lat in _latency_records])
    p95_idx = max(0, int(len(latencies) * 0.95) - 1)
    p95_latency_ms = latencies[p95_idx] if latencies else 0
    p50_latency_ms = latencies[len(latencies) // 2] if latencies else 0

    # Print coverage report
    print("\n" + "=" * 80)
    print("CORPUS EVALUATION REPORT")
    print("=" * 80)
    print(f"\nTotal rows tested: {len(_latency_records)}")
    print(f"Latency (P50): {p50_latency_ms:.2f} ms")
    print(f"Latency (P95): {p95_latency_ms:.2f} ms")
    print(f"Budget: {LATENCY_BUDGET_MS} ms")

    # Print per-detector coverage
    print("\nPer-detector coverage:")
    print("-" * 80)
    print(f"{'Detector':<40} {'TP':<8} {'TN':<8} {'Total':<8}")
    print("-" * 80)

    total_tp = 0
    total_tn = 0
    for detector in sorted(_coverage_stats.keys()):
        stats = _coverage_stats[detector]
        tp = stats["tp"]
        tn = stats["tn"]
        total = tp + tn
        total_tp += tp
        total_tn += tn
        print(f"{detector:<40} {tp:<8} {tn:<8} {total:<8}")

    print("-" * 80)
    print(f"{'TOTAL':<40} {total_tp:<8} {total_tn:<8} {total_tp + total_tn:<8}")
    print("=" * 80 + "\n")

    # Assert latency budget (TC-014-LATENCY-01)
    assert p95_latency_ms <= LATENCY_BUDGET_MS, (
        f"P95 latency {p95_latency_ms:.2f} ms exceeds budget of {LATENCY_BUDGET_MS} ms"
    )
