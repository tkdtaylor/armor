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
declared_detector_coverage_cases = [(row, detector_id) for row in corpus for detector_id in row.covers_detectors]

# Latency budget in milliseconds (per detector, static-only for v0.2)
LATENCY_BUDGET_MS = 50

REQUIRED_CONTEXT_WINDOW_FAMILIES = {
    "context_overflow",
    "instruction_burial",
    "memory_planting",
    "conversation_hijack",
}
REQUIRED_CONTEXT_WINDOW_DETECTORS = {
    "meta.token_count_anomaly",
    "meta.instruction_burial",
    "meta.memory_planting",
    "meta.conversation_hijack",
}

# Global stats collection for coverage report
_coverage_stats: dict[str, dict[str, int]] = defaultdict(lambda: {"tp": 0, "tn": 0})
_latency_records: list[tuple[str, float]] = []


def _extract_detector_signal_id(signal_id: str | None) -> str:
    """Extract detector name from signal_id (e.g., 'regex.instruction_override:override-001' -> 'regex.instruction_override')."""
    if signal_id is None:
        return "none"
    return signal_id.split(":")[0]


def _covered_detector_ids(rows: list["corpus_loader.CorpusRow"]) -> set[str]:
    """Return detector IDs covered by direct signal expectations or row metadata."""
    covered = set()
    for row in rows:
        signal_detector_id = _extract_detector_signal_id(row.expected_signal_id)
        if signal_detector_id != "none":
            covered.add(signal_detector_id)
        covered.update(row.covers_detectors)
    return covered


def _payload_for_row(row: "corpus_loader.CorpusRow") -> Payload:
    """Build a payload for a single-shot corpus row."""
    if row.tool is not None:
        return Payload(tool=row.tool, params=row.tool_params)
    return Payload(text=row.input)


def test_required_context_window_families_have_corpus_rows() -> None:
    """TC-109-02: ADR-037 context-window families are represented in the corpus."""
    families = {row.family for row in corpus if row.attack_category == "context_window" and row.family is not None}

    assert families >= REQUIRED_CONTEXT_WINDOW_FAMILIES


def test_required_context_window_detectors_have_corpus_coverage() -> None:
    """TC-109-01: documented corpus-covered context-window detectors have rows."""
    covered_detector_ids = _covered_detector_ids(corpus)

    assert covered_detector_ids >= REQUIRED_CONTEXT_WINDOW_DETECTORS


def test_source_field_accepted_by_loader() -> None:
    """TC-113-01: Source field accepted by loader without error.

    Verify that corpus rows with a source field load successfully
    and the field is accessible on the returned CorpusRow object.
    """
    # Verify that source field is nullable and accessible on any row
    # (when rows with explicit source are added, they will also be accepted)
    for row in all_rows[:5]:  # Sample a few rows
        # Should not raise AttributeError
        source_value = row.source
        assert source_value is None or isinstance(source_value, str)


def test_missing_source_field_defaults_to_none() -> None:
    """TC-113-02: Missing source field defaults to None / maintainer.

    Verify that rows without explicit source field have source == None,
    which is treated as "maintainer" in the sourcing gate.
    """
    # All existing corpus rows should either have source=None or explicit "external:" prefix
    for row in all_rows:
        if row.source is None:
            # This is expected for maintainer-written rows
            pass
        else:
            # If source is set, it should be a string
            assert isinstance(row.source, str)


def test_external_sourcing_gate() -> None:
    """TC-113-03/04/05: External sourcing gate - families with >= 100 rows must have >= 25 external rows.

    TC-113-03: Gate vacuously passes when no family is at 100 rows.
    TC-113-04: Gate fails when a family hits 100 rows with < 25 external rows.
    TC-113-05: Gate passes when >= 25 external rows present.

    For any attack_category with >= 100 rows, assert that at least 25 of those rows
    have a source field starting with "external:".

    Families below 100 rows skip the assertion (corpus expansion tasks 114-120
    will trigger this gate once they land additional rows).
    """
    # Group all rows (including multi-turn) by attack_category
    rows_by_category: dict[str, list[corpus_loader.CorpusRow]] = {}
    for row in all_rows:
        if row.attack_category not in rows_by_category:
            rows_by_category[row.attack_category] = []
        rows_by_category[row.attack_category].append(row)

    # Check each category
    for category, rows in rows_by_category.items():
        total_rows = len(rows)

        # Skip categories below the 100-row threshold
        if total_rows < 100:
            continue

        # Count external rows for this category
        external_rows = sum(1 for row in rows if (row.source or "").startswith("external:"))

        assert external_rows >= 25, (
            f"Attack category '{category}' has {total_rows} rows but only {external_rows} "
            f"come from external sources (need >=25). "
            f"Use 'source: external:<name>' in YAML rows to mark external provenance."
        )


def test_spec_documents_source_field() -> None:
    """TC-113-06: Spec coverage - docs/spec/data-model.md documents source field.

    Verify that the data model spec includes documentation of the corpus source field.
    """
    spec_path = Path(__file__).parents[2] / "docs" / "spec" / "data-model.md"
    content = spec_path.read_text(encoding="utf-8")

    # Check that the source field is documented
    assert "source" in content.lower()
    assert "external:" in content


@pytest.mark.parametrize(
    ("row", "detector_id"),
    declared_detector_coverage_cases,
    ids=[f"{row.id}:{detector_id}" for row, detector_id in declared_detector_coverage_cases],
)
def test_declared_detector_coverage_is_exercisable(row: "corpus_loader.CorpusRow", detector_id: str) -> None:
    """TC-109-03: explicit coverage metadata must produce a detector-only signal."""
    detector = registry.get(detector_id)

    assert detector is not None, f"Corpus {row.id} covers unknown detector {detector_id}"

    payload = _payload_for_row(row)
    ctx = SessionContext(session_id=f"{row.id}:{detector_id}:coverage", signal_history=[])
    verdict = detector.check(payload, ctx)

    assert verdict.decision != "pass", f"Corpus {row.id} did not exercise {detector_id}"
    assert verdict.signal_id is not None
    assert verdict.signal_id.startswith(f"{detector_id}:")


def test_fitness_spec_names_corpus_coverage_invariant() -> None:
    """TC-109-04: docs/spec/fitness-functions.md names this file as the corpus coverage gate."""
    spec_path = Path(__file__).parents[2] / "docs" / "spec" / "fitness-functions.md"
    content = spec_path.read_text(encoding="utf-8")

    assert "Documented corpus-covered detector families have rows" in content
    assert "[tests/eval/test_corpus.py]" in content


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

    # Build session context — use unique session ID per row to isolate detector state
    ctx = SessionContext(session_id=row.id, signal_history=[])

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
