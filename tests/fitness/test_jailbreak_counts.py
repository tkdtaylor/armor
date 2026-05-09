"""Fitness check: ``jailbreak.yaml`` corpus carries the required TP/TN counts.

The jailbreak detector relies on broad family coverage in the corpus to keep
its false-positive rate honest. The corpus must hold at least:

- 30 true positives overall (rows where ``expected_verdict`` is ``block`` or
  ``advisory``);
- 15 true negatives overall (rows where ``expected_verdict == "pass"``);
- 3 TPs and 1 TN per known jailbreak family (DAN, developer-mode,
  fictional-framing, gradual-escalation).

Spec markers:
    TC-091-18 — jailbreak corpus TP/TN counts asserted post-consolidation.
"""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
CORPUS_FILE = REPO_ROOT / "tests" / "eval" / "corpus" / "jailbreak.yaml"

JAILBREAK_FAMILIES = {"dan", "developer-mode", "fictional-framing", "gradual-escalation"}


def _tally_corpus() -> tuple[list[str], list[str], dict[str, dict[str, int]]]:
    assert CORPUS_FILE.exists(), f"Corpus file not found: {CORPUS_FILE}"
    corpus = yaml.safe_load(CORPUS_FILE.read_text(encoding="utf-8"))
    assert isinstance(corpus, list), "Corpus must be a YAML list"

    tps: list[str] = []
    tns: list[str] = []
    family_counts: dict[str, dict[str, int]] = defaultdict(lambda: {"tp": 0, "tn": 0})

    for row in corpus:
        if not isinstance(row, dict):
            continue
        row_id = row.get("id", "unknown")
        family = row.get("family", "other")
        expected_verdict = row.get("expected_verdict", "pass")

        if expected_verdict in ("block", "advisory"):
            tps.append(row_id)
            family_counts[family]["tp"] += 1
        elif expected_verdict == "pass":
            tns.append(row_id)
            family_counts[family]["tn"] += 1

    return tps, tns, dict(family_counts)


@pytest.mark.smoke
def test_jailbreak_corpus_total_tp_count() -> None:
    """TC-091-18: ≥30 TPs in jailbreak.yaml."""
    tps, _, _ = _tally_corpus()
    assert len(tps) >= 30, f"Need ≥30 TPs, got {len(tps)}"


@pytest.mark.smoke
def test_jailbreak_corpus_total_tn_count() -> None:
    """TC-091-18: ≥15 TNs in jailbreak.yaml."""
    _, tns, _ = _tally_corpus()
    assert len(tns) >= 15, f"Need ≥15 TNs, got {len(tns)}"


@pytest.mark.smoke
def test_jailbreak_corpus_per_family_counts() -> None:
    """TC-091-18: each known family has ≥3 TPs and ≥1 TN."""
    _, _, family_counts = _tally_corpus()
    issues: list[str] = []
    for family in sorted(JAILBREAK_FAMILIES):
        if family not in family_counts:
            issues.append(f"family {family!r} missing from corpus")
            continue
        counts = family_counts[family]
        if counts["tp"] < 3:
            issues.append(f"family {family!r} needs ≥3 TPs, got {counts['tp']}")
        if counts["tn"] < 1:
            issues.append(f"family {family!r} needs ≥1 TN, got {counts['tn']}")
    assert not issues, "Jailbreak per-family coverage gaps:\n  " + "\n  ".join(issues)
