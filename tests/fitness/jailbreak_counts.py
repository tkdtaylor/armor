#!/usr/bin/env python3
"""Fitness function: jailbreak.template detector corpus counts.

Asserts that the jailbreak.yaml corpus has:
- ≥30 true positives (TPs: rows where static_only_expected == "block")
- ≥15 true negatives (TNs: rows where static_only_expected == "pass")
- Each family has ≥3 TPs and ≥1 TN
"""

import sys
from pathlib import Path

import yaml


def main() -> int:
    """Run fitness check for jailbreak corpus."""
    corpus_file = Path(__file__).parent.parent / "eval" / "corpus" / "jailbreak.yaml"

    if not corpus_file.exists():
        print(f"ERROR: Corpus file not found: {corpus_file}")
        return 1

    with open(corpus_file) as f:
        corpus = yaml.safe_load(f)

    if not isinstance(corpus, list):
        print("ERROR: Corpus must be a YAML list")
        return 1

    # Count TPs, TNs, and per-family breakdown
    # TPs are rows where jailbreak pattern is detected (block or advisory, not pass)
    # TNs are rows where no pattern is detected (pass)
    tps = []  # Block or advisory expected rows (detected)
    tns = []  # Pass expected rows (benign)
    family_counts = {}  # family -> {tp_count, tn_count}

    for row in corpus:
        if not isinstance(row, dict):
            continue

        row_id = row.get("id", "unknown")
        family = row.get("family", "other")
        expected_verdict = row.get("expected_verdict", "pass")

        if family not in family_counts:
            family_counts[family] = {"tp": 0, "tn": 0}

        # TP: detected (block or advisory), TN: not detected (pass)
        if expected_verdict in ("block", "advisory"):
            tps.append(row_id)
            family_counts[family]["tp"] += 1
        elif expected_verdict == "pass":
            tns.append(row_id)
            family_counts[family]["tn"] += 1

    # Report counts
    print("Jailbreak corpus fitness check:")
    print(f"  Total TPs (block): {len(tps)}")
    print(f"  Total TNs (pass):  {len(tns)}")
    print()
    print("Per-family breakdown:")
    for family in sorted(family_counts.keys()):
        counts = family_counts[family]
        print(f"  {family:25s} TP={counts['tp']:3d} TN={counts['tn']:3d}")
    print()

    # Check constraints
    passed = True
    if len(tps) < 30:
        print(f"ERROR: Need ≥30 TPs, got {len(tps)}")
        passed = False
    if len(tns) < 15:
        print(f"ERROR: Need ≥15 TNs, got {len(tns)}")
        passed = False

    # Check per-family constraints (skip 'benign' and 'other' families)
    jailbreak_families = {"dan", "developer-mode", "fictional-framing", "gradual-escalation"}
    for family in jailbreak_families:
        if family not in family_counts:
            print(f"ERROR: Family {family} not found in corpus")
            passed = False
            continue
        counts = family_counts[family]
        if counts["tp"] < 3:
            print(f"ERROR: Family {family} needs ≥3 TPs, got {counts['tp']}")
            passed = False
        if counts["tn"] < 1:
            print(f"ERROR: Family {family} needs ≥1 TN, got {counts['tn']}")
            passed = False

    if passed:
        print("✓ All fitness checks passed")
        return 0
    else:
        print("✗ Some fitness checks failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
