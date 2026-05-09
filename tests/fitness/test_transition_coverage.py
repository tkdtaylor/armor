"""Fitness check: session state machine transition coverage.

Per ADR-024, every reachable transition of the session state machine must
appear in at least one row of ``tests/eval/corpus/scenarios_multi_turn.yaml``.
This guards against the multi-turn corpus drifting away from the state machine
as new rungs or step-back edges are added.

Spec markers:
    TC-025-12 — every apply_signal-reachable transition appears in ≥1 corpus row.
    TC-025-13 — failing fitness when a transition is uncovered.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]


def _load_corpus_loader():
    """Import the corpus loader by file path (it lives outside any package)."""
    loader_path = REPO_ROOT / "tests" / "eval" / "corpus" / "_loader.py"
    spec = importlib.util.spec_from_file_location("corpus_loader", loader_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _reachable_transitions() -> set[tuple[str, str]]:
    """Return the set of state transitions reachable from ``apply_signal``.

    Source: ADR-024 transition table.
    """
    return {
        # Forward single-rung
        ("Normal", "Watching"),
        ("Watching", "Elevated"),
        ("Elevated", "High"),
        # Multi-rung forward (high-confidence advisories)
        ("Normal", "Elevated"),
        ("Normal", "High"),
        ("Watching", "High"),
        # Cooldown step-back (one rung per call)
        ("Watching", "Normal"),
        ("Elevated", "Watching"),
        ("High", "Elevated"),
        # Block jumps from any non-Blocked state
        ("Normal", "Blocked"),
        ("Watching", "Blocked"),
        ("Elevated", "Blocked"),
        ("High", "Blocked"),
        # Blocked is sticky
        ("Blocked", "Blocked"),
    }


def _observed_transitions() -> set[tuple[str, str]]:
    """Walk ``scenarios_multi_turn.yaml`` and collect ``(prev_state, post_state)`` pairs."""
    loader = _load_corpus_loader()
    rows = loader.load_corpus("scenarios_multi_turn")

    observed: set[tuple[str, str]] = set()
    for row in rows:
        if not row.is_multi_turn() or not row.turns:
            continue
        previous_state = "Normal"
        for turn in row.turns:
            current_state = turn.expected_session_state
            observed.add((previous_state, current_state))
            previous_state = current_state
    return observed


@pytest.mark.smoke
def test_every_reachable_transition_is_exercised_by_corpus() -> None:
    """TC-025-12 / TC-025-13: every reachable transition shows up in the multi-turn corpus."""
    reachable = _reachable_transitions()
    observed = _observed_transitions()
    uncovered = reachable - observed
    assert not uncovered, (
        f"{len(uncovered)} reachable transition(s) absent from "
        f"scenarios_multi_turn.yaml:\n  "
        + "\n  ".join(f"{src} → {dst}" for src, dst in sorted(uncovered))
        + f"\nObserved {len(observed)} / {len(reachable)} transitions."
    )
