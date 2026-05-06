"""Fitness check: session state machine transition coverage.

TC-025-12: Every apply_signal-reachable transition appears in ≥1 corpus row
TC-025-13: Failing fitness when a transition is uncovered

This script enumerates all reachable state transitions from the session state machine
(defined in src/armor/session/state_machine.py) and verifies that the multi-turn corpus
(tests/eval/corpus/scenarios_multi_turn.yaml) exercises every transition.

Exit code 0 iff all transitions are covered; non-zero with a list of uncovered transitions
otherwise.
"""

import importlib.util
import sys
from pathlib import Path

# Load the corpus loader
_loader_path = Path(__file__).parent.parent / "eval" / "corpus" / "_loader.py"
spec = importlib.util.spec_from_file_location("corpus_loader", _loader_path)
assert spec is not None and spec.loader is not None
corpus_loader = importlib.util.module_from_spec(spec)
spec.loader.exec_module(corpus_loader)

load_corpus = corpus_loader.load_corpus


def get_all_reachable_transitions() -> set[tuple[str, str]]:
    """Return the set of all apply_signal-reachable state transitions.

    Based on ADR-024, the reachable transitions are:
    - Forward edges: Normal → Watching, Watching → Elevated, Elevated → High
    - Multi-rung forward: Normal → Elevated, Normal → High, Watching → High
    - Cooldown step-back (one rung per call):
      - Watching → Normal
      - Elevated → Watching
      - High → Elevated
    - Block jumps: any state → Blocked
    - Blocked stickiness: Blocked → Blocked

    Returns:
        Set of (from_state, to_state) tuples.
    """
    transitions = set()

    # Forward single-rung transitions
    transitions.add(("Normal", "Watching"))
    transitions.add(("Watching", "Elevated"))
    transitions.add(("Elevated", "High"))

    # Multi-rung forward transitions (high-confidence advisories)
    transitions.add(("Normal", "Elevated"))
    transitions.add(("Normal", "High"))
    transitions.add(("Watching", "High"))

    # Cooldown step-back (one rung per call)
    transitions.add(("Watching", "Normal"))
    transitions.add(("Elevated", "Watching"))
    transitions.add(("High", "Elevated"))

    # Block jumps (any non-Blocked state to Blocked)
    transitions.add(("Normal", "Blocked"))
    transitions.add(("Watching", "Blocked"))
    transitions.add(("Elevated", "Blocked"))
    transitions.add(("High", "Blocked"))

    # Blocked stickiness
    transitions.add(("Blocked", "Blocked"))

    return transitions


def extract_transitions_from_corpus() -> set[tuple[str, str]]:
    """Extract observed state transitions from the multi-turn corpus.

    Walks through scenarios_multi_turn.yaml and builds the set of observed
    transitions. Sessions start in Normal state; each transition is from one
    turn's post-state to the next turn's post-state.

    Returns:
        Set of (from_state, to_state) tuples observed in the corpus.
    """
    observed = set()

    try:
        rows = load_corpus("scenarios_multi_turn")
    except Exception as e:
        print(f"ERROR: Failed to load corpus: {e}", file=sys.stderr)
        return observed

    for row in rows:
        if not row.is_multi_turn() or not row.turns:
            continue

        # Sessions start in Normal state
        previous_state = "Normal"

        # Extract transitions from initial state to first turn, and between turns
        for turn in row.turns:
            current_state = turn.expected_session_state
            observed.add((previous_state, current_state))
            previous_state = current_state

    return observed


def main() -> int:
    """Run the transition coverage check.

    Returns:
        0 if all transitions are covered; 1 if any are uncovered.
    """
    reachable = get_all_reachable_transitions()
    observed = extract_transitions_from_corpus()

    uncovered = reachable - observed

    if not uncovered:
        print("Transition coverage: OK (all reachable transitions exercised)")
        return 0

    # Report uncovered transitions
    print("Transition coverage: FAILED", file=sys.stderr)
    print(f"Uncovered transitions ({len(uncovered)}):", file=sys.stderr)
    for from_state, to_state in sorted(uncovered):
        print(f"  {from_state} → {to_state}", file=sys.stderr)
    print(f"\nObserved {len(observed)} / {len(reachable)} transitions", file=sys.stderr)

    return 1


if __name__ == "__main__":
    sys.exit(main())
