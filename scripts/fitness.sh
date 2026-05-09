#!/bin/bash
# Fitness checks for armor project architecture invariants.
#
# All checks are pytest tests under tests/fitness/. Discovery is the single
# source of truth: anything matching tests/fitness/test_*.py runs here, and
# every wired check has a matching row in docs/spec/fitness-functions.md
# (enforced by tests/fitness/test_fitness_spec_correspondence.py).
#
# Marker conventions (registered in pyproject.toml):
#   smoke         — fast checks (<5s each); included in `make fitness-smoke`
#   slow          — long-running checks (full LLM corpus, encryption round-trip);
#                   excluded from the default `make fitness` to keep CI snappy
#   requires_llm  — needs model weights present; cleanly skips otherwise
#
# Selector defaults to `not slow`. Override via:
#   ARMOR_FITNESS_SELECTOR='smoke'           → make fitness-smoke
#   ARMOR_FITNESS_SELECTOR=''                → make fitness-full (all markers)
#
# Exit code mirrors pytest's: 0 on success, non-zero on failure.

set -euo pipefail

cd "$(dirname "$0")/.."

if [[ -z "${ARMOR_FITNESS_SELECTOR+x}" ]]; then
    # Unset → default
    SELECTOR_ARGS=(-m "not slow")
elif [[ -z "${ARMOR_FITNESS_SELECTOR}" ]]; then
    # Empty string → no selector (run everything)
    SELECTOR_ARGS=()
else
    SELECTOR_ARGS=(-m "${ARMOR_FITNESS_SELECTOR}")
fi

exec uv run pytest tests/fitness/ -v --tb=short -p no:cacheprovider "${SELECTOR_ARGS[@]}"
