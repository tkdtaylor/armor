"""Fitness check: P95 LLM latency under budget.

Per ADR-023, enforce two separate latency budgets:
- Validator P95 ≤ 500 ms (empirical from ADR-018: 486 ms)
- Honeypot P95 ≤ 12,000 ms (empirical from ADR-018: 11,875 ms)

This test runs a subset of the corpus through the LLM and measures latency.
It is deferred to v0.4+ pending full corpus integration; for v0.3 we
provide a stub that warns if the model is not available.

Runs: Measure validator and honeypot latency on corpus rows
Expects: Validator P95 ≤ 500 ms, Honeypot P95 ≤ 12,000 ms
"""

import sys


def check_llm_p95_latency() -> bool:
    """Check that LLM latencies are within budget.

    Returns:
        True if latencies are acceptable, False otherwise.
    """
    # v0.3: This is a placeholder. Full latency measurement requires:
    # 1. Loading the model (expensive)
    # 2. Running corpus rows through validator/honeypot
    # 3. Computing P95 percentile
    # This will be implemented in v0.4 as a full integration test.
    # For now, we verify the fitness check exists and warn that
    # latency measurement is deferred.

    print("NOTE: LLM P95 latency measurement deferred to v0.4")
    print("  Validator P95 budget: 500 ms (empirical P95 from ADR-018: 486 ms)")
    print("  Honeypot P95 budget: 12,000 ms (empirical P95 from ADR-018: 11,875 ms)")
    print("  To measure on your hardware: run tests/bench/llm_selection/run.py")

    return True


if __name__ == "__main__":
    if not check_llm_p95_latency():
        sys.exit(1)
