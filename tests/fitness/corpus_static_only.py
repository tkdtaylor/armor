"""Fitness check: Corpus passes with ARMOR_DISABLE_LLM=true.

This verifies the invariant: static detectors alone catch all P0/P1 attacks.
The LLM is advisory; if disabled, the system should still function correctly
on the evaluation corpus.

Runs: ARMOR_DISABLE_LLM=true pytest tests/eval/test_corpus.py
Expects: Exit code 0 (all verdicts match expected)
"""

import os
import subprocess
import sys


def check_corpus_static_only() -> bool:
    """Run corpus evaluation with LLM disabled; assert all tests pass.

    Returns:
        True if all corpus tests pass with ARMOR_DISABLE_LLM=true, False otherwise.
    """
    env = os.environ.copy()
    env["ARMOR_DISABLE_LLM"] = "true"

    result = subprocess.run(
        ["uv", "run", "pytest", "tests/eval/test_corpus.py", "-v", "--tb=short"],
        env=env,
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        print("FAIL: Corpus tests failed with ARMOR_DISABLE_LLM=true")
        print("\nStdout:")
        print(result.stdout)
        print("\nStderr:")
        print(result.stderr)
        return False

    print("PASS: Static detectors alone pass all corpus tests")
    return True


if __name__ == "__main__":
    if not check_corpus_static_only():
        sys.exit(1)
