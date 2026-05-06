"""Fitness check: Validator soft-fails to advisory(confidence=0) on timeout.

TC-021-01: Validator timeout returns advisory(confidence=0)
TC-021-09: LLMSession stores validator_budget_ms

This test runs the unit test suite in tests/unit/llm/test_soft_fail.py
and asserts that the soft-fail tests pass.

Runs: pytest tests/unit/llm/test_soft_fail.py -v
Expects: Exit code 0 (all soft-fail tests pass)
"""

import subprocess
import sys


def check_validator_soft_fail() -> bool:
    """Run the soft-fail unit tests; assert they pass.

    Returns:
        True if all soft-fail tests pass, False otherwise.
    """
    result = subprocess.run(
        ["uv", "run", "pytest", "tests/unit/llm/test_soft_fail.py", "-v"],
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        print("FAIL: Soft-fail tests did not pass")
        print("\nStdout:")
        print(result.stdout)
        print("\nStderr:")
        print(result.stderr)
        return False

    print("PASS: Validator soft-fail tests passed")
    return True


if __name__ == "__main__":
    if not check_validator_soft_fail():
        sys.exit(1)
