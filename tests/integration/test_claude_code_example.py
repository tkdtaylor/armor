# SPDX-License-Identifier: Apache-2.0
"""Integration test for the examples/claude_code/ Claude Code hooks example (task 055).

Spec markers:
    TC-055-07 — examples/claude_code/demo.sh --offline-smoke exits 0 in <5s
    TC-055-10 — this test file exists and exercises the example
"""

import subprocess
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DEMO_SCRIPT = REPO_ROOT / "examples" / "claude_code" / "demo.sh"


def test_claude_code_offline_smoke_exits_clean() -> None:
    """TC-055-07: bash examples/claude_code/demo.sh --offline-smoke exits 0 within 5s."""
    assert DEMO_SCRIPT.exists(), f"demo script missing at {DEMO_SCRIPT}"

    t0 = time.monotonic()
    result = subprocess.run(
        ["bash", str(DEMO_SCRIPT), "--offline-smoke"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=10,
    )
    elapsed = time.monotonic() - t0

    assert result.returncode == 0, (
        f"offline-smoke exited {result.returncode}\nstdout: {result.stdout}\nstderr: {result.stderr}"
    )
    assert elapsed < 5.0, f"offline-smoke too slow ({elapsed:.2f}s); target <5s"
    assert "PASSED" in result.stdout, f"offline-smoke did not print PASSED: {result.stdout}"
