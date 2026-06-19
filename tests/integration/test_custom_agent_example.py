# SPDX-License-Identifier: Apache-2.0
"""Integration tests for examples/custom_agent.py (task 056).

Spec markers:
    TC-056-04 — --offline-smoke exits 0 in <10s
    TC-056-05 — --demo-attack injection blocks at the input layer
    TC-056-06 — --demo-attack path-traversal blocks at the tool layer
    TC-056-07 — --demo-attack canary-leak blocks at the output layer
"""

import subprocess
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
EXAMPLE = REPO_ROOT / "examples" / "custom_agent.py"


def _run(args: list[str], timeout: int = 15) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["uv", "run", "python", str(EXAMPLE), *args],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def test_tc_056_04_offline_smoke_exits_clean() -> None:
    """TC-056-04: --offline-smoke exits 0 within 10s."""
    t0 = time.monotonic()
    result = _run(["--offline-smoke"])
    elapsed = time.monotonic() - t0
    assert result.returncode == 0, (
        f"offline-smoke exited {result.returncode}\nstdout: {result.stdout}\nstderr: {result.stderr}"
    )
    assert elapsed < 10.0, f"offline-smoke too slow ({elapsed:.2f}s)"
    assert "PASSED" in result.stdout


def test_tc_056_05_injection_blocks_at_input_layer() -> None:
    """TC-056-05: --demo-attack injection exits non-zero with input-layer marker."""
    result = _run(["--demo-attack", "injection"])
    assert result.returncode != 0, "expected non-zero exit on injection attack"
    combined = (result.stdout + result.stderr).lower()
    assert "input" in combined, f"no input-layer marker in output: {combined!r}"


def test_tc_056_06_path_traversal_blocks_at_tool_layer() -> None:
    """TC-056-06: --demo-attack path-traversal exits non-zero with tool-layer marker."""
    result = _run(["--demo-attack", "path-traversal"])
    assert result.returncode != 0
    combined = (result.stdout + result.stderr).lower()
    assert "tool" in combined, f"no tool-layer marker in output: {combined!r}"


def test_tc_056_07_canary_leak_blocks_at_output_layer() -> None:
    """TC-056-07: --demo-attack canary-leak exits non-zero with output-layer marker."""
    result = _run(["--demo-attack", "canary-leak"])
    assert result.returncode != 0
    combined = (result.stdout + result.stderr).lower()
    assert "output" in combined, f"no output-layer marker in output: {combined!r}"
