# SPDX-License-Identifier: Apache-2.0
"""Fitness check: corpus passes with ``ARMOR_DISABLE_LLM=true``.

Defends the invariant that static detectors alone catch all P0/P1 attacks. The
LLM is advisory; if it's disabled the rest of the system must still produce
the expected verdicts. The check is implemented by re-running the eval corpus
under ``ARMOR_DISABLE_LLM=true`` and asserting the suite still passes.

Spec markers:
    TC-021-04 — static corpus passes with ``ARMOR_DISABLE_LLM=true``.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
CORPUS_SUITE = "tests/eval/test_corpus.py"


@pytest.mark.slow
def test_corpus_passes_with_llm_disabled() -> None:
    """TC-021-04: static-only corpus run produces every expected verdict."""
    env = os.environ.copy()
    env["ARMOR_DISABLE_LLM"] = "true"
    result = subprocess.run(
        ["uv", "run", "pytest", CORPUS_SUITE, "-v", "--tb=short", "-p", "no:cacheprovider"],
        env=env,
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=900,
    )
    assert result.returncode == 0, (
        "Corpus failed under ARMOR_DISABLE_LLM=true (static detectors must cover all P0/P1).\n"
        f"stdout:\n{result.stdout}\n"
        f"stderr:\n{result.stderr}"
    )
