# SPDX-License-Identifier: Apache-2.0
"""Integration tests for SDK examples.

Tests TC-026-12, TC-026-13, TC-026-14: Examples run offline without errors.

These tests verify that the example scripts are importable and executable
as smoke tests using the --offline-smoke flag.
"""

import subprocess
import sys
from pathlib import Path


class TestExamples:
    """Tests for example scripts."""

    def test_anthropic_example_offline_smoke(self):
        """TC-026-12: anthropic_sdk.py smoke test runs successfully."""
        example_path = Path(__file__).parent.parent.parent / "examples" / "anthropic_sdk.py"

        result = subprocess.run(
            [sys.executable, str(example_path), "--offline-smoke"],
            capture_output=True,
            text=True,
            timeout=10,
        )

        assert result.returncode == 0, f"stdout: {result.stdout}\nstderr: {result.stderr}"

    def test_openai_example_offline_smoke(self):
        """TC-026-13: openai_sdk.py smoke test runs successfully."""
        example_path = Path(__file__).parent.parent.parent / "examples" / "openai_sdk.py"

        result = subprocess.run(
            [sys.executable, str(example_path), "--offline-smoke"],
            capture_output=True,
            text=True,
            timeout=10,
        )

        assert result.returncode == 0, f"stdout: {result.stdout}\nstderr: {result.stderr}"

    def test_langchain_example_offline_smoke(self):
        """TC-026-14: langchain.py smoke test runs successfully."""
        example_path = Path(__file__).parent.parent.parent / "examples" / "langchain.py"

        result = subprocess.run(
            [sys.executable, str(example_path), "--offline-smoke"],
            capture_output=True,
            text=True,
            timeout=10,
        )

        assert result.returncode == 0, f"stdout: {result.stdout}\nstderr: {result.stderr}"
