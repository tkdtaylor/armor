# SPDX-License-Identifier: Apache-2.0
"""Fitness checks for examples/custom_agent.py (task 056).

Spec markers:
    TC-056-01 — file exists and parses as Python
    TC-056-02 — only stdlib + armor + anthropic imports
    TC-056-03 — invokes check_input, check_tool*, check_output
    TC-056-08 — no real-shape canary strings without FAKE/EXAMPLE markers
    TC-056-09 — root README references the example
"""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
EXAMPLE = REPO_ROOT / "examples" / "custom_agent.py"


def test_tc_056_01_example_exists_and_parses() -> None:
    """TC-056-01: file exists and is valid Python."""
    assert EXAMPLE.exists(), f"missing {EXAMPLE}"
    ast.parse(EXAMPLE.read_text())


def test_tc_056_02_only_allowed_imports() -> None:
    """TC-056-02: only stdlib + armor + anthropic top-level imports."""
    text = EXAMPLE.read_text()
    tree = ast.parse(text)
    allowed = {"armor", "anthropic"}
    stdlib = set(sys.stdlib_module_names)

    for node in ast.walk(tree):
        names: list[str] = []
        if isinstance(node, ast.Import):
            names = [n.name.split(".")[0] for n in node.names]
        elif isinstance(node, ast.ImportFrom):
            if node.module is None:
                continue
            names = [node.module.split(".")[0]]
        else:
            continue

        for name in names:
            if name and name not in stdlib and name not in allowed:
                raise AssertionError(f"unexpected import {name!r} in custom_agent.py")


def test_tc_056_03_invokes_all_three_checkpoints() -> None:
    """TC-056-03: calls check_input, check_tool*, and check_output."""
    text = EXAMPLE.read_text()
    for needle in ("check_input", "check_tool", "check_output"):
        assert needle in text, f"example missing armor.{needle} call"


def test_tc_056_08_no_real_canary_strings() -> None:
    """TC-056-08: any AKIA-shaped string is clearly synthetic (FAKE/EXAMPLE)."""
    text = EXAMPLE.read_text()
    matches = re.findall(r"AKIA[A-Z0-9]{8,20}", text)
    for m in matches:
        assert "FAKE" in m or "EXAMPLE" in m, f"canary-shaped string lacks FAKE/EXAMPLE marker: {m}"


def test_tc_056_09_root_readme_references_example() -> None:
    """TC-056-09: project root README links to custom_agent.py."""
    text = (REPO_ROOT / "README.md").read_text()
    assert "examples/custom_agent.py" in text, "root README does not reference custom_agent.py"
