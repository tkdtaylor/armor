# SPDX-License-Identifier: Apache-2.0
"""Fitness check: validator module has no canary value access.

Per ADR-021, ``src/armor/llm/validator.py`` must not call
``catalogue.values()`` or read the ``.value`` attribute of catalogue entries.
Canary values flow only through the honeypot path; the validator path stays
value-blind so its prompt cannot be tricked into echoing a value.

Spec markers:
    TC-019-02 — validator never reads canary values.
    TC-091-15 — AST scan still fires after the consolidation.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
VALIDATOR_PATH = REPO_ROOT / "src" / "armor" / "llm" / "validator.py"


class _CanaryValueAccessChecker(ast.NodeVisitor):
    def __init__(self) -> None:
        self.violations: list[str] = []

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if isinstance(node.value, ast.Name) and node.value.id == "catalogue" and node.attr == "values":
            self.violations.append(f"line {node.lineno}: catalogue.values()")
        if node.attr == "value" and isinstance(node.value, ast.Name) and node.value.id in ("entry", "canary"):
            self.violations.append(f"line {node.lineno}: {node.value.id}.value")
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        if (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "catalogue"
            and node.func.attr == "values"
        ):
            self.violations.append(f"line {node.lineno}: catalogue.values() call")
        self.generic_visit(node)


@pytest.mark.smoke
def test_validator_does_not_read_canary_values() -> None:
    """TC-019-02 / TC-091-15: AST scan rejects catalogue.values() and entry.value access."""
    assert VALIDATOR_PATH.is_file(), f"validator.py not found at {VALIDATOR_PATH}"
    tree = ast.parse(VALIDATOR_PATH.read_text(encoding="utf-8"))
    checker = _CanaryValueAccessChecker()
    checker.visit(tree)
    assert not checker.violations, "Validator reads canary values:\n  " + "\n  ".join(checker.violations)
