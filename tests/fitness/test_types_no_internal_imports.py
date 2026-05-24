"""Fitness check: types.py has no internal armor imports.

Per the dependency hierarchy, src/armor/types.py must not import
from any armor.* module to prevent circular dependencies. It can
import from stdlib and third-party packages only.

Spec markers:
    TC-127-02 — types.py has no internal imports.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
TYPES_PATH = REPO_ROOT / "src" / "armor" / "types.py"


class _InternalImportChecker(ast.NodeVisitor):
    def __init__(self) -> None:
        self.violations: list[str] = []
        self.in_type_checking_block = False

    def visit_If(self, node: ast.If) -> None:
        """Detect TYPE_CHECKING blocks."""
        # Check if this is an "if TYPE_CHECKING:" block
        is_type_checking = False
        if isinstance(node.test, ast.Name) and node.test.id == "TYPE_CHECKING":
            is_type_checking = True

        if is_type_checking:
            # Temporarily allow armor imports inside TYPE_CHECKING
            old_state = self.in_type_checking_block
            self.in_type_checking_block = True
            self.generic_visit(node)
            self.in_type_checking_block = old_state
        else:
            self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Check 'from X import Y' statements."""
        # Skip armor imports inside TYPE_CHECKING blocks (they're compile-time only)
        if not self.in_type_checking_block and node.module and node.module.startswith("armor."):
            self.violations.append(f"line {node.lineno}: from {node.module} import ...")
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        """Check 'import X' statements."""
        # Skip armor imports inside TYPE_CHECKING blocks
        if not self.in_type_checking_block:
            for alias in node.names:
                if alias.name.startswith("armor."):
                    self.violations.append(f"line {node.lineno}: import {alias.name}")
        self.generic_visit(node)


@pytest.mark.smoke
def test_types_has_no_internal_imports() -> None:
    """TC-127-02: AST scan rejects internal armor imports in types.py."""
    assert TYPES_PATH.is_file(), f"types.py not found at {TYPES_PATH}"

    try:
        tree = ast.parse(TYPES_PATH.read_text(encoding="utf-8"))
    except SyntaxError as e:
        pytest.fail(f"types.py has syntax error: {e}")

    checker = _InternalImportChecker()
    checker.visit(tree)

    assert not checker.violations, "types.py has internal armor imports:\n  " + "\n  ".join(checker.violations)
