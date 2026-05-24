"""Fitness check: detectors do not import each other.

Per the modularity design principle, detector modules must not import
sibling detectors or cross-reference each other. The __init__.py and
any future registry.py are exempt (they need to import detectors for
discovery and registration).

Spec markers:
    TC-127-01 — detectors have no cross-imports.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
DETECTORS_DIR = REPO_ROOT / "src" / "armor" / "detectors"


class _CrossImportChecker(ast.NodeVisitor):
    def __init__(self, current_file: str) -> None:
        self.current_file = current_file
        self.violations: list[str] = []
        # These are public utility functions exported for reuse by other detectors
        self._allowed_functions = {
            "get_compiled_patterns",
            "get_override_patterns",
            "get_extraction_patterns",
        }

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Check 'from X import Y' statements."""
        if node.module:
            # Check for absolute imports from armor.detectors
            if node.module.startswith("armor.detectors"):
                # Allow imports of specific public utility functions only
                imported_names = [alias.name for alias in node.names]
                disallowed = [name for name in imported_names if name not in self._allowed_functions]
                if disallowed:
                    self.violations.append(
                        f"line {node.lineno}: from {node.module} import {', '.join(disallowed)} (not public utilities)"
                    )
            # Check for relative imports from sibling detectors (e.g., from .sibling_detector import)
            elif node.level == 1 and node.module:
                # level=1 means single dot (from .X import)
                imported_names = [alias.name for alias in node.names]
                disallowed = [name for name in imported_names if name not in self._allowed_functions]
                if disallowed:
                    self.violations.append(
                        f"line {node.lineno}: from .{node.module} import {', '.join(disallowed)} (not public utilities)"
                    )
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        """Check 'import X' statements."""
        for alias in node.names:
            if alias.name.startswith("armor.detectors"):
                self.violations.append(f"line {node.lineno}: import {alias.name} (full module import not allowed)")
        self.generic_visit(node)


@pytest.mark.smoke
def test_detectors_do_not_cross_import() -> None:
    """TC-127-01: AST scan rejects detector-to-detector imports."""
    assert DETECTORS_DIR.is_dir(), f"detectors directory not found at {DETECTORS_DIR}"

    violations: list[str] = []

    for detector_file in sorted(DETECTORS_DIR.glob("*.py")):
        # Skip __init__.py and registry.py (they are allowed to import detectors)
        if detector_file.name in ("__init__.py", "registry.py"):
            continue

        try:
            tree = ast.parse(detector_file.read_text(encoding="utf-8"))
        except SyntaxError as e:
            violations.append(f"{detector_file.name}: syntax error: {e}")
            continue

        checker = _CrossImportChecker(detector_file.name)
        checker.visit(tree)

        if checker.violations:
            violations.extend([f"{detector_file.name}: {v}" for v in checker.violations])

    assert not violations, "Detectors cross-import each other:\n  " + "\n  ".join(violations)
