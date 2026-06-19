"""Fitness check: armor.spotlight package has no daemon/pipeline/detector imports.

Defends the isolation invariant from ADR-043 section 2: the spotlight annotator is
a pure library transform that must not import armor.pipeline, armor.daemon,
or armor.detectors. Importing armor.types (for Source) IS allowed.

Spec markers:
    TC-129-13 -- spotlight package imports no daemon, pipeline, or detector modules.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SPOTLIGHT_DIR = REPO_ROOT / "src" / "armor" / "spotlight"

BANNED_IMPORT_PREFIXES = [
    "armor.pipeline",
    "armor.daemon",
    "armor.detectors",
]


def _collect_imports(tree: ast.Module) -> list[str]:
    """Return all imported module names from an AST."""
    imported: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported.append(alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.append(node.module)
    return imported


def _scan_spotlight_for_banned_imports() -> list[tuple[str, str]]:
    """Return (rel_path, banned_module) pairs for any violations found."""
    violations: list[tuple[str, str]] = []

    if not SPOTLIGHT_DIR.is_dir():
        return violations

    for py_file in SPOTLIGHT_DIR.rglob("*.py"):
        source = py_file.read_text(encoding="utf-8")
        try:
            tree = ast.parse(source, filename=str(py_file))
        except SyntaxError:
            # If the file has a syntax error, skip it -- other tests will catch it.
            continue

        imports = _collect_imports(tree)
        rel_path = str(py_file.relative_to(REPO_ROOT))
        for imp in imports:
            for banned in BANNED_IMPORT_PREFIXES:
                if imp == banned or imp.startswith(banned + "."):
                    violations.append((rel_path, imp))

    return violations


@pytest.mark.smoke
def test_tc_129_13_spotlight_no_daemon_imports() -> None:
    """TC-129-13: spotlight package must not import armor.pipeline, armor.daemon, or armor.detectors."""
    assert SPOTLIGHT_DIR.is_dir(), f"spotlight directory not found: {SPOTLIGHT_DIR}"

    violations = _scan_spotlight_for_banned_imports()
    assert not violations, "Banned imports found in armor.spotlight:\n" + "\n".join(
        f"  {path} imports {mod}" for path, mod in violations
    )


def test_tc_129_13_spotlight_armor_types_allowed() -> None:
    """TC-129-13 (corollary): armor.types is allowed in spotlight -- verify it is importable."""
    # This just confirms the module exists and imports cleanly.
    from armor.types import Source

    assert Source.TOOL_RESULT_UNTRUSTED is not None
