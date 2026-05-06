"""Fitness function: Validator module has no canary value access.

Enforces TC-019-02: src/armor/llm/validator.py contains zero references to
catalogue.values() or code paths that read actual canary values. This ensures
canary values flow ONLY through the honeypot path, never the validator path.
"""

import ast
import sys
from pathlib import Path


class CanaryValueAccessChecker(ast.NodeVisitor):
    """AST visitor to find references to canary value reading."""

    def __init__(self) -> None:
        """Initialize the checker."""
        self.violations: list[str] = []
        self.line_number = 0

    def visit_Attribute(self, node: ast.Attribute) -> None:
        """Check for .values() calls and .value field accesses."""
        # Check for catalogue.values()
        if isinstance(node.value, ast.Name) and node.value.id == "catalogue" and node.attr == "values":
            self.violations.append(f"Line {node.lineno}: Direct access to catalogue.values()")

        # Check for .value field access (excluding other objects)
        if node.attr == "value" and isinstance(node.value, ast.Name):
            if node.value.id == "entry":
                self.violations.append(f"Line {node.lineno}: Access to entry.value (canary value field)")
            elif node.value.id == "canary":
                self.violations.append(f"Line {node.lineno}: Access to canary.value (canary value field)")

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """Check for .values() method calls."""
        if (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "catalogue"
            and node.func.attr == "values"
        ):
            self.violations.append(f"Line {node.lineno}: Call to catalogue.values()")

        self.generic_visit(node)


def check_validator_no_value_access() -> bool:
    """Check that validator.py has no canary value access code paths.

    Returns:
        True if no violations found, False otherwise.
    """
    validator_file = Path(__file__).parent.parent.parent / "src" / "armor" / "llm" / "validator.py"

    if not validator_file.exists():
        print(f"Validator file not found: {validator_file}")
        return False

    try:
        content = validator_file.read_text(encoding="utf-8")
        tree = ast.parse(content)
    except SyntaxError as e:
        print(f"Fitness check FAILED: Syntax error in validator.py: {e}")
        return False

    checker = CanaryValueAccessChecker()
    checker.visit(tree)

    if checker.violations:
        print("Fitness check FAILED: Validator module reads canary values:")
        for violation in checker.violations:
            print(f"  {violation}")
        return False

    print("Fitness check PASSED: Validator module has no canary value access")
    return True


if __name__ == "__main__":
    result = check_validator_no_value_access()
    sys.exit(0 if result else 1)
