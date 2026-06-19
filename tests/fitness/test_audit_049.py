# SPDX-License-Identifier: Apache-2.0
"""Fitness audit for task 049: incidents export spec/code alignment.

Ensures that the spec documents `incidents export` if and only if the code
implements it (and vice versa).
"""

from pathlib import Path


def test_incidents_export_spec_code_alignment() -> None:
    """TC-049-01: Spec and code agree on whether `incidents export` exists."""
    repo_root = Path(__file__).parent.parent.parent

    # Check spec
    spec_path = repo_root / "docs" / "spec" / "interfaces.md"
    spec = spec_path.read_text()
    in_spec = "incidents export" in spec

    # Check code
    cli_path = repo_root / "src" / "armor" / "cli.py"
    cli = cli_path.read_text()
    in_code = "'export'" in cli or '"export"' in cli or 'add_parser("export"' in cli or "add_parser('export'" in cli

    # They must match
    assert in_spec == in_code, f"incidents export spec/code drift: spec={in_spec}, code={in_code}"
