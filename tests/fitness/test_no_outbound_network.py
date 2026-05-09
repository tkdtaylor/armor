"""Fitness check: armor daemon has no outbound network imports.

Defends the SPEC.md "no-network" invariant for the daemon code path. Imports of
``requests``, ``httpx``, ``urllib3``, ``http.client``, ``socket``, or ``urllib``
under ``src/armor/daemon/`` fail this check. Telemetry / outbound-aware modules
must live outside the daemon tree.

Spec markers:
    TC-091-14 — daemon code path still rejected if it imports network modules.
"""

from __future__ import annotations

from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
DAEMON_DIR = REPO_ROOT / "src" / "armor" / "daemon"

BANNED_IMPORTS = ["requests", "httpx", "urllib3", "http.client", "socket", "urllib"]


def _scan_daemon_for_banned_imports() -> list[tuple[str, int, str, str]]:
    """Return a list of ``(rel_path, line_no, banned, source_line)`` violations."""
    violations: list[tuple[str, int, str, str]] = []
    for py_file in DAEMON_DIR.rglob("*.py"):
        text = py_file.read_text(encoding="utf-8")
        for line_no, line in enumerate(text.splitlines(), 1):
            code_part = line.split("#", 1)[0].strip()
            if not code_part or not (code_part.startswith("import ") or code_part.startswith("from ")):
                continue
            for banned in BANNED_IMPORTS:
                if f"import {banned}" in code_part or f"from {banned}" in code_part:
                    rel_path = str(py_file.relative_to(REPO_ROOT))
                    violations.append((rel_path, line_no, banned, code_part))
    return violations


@pytest.mark.smoke
def test_daemon_has_no_outbound_network_imports() -> None:
    """TC-091-14: daemon code path imports nothing that opens an outbound connection."""
    assert DAEMON_DIR.is_dir(), f"daemon directory not found: {DAEMON_DIR}"
    violations = _scan_daemon_for_banned_imports()
    assert not violations, "Banned network imports found in daemon code:\n" + "\n".join(
        f"  {path}:{line_no} — {module}\n    {line}" for path, line_no, module, line in violations
    )
