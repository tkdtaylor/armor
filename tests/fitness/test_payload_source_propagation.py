"""Fitness check: every IPC op constructs ``Payload`` with the correct default source.

Per ADR-041 §1, the daemon's IPC routing must assign ``Payload.source`` from
the op name without expecting clients to supply it:

    check.input    → USER_INPUT
    check.output   → MODEL_OUTPUT
    check.tool     → TOOL_PARAMS
    check.fetched  → TOOL_RESULT_UNTRUSTED

Spec markers:
    TC-065-24 — Payload.source defaults match ADR-041 §1.
    TC-091-17 — propagation check still fires after the consolidation.
"""

from __future__ import annotations

from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SERVER_PATH = REPO_ROOT / "src" / "armor" / "daemon" / "server.py"

EXPECTED_SOURCES: dict[str, str] = {
    "check.input": "USER_INPUT",
    "check.output": "MODEL_OUTPUT",
    "check.tool": "TOOL_PARAMS",
    "check.fetched": "TOOL_RESULT_UNTRUSTED",
}


def _op_assigns_expected_source(server_text: str, op_name: str, expected_source: str) -> bool:
    """Return True if a Payload(..., source=Source.EXPECTED) appears near the op handler."""
    lines = server_text.splitlines()
    for i, line in enumerate(lines):
        if f'"{op_name}"' in line or f"'{op_name}'" in line or f"`{op_name}`" in line:
            context = "\n".join(lines[max(0, i - 10) : min(len(lines), i + 30)])
            if f"source=Source.{expected_source}" in context:
                return True
            if "Payload(" in context and f"Source.{expected_source}" in context:
                return True
    return False


@pytest.mark.smoke
def test_ipc_ops_assign_expected_payload_source() -> None:
    """TC-065-24 / TC-091-17: every IPC op sets the ADR-041 default source."""
    assert SERVER_PATH.is_file(), f"daemon/server.py not found: {SERVER_PATH}"
    server_text = SERVER_PATH.read_text(encoding="utf-8")
    violations: list[str] = []
    for op_name, expected_source in EXPECTED_SOURCES.items():
        if not _op_assigns_expected_source(server_text, op_name, expected_source):
            violations.append(f"{op_name} should set source=Source.{expected_source}")
    assert not violations, "Payload.source default mismatches:\n  " + "\n  ".join(violations)
