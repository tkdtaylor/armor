"""Fitness checks for the examples/claude_code/ integration example (task 055).

Spec markers:
    TC-055-01 — settings.json exists and is valid JSON
    TC-055-02 — wires UserPromptSubmit / PreToolUse / PostToolUse / Stop
    TC-055-03 — every hook command starts with `armor `
    TC-055-04 — README.md exists with the four required topic markers
    TC-055-05 — README.md is ≤120 lines
    TC-055-06 — demo.sh exists, is executable, supports --offline-smoke
    TC-055-08 — root README links to examples/claude_code
"""

from __future__ import annotations

import json
import os
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
EX_DIR = REPO_ROOT / "examples" / "claude_code"


def test_tc_055_01_settings_json_valid() -> None:
    """TC-055-01: settings.json parses as JSON."""
    p = EX_DIR / "settings.json"
    assert p.exists(), f"missing {p}"
    data = json.loads(p.read_text())
    assert isinstance(data, dict)


def test_tc_055_02_wires_all_four_hooks() -> None:
    """TC-055-02: hooks dict contains the four lifecycle events."""
    data = json.loads((EX_DIR / "settings.json").read_text())
    hooks = data.get("hooks", {})
    for event in ("UserPromptSubmit", "PreToolUse", "PostToolUse", "Stop"):
        assert event in hooks, f"settings.json missing hook for {event}"


def test_tc_055_03_every_command_invokes_armor() -> None:
    """TC-055-03: every hook command begins with `armor `."""
    data = json.loads((EX_DIR / "settings.json").read_text())
    for event, entries in data.get("hooks", {}).items():
        for entry in entries:
            for hook in entry.get("hooks", []):
                cmd = hook.get("command", "")
                assert cmd.startswith("armor "), f"{event}: command does not invoke armor: {cmd!r}"


def test_tc_055_04_readme_has_required_topics() -> None:
    """TC-055-04: README references settings.json + each hook event + exit code."""
    p = EX_DIR / "README.md"
    assert p.exists(), f"missing {p}"
    text = p.read_text().lower()
    for needle in ("settings.json", "userpromptsubmit", "pretooluse", "posttooluse", "stop", "exit code"):
        assert needle in text, f"README missing reference to {needle!r}"


def test_tc_096_06_readme_has_real_session_verification_anchor() -> None:
    """TC-096-06: README records the agent versions used for real-session verification."""
    text = (EX_DIR / "README.md").read_text()
    assert "Last verified hook integration:" in text
    assert "Claude Code" in text
    assert "Codex CLI" in text


def test_tc_055_05_readme_length_under_120_lines() -> None:
    """TC-055-05: README is ≤120 lines."""
    text = (EX_DIR / "README.md").read_text()
    n = len(text.splitlines())
    assert n <= 120, f"README too long ({n} lines); target is ≤120"


def test_tc_055_06_demo_sh_exists_executable_and_supports_offline_smoke() -> None:
    """TC-055-06: demo.sh exists, is executable, and supports --offline-smoke."""
    p = EX_DIR / "demo.sh"
    assert p.exists(), f"missing {p}"
    assert os.access(p, os.X_OK), "demo.sh is not executable"
    assert "--offline-smoke" in p.read_text(), "demo.sh does not handle --offline-smoke"


def test_tc_055_08_root_readme_links_to_example() -> None:
    """TC-055-08: project root README references examples/claude_code/."""
    text = (REPO_ROOT / "README.md").read_text()
    assert "examples/claude_code" in text, "root README does not link to examples/claude_code"
