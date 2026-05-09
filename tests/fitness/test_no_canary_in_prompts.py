"""Fitness check: prompt templates contain no literal canary values.

Per ADR-021, prompt templates carry only ``{{canary:id}}`` placeholders, never
actual canary values (AWS keys, GitHub PATs, etc.). This guards against an
operator accidentally committing a real value into a template.

Spec markers:
    TC-019-01 — prompt templates contain only placeholders, never values.
    TC-091-13 — AST/regex scan over ``src/armor/llm/prompts/*.txt`` still rejects
                literal canary patterns after the consolidation.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
PROMPTS_DIR = REPO_ROOT / "src" / "armor" / "llm" / "prompts"

# Common canary value patterns (based on marker_rules in default_catalogue.json).
# AWS Secret Key entropy pattern is intentionally excluded (too broad → false positives).
CANARY_PATTERNS: list[tuple[str, str]] = [
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key"),
    (r"ghp_[a-zA-Z0-9_]{36,}", "GitHub Personal Access Token"),
    (r"sk_live_[a-zA-Z0-9]{24,}", "Stripe Secret Key"),
    (r"SG\.[a-zA-Z0-9_\-]{20,}", "SendGrid API Key"),
]


@pytest.mark.smoke
def test_prompt_templates_have_no_literal_canary_values() -> None:
    """TC-019-01 / TC-091-13: regex scan rejects literal canary patterns in prompt templates."""
    if not PROMPTS_DIR.exists():
        pytest.skip(f"prompts directory does not exist: {PROMPTS_DIR}")

    violations: list[str] = []
    for prompt_file in sorted(PROMPTS_DIR.glob("*.txt")):
        content = prompt_file.read_text(encoding="utf-8")
        for pattern, pattern_name in CANARY_PATTERNS:
            matches = re.findall(pattern, content)
            if matches:
                sample = ", ".join(sorted(set(matches[:3])))
                violations.append(f"{prompt_file.name}: {pattern_name}: {sample}")

    assert not violations, "Canary values found in prompt templates:\n  " + "\n  ".join(violations)
