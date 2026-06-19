# SPDX-License-Identifier: Apache-2.0
"""Fitness checks for task 045 — AWS-shape canary fixture replacement.

This module encodes the AWS-shaped canary replacement audit as a runnable
assertion that prevents re-introduction of unannotated AWS-shape literals.

Spec markers:
    TC-045-01 — No unannotated AKIA[A-Z0-9]{16} literals in tests/
"""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TESTS = ROOT / "tests"
ALLOW_LITERAL = "AKIAIOSFODNN7EXAMPLE"


def test_no_unannotated_aws_shape_canaries():
    """TC-045-01: No unannotated AWS-shape canaries in test fixtures.

    Verify that all AWS-shaped literals (AKIA[A-Z0-9]{16}) are either:
    - The AWS-published example AKIAIOSFODNN7EXAMPLE, or
    - Accompanied by a comment explaining why the shape must be kept.
    """
    pat = re.compile(r"\bAKIA[A-Z0-9]{16}\b")
    violations = []

    for p in TESTS.rglob("*.py"):
        lines = p.read_text().splitlines()
        for i, line in enumerate(lines):
            for m in pat.finditer(line):
                tok = m.group(0)
                if tok == ALLOW_LITERAL:
                    continue
                # Check up to 2 lines before for annotation
                ctx = "\n".join(lines[max(0, i - 2) : i + 1])
                if "AWS-shape required" not in ctx and "honeypot" not in ctx.lower():
                    violations.append(f"{p.relative_to(ROOT)}:{i + 1}: {tok}")

    assert violations == [], f"Found {len(violations)} unannotated AWS-shape canaries:\n" + "\n".join(violations)


# TC-045-02: All affected tests still pass (operator-verified at completion)
# TC-045-03: make check passes (operator-verified at completion)
