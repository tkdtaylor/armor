"""Fitness check: every IPC op constructs Payload with correct default source per ADR-041.

Exit code 0 if all ops set correct default sources, non-zero if violations found.

This is a standalone script (not a pytest test) that verifies the daemon's IPC
routing assigns Payload.source correctly per the defaults table in ADR-041 §1:
  - check.input → USER_INPUT
  - check.output → MODEL_OUTPUT
  - check.tool → TOOL_PARAMS
  - check.fetched → TOOL_RESULT_UNTRUSTED
"""

import sys
from pathlib import Path


def check_payload_source_defaults() -> bool:
    """Check that all IPC ops assign correct Payload.source defaults.

    Expected mapping per ADR-041 §1:
      - check.input → USER_INPUT
      - check.output → MODEL_OUTPUT
      - check.tool → TOOL_PARAMS
      - check.fetched → TOOL_RESULT_UNTRUSTED

    Returns:
        True if all ops are correct, False otherwise.
    """
    server_path = Path(__file__).parent.parent.parent / "src" / "armor" / "daemon" / "server.py"

    if not server_path.exists():
        print(f"Error: daemon/server.py not found: {server_path}", file=sys.stderr)
        return False

    with open(server_path) as f:
        server_content = f.read()

    # Expected source assignments per ADR-041 §1
    expected = {
        "check.input": "USER_INPUT",
        "check.output": "MODEL_OUTPUT",
        "check.tool": "TOOL_PARAMS",
        "check.fetched": "TOOL_RESULT_UNTRUSTED",
    }

    # For each op, search for the pattern in the source code
    violations = []

    for op_name, expected_source in expected.items():
        # Search for a pattern like:
        # source=Source.USER_INPUT or similar within the op handler
        if _check_op_has_source(server_content, op_name, expected_source):
            continue
        violations.append((op_name, expected_source))

    if violations:
        print(
            "ERROR: Found ops with incorrect or missing Payload.source defaults:",
            file=sys.stderr,
        )
        for op_name, expected_source in violations:
            print(
                f"  {op_name} should set source=Source.{expected_source}",
                file=sys.stderr,
            )
        return False

    print("OK: All IPC ops set correct Payload.source defaults per ADR-041 §1.")
    return True


def _check_op_has_source(source_code: str, op_name: str, expected_source: str) -> bool:
    """Check if an op handler assigns the expected Payload.source value.

    Args:
        source_code: Contents of server.py
        op_name: Operation name (e.g., "check.input")
        expected_source: Expected Source enum value (e.g., "USER_INPUT")

    Returns:
        True if the op correctly assigns the source, False otherwise.
    """
    # Find the handler function for this op
    # Pattern: usually there's a function that handles this op and constructs Payload

    # Look for any mention of Payload(..., source=Source.EXPECTED_SOURCE)
    # near the op_name string in the source code

    # Simple heuristic: search for the pattern in a context window around op_name
    lines = source_code.split("\n")

    for i, line in enumerate(lines):
        if f'"{op_name}"' in line or f"'{op_name}'" in line or f"`{op_name}`" in line:
            # Found a line mentioning the op; search in the surrounding context
            # for Payload with correct source
            context_start = max(0, i - 10)
            context_end = min(len(lines), i + 30)
            context = "\n".join(lines[context_start:context_end])

            # Check if this context contains Payload construction with the right source
            if f"source=Source.{expected_source}" in context or (
                "Payload(" in context and f"Source.{expected_source}" in context
            ):
                return True

    return False


if __name__ == "__main__":
    sys.exit(0 if check_payload_source_defaults() else 1)
