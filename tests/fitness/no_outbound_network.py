"""Fitness check: armor daemon has no outbound network imports.

Exit code 0 if clean, non-zero if violations found.
"""

import sys
from pathlib import Path

# Banned imports in src/armor/daemon/
BANNED_IMPORTS = ["requests", "httpx", "urllib3", "http.client", "socket", "urllib"]


def check_daemon_imports() -> bool:
    """Scan daemon source for banned network imports.

    Returns:
        True if clean, False if violations found.
    """
    daemon_dir = Path(__file__).parent.parent.parent / "src" / "armor" / "daemon"

    if not daemon_dir.exists():
        print(f"Error: daemon directory not found: {daemon_dir}", file=sys.stderr)
        return False

    violations = []

    for py_file in daemon_dir.rglob("*.py"):
        with open(py_file) as f:
            content = f.read()
            lines = content.split("\n")

        for line_no, line in enumerate(lines, 1):
            # Skip comments
            code_part = line.split("#")[0].strip()
            if not code_part:
                continue

            # Check for import statements
            if code_part.startswith("import ") or code_part.startswith("from "):
                for banned in BANNED_IMPORTS:
                    # Match "import requests", "from requests", "import requests as", etc.
                    if f"import {banned}" in code_part or f"from {banned}" in code_part:
                        rel_path = py_file.relative_to(daemon_dir.parent.parent.parent)
                        violations.append((str(rel_path), line_no, banned, code_part))

    if violations:
        print("ERROR: Found banned network imports in daemon code:", file=sys.stderr)
        for path, line_no, module, line in violations:
            print(f"  {path}:{line_no} — {module}", file=sys.stderr)
            print(f"    {line}", file=sys.stderr)
        return False

    print("OK: No banned network imports found in daemon code.")
    return True


if __name__ == "__main__":
    sys.exit(0 if check_daemon_imports() else 1)
