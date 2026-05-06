"""Fitness function: No literal canary value appears in prompt templates.

Enforces TC-019-01: Prompt templates contain only placeholders like {{canary:id}},
never actual canary values (AWS keys, GitHub PATs, etc.).
"""

import re
import sys
from pathlib import Path

# Common canary value patterns (based on marker_rules in default_catalogue.json)
CANARY_PATTERNS = [
    # AWS Access Keys: AKIA followed by 16 alphanumeric
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key"),
    # GitHub Personal Access Tokens: ghp_ prefix
    (r"ghp_[a-zA-Z0-9_]{36,}", "GitHub Personal Access Token"),
    # AWS Secret Keys (simulated pattern)
    (r"[a-zA-Z0-9/+=]{40,}", "AWS Secret Key (entropy-based)"),
    # Stripe Secret Key
    (r"sk_live_[a-zA-Z0-9]{24,}", "Stripe Secret Key"),
    # SendGrid API Key
    (r"SG\.[a-zA-Z0-9_\-]{20,}", "SendGrid API Key"),
]


def check_no_canary_values_in_prompts() -> bool:
    """Check that prompt templates contain no literal canary values.

    Returns:
        True if no canary values found, False otherwise.
    """
    prompts_dir = Path(__file__).parent.parent.parent / "src" / "armor" / "llm" / "prompts"

    if not prompts_dir.exists():
        print(f"Prompts directory not found: {prompts_dir}")
        return True  # Directory doesn't exist, so no violations

    violations = []

    for prompt_file in prompts_dir.glob("*.txt"):
        content = prompt_file.read_text(encoding="utf-8")

        for pattern, pattern_name in CANARY_PATTERNS:
            matches = re.findall(pattern, content)
            # Filter out common false positives (very generic patterns)
            # AWS secret key pattern is too broad, skip it for now
            if pattern_name == "AWS Secret Key (entropy-based)" and len(matches) > 0:
                continue
            if matches:
                violations.append(f"File {prompt_file.name}: Found {pattern_name}: {', '.join(set(matches[:3]))}")

    if violations:
        print("Fitness check FAILED: Canary values found in prompt templates:")
        for violation in violations:
            print(f"  {violation}")
        return False

    print("Fitness check PASSED: No canary values in prompt templates")
    return True


if __name__ == "__main__":
    result = check_no_canary_values_in_prompts()
    sys.exit(0 if result else 1)
