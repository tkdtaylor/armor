"""Generate canary values for the catalogue at install time.

This module generates fresh, deterministic canary values given a seed
(or randomized if no seed is provided). Values are written to a file
that the daemon reads at boot time.

The generator reads the bundled schema (which contains no values),
generates a fresh value for each active canary using its marker_rule
as the shape constraint, and writes both schema and values to a file
that the daemon can load.
"""

import json
import logging
import os
import random
import re
import string
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def _generate_value_for_pattern(marker_rule: str) -> str:
    """Generate a fake-but-realistic value matching a given regex pattern.

    Supports common credential and identifier patterns. For unknown patterns,
    raises an error rather than silently returning a placeholder.

    Args:
        marker_rule: Regex pattern that the generated value must match.

    Returns:
        A string matching the pattern.

    Raises:
        ValueError: If the pattern is not recognized or generation fails.
    """
    # AWS access keys: AKIA + 16 chars [A-Z0-9]
    if marker_rule == r"^AKIA[A-Z0-9]{16}$":
        return "AKIA" + "".join(random.choice(string.ascii_uppercase + string.digits) for _ in range(16))

    # GitHub PATs: ghp_ + 36 chars [A-Za-z0-9]
    if marker_rule == r"^ghp_[A-Za-z0-9]{36}$":
        return "ghp_" + "".join(random.choice(string.ascii_letters + string.digits) for _ in range(36))

    # Stripe live keys: sk_live_ + 24 chars [A-Za-z0-9]
    if marker_rule == r"^sk_live_[A-Za-z0-9]{24}$":
        return "sk_live_" + "".join(random.choice(string.ascii_letters + string.digits) for _ in range(24))

    # Fake URLs: https://canary.armor-trap.invalid/<id>
    if marker_rule == r"^https://canary\.armor-trap\.invalid/[a-z0-9\-]+$":
        suffix = "".join(random.choice(string.ascii_lowercase + string.digits + "-") for _ in range(12))
        return f"https://canary.armor-trap.invalid/{suffix}"

    # Fake paths: /etc/armor-canary-<id>.pem
    if marker_rule == r"^/etc/armor-canary-[a-z0-9\-]+\.pem$":
        suffix = "".join(random.choice(string.ascii_lowercase + string.digits + "-") for _ in range(12))
        return f"/etc/armor-canary-{suffix}.pem"

    # Fake hostnames: <id>.canary.armor-trap.invalid
    if marker_rule == r"^[a-z0-9\-]+\.canary\.armor-trap\.invalid$":
        prefix = "".join(random.choice(string.ascii_lowercase + string.digits + "-") for _ in range(12))
        return f"{prefix}.canary.armor-trap.invalid"

    # Fake email addresses: canary-<id>@armor-trap.invalid
    if marker_rule == r"^canary-[a-z0-9\-]+@armor-trap\.invalid$":
        suffix = "".join(random.choice(string.ascii_lowercase + string.digits + "-") for _ in range(12))
        return f"canary-{suffix}@armor-trap.invalid"

    # Fake wallet addresses: 1ARMORTRAP + 32 hex chars
    if marker_rule == r"^1ARMORTRAP[0-9a-f]{32}$":
        hex_part = "".join(random.choice(string.hexdigits[:-6]) for _ in range(32))
        return f"1ARMORTRAP{hex_part}"

    # Fallback: try to generate a value that matches the regex
    # This is a best-effort approach for patterns we don't recognize
    raise ValueError(f"Don't know how to generate a value for pattern: {marker_rule}")


def generate_values(
    schema_path: str | Path,
    seed: int | None = None,
) -> list[dict[str, Any]]:
    """Generate values for all active canaries in the schema.

    Args:
        schema_path: Path to the bundled catalogue schema (JSON with no values).
        seed: Optional seed for deterministic generation. If None, uses OS RNG.

    Returns:
        List of dicts with {canary_id, value} for each active canary.

    Raises:
        FileNotFoundError: If schema file not found.
        ValueError: If schema is invalid or a value cannot be generated.
    """
    schema_path = Path(schema_path) if isinstance(schema_path, str) else schema_path

    if not schema_path.exists():
        raise FileNotFoundError(f"Schema file not found: {schema_path}")

    # Set seed if provided
    if seed is not None:
        random.seed(seed)

    # Load schema
    with open(schema_path, encoding="utf-8") as f:
        schema = json.load(f)

    if not isinstance(schema, list):
        raise ValueError("Schema must be a JSON array")

    # Generate values for active canaries
    values: list[dict[str, Any]] = []
    for entry in schema:
        if not entry.get("active", True):
            continue

        canary_id = entry.get("canary_id")
        marker_rule = entry.get("marker_rule")

        if not canary_id or not marker_rule:
            raise ValueError("Invalid schema entry: missing canary_id or marker_rule")

        try:
            value = _generate_value_for_pattern(marker_rule)
        except ValueError as e:
            raise ValueError(f"Failed to generate value for {canary_id}: {e}") from e

        # Validate the generated value matches the pattern
        try:
            if not re.match(marker_rule, value):
                raise ValueError("Generated value does not match pattern")
        except re.error as e:
            raise ValueError(f"Invalid marker_rule regex: {e}") from e

        values.append({"canary_id": canary_id, "value": value})

    if not values:
        raise ValueError("No active canaries in schema")

    return values


def write_values_file(
    output_path: str | Path,
    schema_path: str | Path,
    seed: int | None = None,
) -> None:
    """Generate and write canary values to a file.

    The output file contains the full catalogue (schema + generated values).
    File is written with mode 0o600 (read/write owner only).

    Args:
        output_path: Path where the values file should be written.
        schema_path: Path to the bundled catalogue schema.
        seed: Optional seed for deterministic generation.

    Raises:
        FileNotFoundError: If schema file not found.
        ValueError: If schema is invalid or generation fails.
        IOError: If output file cannot be written.
    """
    output_path = Path(output_path) if isinstance(output_path, str) else output_path
    schema_path = Path(schema_path) if isinstance(schema_path, str) else schema_path

    # Generate values
    values_list = generate_values(schema_path, seed)

    # Load schema to merge
    with open(schema_path, encoding="utf-8") as f:
        schema = json.load(f)

    # Create value lookup
    values_by_id = {v["canary_id"]: v["value"] for v in values_list}

    # Merge schema with values
    merged = []
    for entry in schema:
        merged_entry = entry.copy()
        canary_id = entry.get("canary_id")
        if canary_id in values_by_id:
            merged_entry["value"] = values_by_id[canary_id]
        merged.append(merged_entry)

    # Write output file with restricted permissions
    # Use os.open to ensure mode is set atomically
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(output_path), os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(merged, f, indent=2)
    except Exception:
        # If write fails, close the fd
        os.close(fd)
        raise

    logger.info(f"Wrote {len(merged)} canaries to {output_path} (mode 0o600)")
