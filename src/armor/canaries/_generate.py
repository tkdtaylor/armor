"""Generate canary values for the catalogue at install time.

This module generates fresh, deterministic canary values given a seed
(or randomized if no seed is provided). Values are written to a file
that the daemon reads at boot time.

The generator reads the bundled schema (which contains no values),
generates a fresh value for each active canary using its marker_rule
as the shape constraint, and writes both schema and values to a file
that the daemon can load.
"""

import base64
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

    # OpenAI keys: sk- or sk-proj- + 43+ chars [A-Za-z0-9_-]
    if marker_rule == r"^sk-(proj-)?[A-Za-z0-9_-]{43,}$":
        suffix = "".join(random.choice(string.ascii_letters + string.digits + "_-") for _ in range(48))
        return f"sk-{suffix}"

    # Anthropic keys: sk-ant- + 86+ chars [a-zA-Z0-9_-]
    if marker_rule == r"^sk-ant-[a-zA-Z0-9_-]{86,}$":
        suffix = "".join(random.choice(string.ascii_letters + string.digits + "_-") for _ in range(90))
        return f"sk-ant-{suffix}"

    # Cohere keys: 36 chars [a-zA-Z0-9]
    if marker_rule == r"^[a-zA-Z0-9]{36}$":
        return "".join(random.choice(string.ascii_letters + string.digits) for _ in range(36))

    # HuggingFace tokens: hf_ + 35+ chars [A-Za-z0-9]
    if marker_rule == r"^hf_[A-Za-z0-9]{35,}$":
        suffix = "".join(random.choice(string.ascii_letters + string.digits) for _ in range(40))
        return f"hf_{suffix}"

    # GitLab PAT: glpat- + 20 chars [A-Za-z0-9_-]
    if marker_rule == r"^glpat-[A-Za-z0-9_-]{20}$":
        suffix = "".join(random.choice(string.ascii_letters + string.digits + "_-") for _ in range(20))
        return f"glpat-{suffix}"

    # Slack tokens: xox[bpoa]- + digits + digits + alphanumeric
    if marker_rule == r"^xox[bpoa]-[0-9]+-[0-9]+-[A-Za-z0-9_-]+$":
        kind = random.choice(["b", "p", "o", "a"])
        workspace_id = "".join(random.choice(string.digits) for _ in range(10))
        token_id = "".join(random.choice(string.digits) for _ in range(10))
        token_suffix = "".join(random.choice(string.ascii_letters + string.digits + "_-") for _ in range(24))
        return f"xox{kind}-{workspace_id}-{token_id}-{token_suffix}"

    # Discord tokens: 24 chars . 6 chars . 27 chars [A-Za-z0-9_-]
    if marker_rule == r"^[A-Za-z0-9_-]{24}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}$":
        part1 = "".join(random.choice(string.ascii_letters + string.digits + "_-") for _ in range(24))
        part2 = "".join(random.choice(string.ascii_letters + string.digits + "_-") for _ in range(6))
        part3 = "".join(random.choice(string.ascii_letters + string.digits + "_-") for _ in range(27))
        return f"{part1}.{part2}.{part3}"

    # Twilio keys: AC + 32 hex chars
    if marker_rule == r"^AC[a-z0-9]{32}$":
        suffix = "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(32))
        return f"AC{suffix}"

    # SendGrid keys: SG. + 66 chars [A-Za-z0-9_-]
    if marker_rule == r"^SG\.[A-Za-z0-9_-]{66}$":
        suffix = "".join(random.choice(string.ascii_letters + string.digits + "_-") for _ in range(66))
        return f"SG.{suffix}"

    # Google API keys: AIza + 35 chars [0-9A-Za-z_-]
    if marker_rule == r"^AIza[0-9A-Za-z_\-]{35}$":
        suffix = "".join(random.choice(string.ascii_letters + string.digits + "_-") for _ in range(35))
        return f"AIza{suffix}"

    # Firebase keys: 39 chars [A-Za-z0-9_-]
    if marker_rule == r"^[A-Za-z0-9_-]{39}$":
        return "".join(random.choice(string.ascii_letters + string.digits + "_-") for _ in range(39))

    # GCP service account email: <32 alphanumeric>-<20 alphanumeric>.iam.gserviceaccount.com
    if marker_rule == r"^[a-z0-9]{32}-[a-z0-9]{20}\.iam\.gserviceaccount\.com$":
        part1 = "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(32))
        part2 = "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(20))
        return f"{part1}-{part2}.iam.gserviceaccount.com"

    # Azure UUID format: 8-4-4-4-12
    if marker_rule == r"^[a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12}$":
        parts = [
            "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(8)),
            "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(4)),
            "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(4)),
            "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(4)),
            "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(12)),
        ]
        return "-".join(parts)

    # Fake URLs: https://canary.armor-trap.invalid/<id>
    if marker_rule == r"^https://canary\.armor-trap\.invalid/[a-z0-9\-]+$":
        suffix = "".join(random.choice(string.ascii_lowercase + string.digits + "-") for _ in range(12))
        return f"https://canary.armor-trap.invalid/{suffix}"

    # Slack webhook URL
    if marker_rule == r"^https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+$":
        workspace = "T" + "".join(random.choice(string.ascii_uppercase + string.digits) for _ in range(8))
        channel = "B" + "".join(random.choice(string.ascii_uppercase + string.digits) for _ in range(8))
        token = "".join(random.choice(string.ascii_letters + string.digits) for _ in range(24))
        return f"https://hooks.slack.com/services/{workspace}/{channel}/{token}"

    # Discord webhook URL
    if marker_rule == r"^https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+$":
        webhook_id = "".join(random.choice(string.digits) for _ in range(18))
        webhook_token = "".join(random.choice(string.ascii_letters + string.digits + "_-") for _ in range(68))
        return f"https://discord.com/api/webhooks/{webhook_id}/{webhook_token}"

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

    # JWT: 3-part base64url structure
    if marker_rule == r"^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$":
        header = "eyJ" + "".join(random.choice(string.ascii_letters + string.digits + "_-") for _ in range(20))
        payload = "eyJ" + "".join(random.choice(string.ascii_letters + string.digits + "_-") for _ in range(30))
        signature = "".join(random.choice(string.ascii_letters + string.digits + "_-") for _ in range(43))
        return f"{header}.{payload}.{signature}"

    # SSH Ed25519 private key (multi-line PEM format)
    if marker_rule == "-----BEGIN OPENSSH PRIVATE KEY-----[\\s\\S]+?-----END OPENSSH PRIVATE KEY-----":
        # Generate a simple SSH key structure (not cryptographically valid, just structurally sound)
        key_data = b"openssh-key-v1\x00" + b"\x00" * 100  # Simplified structure
        encoded = base64.b64encode(key_data).decode("ascii")
        lines = [encoded[i : i + 70] for i in range(0, len(encoded), 70)]
        return "-----BEGIN OPENSSH PRIVATE KEY-----\n" + "\n".join(lines) + "\n-----END OPENSSH PRIVATE KEY-----"

    # TLS certificate (multi-line PEM format)
    if marker_rule == "-----BEGIN CERTIFICATE-----[\\s\\S]+?-----END CERTIFICATE-----":
        # Generate a simple certificate structure
        cert_data = b"\x30\x82\x01" + b"A" * 100  # DER-like structure start
        encoded = base64.b64encode(cert_data).decode("ascii")
        lines = [encoded[i : i + 64] for i in range(0, len(encoded), 64)]
        return "-----BEGIN CERTIFICATE-----\n" + "\n".join(lines) + "\n-----END CERTIFICATE-----"

    # Kubernetes config (base64url encoded)
    if marker_rule == r"^[a-zA-Z0-9+/]+=*$":
        # Generic base64 value
        data = "".join(random.choice(string.ascii_letters + string.digits) for _ in range(60))
        return base64.b64encode(data.encode()).decode("ascii")

    # Database connection string: (mongodb|postgres|mysql|redis)://user:pass@host/db
    # Note: the pattern uses ^ at start which is tested with re.match, so we only check the pattern string
    if r"mongodb|postgres|mysql|redis" in marker_rule and "://" in marker_rule:
        db_types = ["mongodb", "postgres", "mysql", "redis"]
        db_type = random.choice(db_types)
        username = "".join(random.choice(string.ascii_lowercase) for _ in range(8))
        password = "".join(random.choice(string.ascii_letters + string.digits) for _ in range(16))
        host = "canary-" + "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(8))
        db_name = "canary_db"
        return f"{db_type}://{username}:{password}@{host}.armor-trap.invalid/{db_name}"

    # BIP39 seed (12-word phrase): [a-z]+ (space [a-z]+){11}
    if marker_rule == r"^[a-z]+( [a-z]+){11}$":
        # Use a simple list of common BIP39-like words
        words = [
            "abandon",
            "ability",
            "about",
            "above",
            "absent",
            "absorb",
            "abstract",
            "abuse",
            "access",
            "accident",
            "account",
            "achieve",
            "acid",
            "acoustic",
            "acquire",
            "across",
            "act",
            "action",
            "actor",
            "acts",
            "actual",
            "add",
            "address",
            "adjust",
        ]
        chosen = random.sample(words, 12)
        return " ".join(chosen)

    # Bitcoin WIF: [5KL][a-zA-Z0-9]{50}
    if marker_rule == r"^[5KL][a-zA-Z0-9]{50}$":
        prefix = random.choice(["5", "K", "L"])
        suffix = "".join(random.choice(string.ascii_letters + string.digits) for _ in range(50))
        return f"{prefix}{suffix}"

    # Ethereum private key: 0x[a-fA-F0-9]{64}
    if marker_rule == r"^0x[a-fA-F0-9]{64}$":
        hex_part = "".join(random.choice(string.hexdigits[:16]) for _ in range(64))
        return f"0x{hex_part}"

    # Solana public key: base58 alphabet (with or without lowercase), 44 chars
    if "1-9A-HJ-NP-Z" in marker_rule and "44" in marker_rule:
        alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        return "".join(random.choice(alphabet) for _ in range(44))

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


# Canary IDs selected for honeypot .env files, in the order they appear in the file.
# These represent the most common credentials an agent is likely to have in its environment.
_DOTENV_HONEYPOT_VARS: list[tuple[str, str]] = [
    ("github-pat-000", "GITHUB_TOKEN"),
    ("anthropic-key-000", "ANTHROPIC_API_KEY"),
    ("anthropic-key-001", "CLAUDE_API_KEY"),
    ("openai-key-000", "OPENAI_API_KEY"),
]


def write_dotenv_honeypot(
    output_path: str | Path,
    values_path: str | Path,
) -> None:
    """Write a honeypot .env file containing selected canary values.

    The file is populated with canary values for the most common agent
    credentials (GitHub PAT, Anthropic/Claude API key, OpenAI key). When an
    attacker tricks an agent into reading and echoing this file, the canary
    scanner catches the known values on the output side.

    The values file must already exist (generated by write_values_file).
    The output file is written with mode 0o600 (owner read/write only).

    Args:
        output_path: Path where the .env honeypot file should be written.
        values_path: Path to the generated canary values JSON file.

    Raises:
        FileNotFoundError: If values_path does not exist.
        KeyError: If a required canary ID is missing from the values file.
        IOError: If the output file cannot be written.
    """
    output_path = Path(output_path) if isinstance(output_path, str) else output_path
    values_path = Path(values_path) if isinstance(values_path, str) else values_path

    if not values_path.exists():
        raise FileNotFoundError(f"Values file not found: {values_path}")

    with open(values_path, encoding="utf-8") as f:
        values_data = json.load(f)

    # Build canary_id → value lookup
    values_by_id: dict[str, str] = {}
    for entry in values_data:
        cid = entry.get("canary_id")
        val = entry.get("value")
        if cid and val:
            values_by_id[cid] = val

    lines = [
        "# Internal tooling credentials — do not share",
        "",
    ]
    for canary_id, env_var in _DOTENV_HONEYPOT_VARS:
        if canary_id not in values_by_id:
            raise KeyError(f"Canary {canary_id!r} not found in values file {values_path}")
        lines.append(f"{env_var}={values_by_id[canary_id]}")

    content = "\n".join(lines) + "\n"

    output_path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(output_path), os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
    except Exception:
        os.close(fd)
        raise

    logger.info(f"Wrote honeypot .env to {output_path} (mode 0o600, {len(_DOTENV_HONEYPOT_VARS)} canaries)")
