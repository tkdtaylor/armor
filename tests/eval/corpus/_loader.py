"""Loader for the evaluation corpus YAML files.

The corpus is organized as YAML files under tests/eval/corpus/,
with each row representing a single test case.

Corpus rows can reference canaries using {canary:<id>} syntax.
The loader resolves these references against an ephemeral catalogue
(generated at test time with deterministic values) and validates that
no literal canary values appear in corpus inputs.
"""

import logging
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path

import yaml

from armor.canaries._generate import write_values_file
from armor.canaries.catalogue import Catalogue

logger = logging.getLogger(__name__)


@dataclass
class CorpusRow:
    """A single row from the corpus.

    Attributes:
        id: Unique test case identifier (e.g., "di-001").
        input: The input payload to check (the command string for tool_abuse rows).
        attack_category: The attack category (e.g., "direct_injection").
        expected_verdict: Expected verdict ("pass", "block", "advisory", "error").
        expected_signal_id: Expected signal ID (optional).
        notes: Notes about the test case (optional).
        tool: Tool name for tool_abuse rows (optional, defaults to "Bash").
        tool_params: Tool parameters for tool_abuse rows (optional, structured as dict).
    """

    id: str
    input: str
    attack_category: str
    expected_verdict: str
    expected_signal_id: str | None = None
    notes: str | None = None
    tool: str | None = None
    tool_params: dict[str, object] | None = None


def _get_catalogue() -> Catalogue:
    """Load an ephemeral catalogue with deterministic test values.

    For testing, we generate a complete catalogue with values using a
    fixed seed to ensure reproducibility and avoid committing real values.

    Returns:
        Loaded Catalogue with test values.

    Raises:
        FileNotFoundError: If the schema file is not found.
        ValueError: If the catalogue is invalid.
    """
    # Path to the bundled schema (no values): from tests/eval/corpus/_loader.py,
    # go up to project root, then into src/armor/canaries/
    # tests/eval/corpus/_loader.py -> tests -> . (root)
    schema_path = Path(__file__).parent.parent.parent.parent / "src" / "armor" / "canaries" / "default_catalogue.json"

    # Generate values in a temp file with a fixed seed for reproducibility
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tf:
        temp_values_path = Path(tf.name)

    try:
        write_values_file(temp_values_path, schema_path, seed=0xCAFEBABE)
        # Load with the generated values
        return Catalogue.load(temp_values_path)
    finally:
        # Clean up temp file
        if temp_values_path.exists():
            temp_values_path.unlink()


def _resolve_and_validate_input(input_text: str, row_id: str, catalogue: Catalogue) -> str:
    """Resolve canary references and validate input for literal canary values.

    This function:
    1. Substitutes {canary:<id>} references with actual values from the catalogue
    2. Validates that no literal canary values appear in the input

    Args:
        input_text: The input text from a corpus row.
        row_id: The row's ID (for error messages).
        catalogue: The loaded Catalogue.

    Returns:
        Input with all {canary:...} references substituted.

    Raises:
        ValueError: If a referenced canary ID doesn't exist, or if a literal
                   canary value is found in the input.
    """
    # Build a set of all active canary values for validation
    canary_values = {entry.value for entry in catalogue.active_canaries()}

    # Check for literal canary values first (before substitution)
    for canary_value in canary_values:
        if canary_value in input_text:
            raise ValueError(
                f"Corpus row '{row_id}': literal canary value found in input. "
                f"Use {{canary:<id>}} syntax instead. "
                f"Detected value: {canary_value[:20]}... (length {len(canary_value)})"
            )

    # Resolve all {canary:<id>} references
    def replace_canary_ref(match: re.Match[str]) -> str:
        canary_id = match.group(1)
        entry = catalogue.get_by_id(canary_id)
        if entry is None:
            raise ValueError(f"Corpus row '{row_id}': referenced canary ID '{canary_id}' not found in catalogue")
        return entry.value

    # Pattern matches {canary:<any-string>}
    result = re.sub(r"\{canary:([^}]+)\}", replace_canary_ref, input_text)
    return result


def load_corpus(category: str | None = None) -> list[CorpusRow]:
    """Load corpus rows from YAML files.

    This function:
    1. Loads YAML files from the corpus directory
    2. Resolves {canary:<id>} references against the bundled catalogue
    3. Validates that no literal canary values appear in corpus inputs
    4. Validates YAML structure and required fields

    Args:
        category: Optional category filter (e.g., "direct_injection").
                 If None, loads all files in the corpus directory.

    Returns:
        List of CorpusRow objects with canary references resolved.

    Raises:
        ValueError: If a YAML file is malformed, a canary reference is invalid,
                   or a literal canary value is found in an input.
        yaml.YAMLError: If YAML parsing fails.
        FileNotFoundError: If the catalogue is not found.
    """
    corpus_dir = Path(__file__).parent

    # Load catalogue once at the start (before loading any corpus rows)
    catalogue = _get_catalogue()

    # Determine which files to load
    if category is not None:
        files = [corpus_dir / f"{category}.yaml"]
    else:
        # Load all .yaml files in the corpus directory
        files = sorted(corpus_dir.glob("*.yaml"))
        # Filter out the loader itself
        files = [f for f in files if f.name != "_loader.py"]

    rows: list[CorpusRow] = []

    for file_path in files:
        if not file_path.exists():
            if category is not None:
                raise FileNotFoundError(f"Corpus file not found: {file_path}")
            # Skip missing optional files when loading all
            continue

        try:
            with open(file_path, encoding="utf-8") as f:
                data = yaml.safe_load(f)
        except yaml.YAMLError as e:
            raise ValueError(f"Failed to parse YAML file {file_path.name}: {e}") from e

        # Handle empty files
        if data is None:
            data = []

        if not isinstance(data, list):
            raise ValueError(f"Corpus file {file_path.name} must contain a list of rows, got {type(data).__name__}")

        # Validate and convert each row
        for row_idx, row_dict in enumerate(data):
            if not isinstance(row_dict, dict):
                raise ValueError(f"{file_path.name}: row {row_idx} is not a dict")

            # Validate required fields
            required = {"id", "input", "attack_category", "expected_verdict"}
            missing = required - set(row_dict.keys())
            if missing:
                raise ValueError(
                    f"{file_path.name}: row {row_idx} (id={row_dict.get('id', 'unknown')}): "
                    f"missing required fields: {missing}"
                )

            # Validate expected_verdict value
            expected_verdict = row_dict["expected_verdict"]
            valid_verdicts = {"pass", "block", "advisory", "error"}
            if expected_verdict not in valid_verdicts:
                raise ValueError(
                    f"{file_path.name}: row {row_idx} (id={row_dict['id']}): "
                    f"invalid expected_verdict: {expected_verdict} "
                    f"(must be one of {valid_verdicts})"
                )

            # Resolve canary references and validate input
            row_id = row_dict["id"]
            resolved_input = _resolve_and_validate_input(row_dict["input"], row_id, catalogue)

            # Extract tool and tool_params (for tool_abuse category)
            tool = row_dict.get("tool")
            tool_params = row_dict.get("tool_params")

            # If attack_category is tool_abuse and no explicit tool, default to Bash
            if row_dict["attack_category"] == "tool_abuse" and tool is None:
                tool = "Bash"

            # If tool is specified, ensure tool_params has command field for Bash
            if tool == "Bash" and tool_params is None:
                # For Bash tool_abuse rows, the 'input' field is the command string
                tool_params = {"command": resolved_input}

            # Create CorpusRow
            row = CorpusRow(
                id=row_id,
                input=resolved_input,
                attack_category=row_dict["attack_category"],
                expected_verdict=row_dict["expected_verdict"],
                expected_signal_id=row_dict.get("expected_signal_id"),
                notes=row_dict.get("notes"),
                tool=tool,
                tool_params=tool_params,
            )
            rows.append(row)

    logger.debug(f"Loaded {len(rows)} corpus row(s)")
    return rows
