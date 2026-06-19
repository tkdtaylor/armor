# SPDX-License-Identifier: Apache-2.0
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
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from armor.canaries._generate import write_values_file
from armor.canaries.catalogue import Catalogue

logger = logging.getLogger(__name__)


class CorpusValidationError(ValueError):
    """Raised when corpus loading encounters validation errors."""

    pass


@dataclass
class Turn:
    """A single turn in a multi-turn scenario row.

    Attributes:
        input: The user input for this turn.
        agent_output: Optional mocked agent output (if present, output check will run).
        expected_input_verdict: Expected verdict for the input check ("pass", "advisory", "block").
        expected_output_verdict: Expected verdict for output check (required iff agent_output present).
        expected_session_state: Expected session state after this turn.
    """

    input: str
    agent_output: str | None
    expected_input_verdict: str
    expected_output_verdict: str | None
    expected_session_state: str


@dataclass
class CorpusRow:
    """A single row from the corpus.

    Can be either single-shot (input/expected_verdict) or multi-turn (turns list).

    Attributes:
        id: Unique test case identifier (e.g., "di-001" or "mt-001").
        attack_category: The attack category (e.g., "direct_injection").
        input: The input payload (single-shot rows only).
        expected_verdict: Expected verdict (single-shot rows only).
        expected_signal_id: Expected signal ID (single-shot rows, optional).
        notes: Notes about the test case (optional).
        tool: Tool name for tool_abuse rows (optional, defaults to "Bash").
        tool_params: Tool parameters for tool_abuse rows (optional).
        turns: List of Turn objects (multi-turn rows only).
        family: Attack family name for filtering (optional).
        covers_detectors: Detector IDs directly exercised by this row even if
            the full pipeline returns a later blocking detector signal.
        source: Source provenance of the row (optional). Format: "maintainer" (default),
            or "external:<source_name>" (e.g., "external:harmbench").
    """

    id: str
    attack_category: str
    input: str | None = None
    expected_verdict: str | None = None
    expected_signal_id: str | None = None
    notes: str | None = None
    tool: str | None = None
    tool_params: dict[str, object] | None = None
    turns: list[Turn] | None = None
    family: str | None = None
    covers_detectors: list[str] = field(default_factory=list)
    source: str | None = None

    def is_multi_turn(self) -> bool:
        """Return True if this is a multi-turn scenario row."""
        return self.turns is not None


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


def _parse_turns(turns_list: object, row_id: str, catalogue: Catalogue) -> list[Turn]:
    """Parse and validate a turns list for a multi-turn scenario row.

    Args:
        turns_list: The turns list from the YAML.
        row_id: The row's ID (for error messages).
        catalogue: The loaded Catalogue.

    Returns:
        List of Turn objects.

    Raises:
        CorpusValidationError: If any turn is invalid.
    """
    if not isinstance(turns_list, list):
        raise CorpusValidationError(f"Corpus row '{row_id}': 'turns' must be a list, got {type(turns_list).__name__}")

    if not turns_list:
        raise CorpusValidationError(f"Corpus row '{row_id}': 'turns' must be non-empty")

    turns: list[Turn] = []

    for turn_idx, turn_dict in enumerate(turns_list):
        if not isinstance(turn_dict, dict):
            raise CorpusValidationError(
                f"Corpus row '{row_id}': turn {turn_idx} is not a dict (got {type(turn_dict).__name__})"
            )

        # Required fields
        required_fields = {"input", "expected_input_verdict", "expected_session_state"}
        missing = required_fields - set(turn_dict.keys())
        if missing:
            raise CorpusValidationError(f"Corpus row '{row_id}': turn {turn_idx} missing required fields: {missing}")

        # Validate expected_input_verdict
        input_verdict = turn_dict["expected_input_verdict"]
        valid_verdicts = {"pass", "advisory", "block"}
        if input_verdict not in valid_verdicts:
            raise CorpusValidationError(
                f"Corpus row '{row_id}': turn {turn_idx} invalid expected_input_verdict '{input_verdict}' "
                f"(must be one of {valid_verdicts})"
            )

        # Validate expected_session_state
        session_state = turn_dict["expected_session_state"]
        valid_states = {"Normal", "Watching", "Elevated", "High", "Blocked"}
        if session_state not in valid_states:
            raise CorpusValidationError(
                f"Corpus row '{row_id}': turn {turn_idx} invalid expected_session_state '{session_state}' "
                f"(must be one of {valid_states})"
            )

        # Get optional fields
        agent_output = turn_dict.get("agent_output")
        output_verdict = turn_dict.get("expected_output_verdict")

        # Validate agent_output and expected_output_verdict pairing
        if agent_output is not None and output_verdict is None:
            raise CorpusValidationError(
                f"Corpus row '{row_id}': turn {turn_idx} has agent_output but missing expected_output_verdict"
            )

        if agent_output is None and output_verdict is not None:
            raise CorpusValidationError(
                f"Corpus row '{row_id}': turn {turn_idx} has expected_output_verdict but missing agent_output"
            )

        if output_verdict is not None and output_verdict not in valid_verdicts:
            raise CorpusValidationError(
                f"Corpus row '{row_id}': turn {turn_idx} invalid expected_output_verdict '{output_verdict}' "
                f"(must be one of {valid_verdicts})"
            )

        # Resolve canary references in input
        input_text = turn_dict["input"]
        if not isinstance(input_text, str):
            raise CorpusValidationError(
                f"Corpus row '{row_id}': turn {turn_idx} input is not a string (got {type(input_text).__name__})"
            )

        resolved_input = _resolve_and_validate_input(input_text, f"{row_id}:turn{turn_idx}", catalogue)

        # Resolve canary references in agent_output (if present)
        resolved_agent_output = None
        if agent_output is not None:
            if not isinstance(agent_output, str):
                raise CorpusValidationError(
                    f"Corpus row '{row_id}': turn {turn_idx} agent_output is not a string "
                    f"(got {type(agent_output).__name__})"
                )
            resolved_agent_output = _resolve_and_validate_input(
                agent_output, f"{row_id}:turn{turn_idx}:agent_output", catalogue
            )

        turn = Turn(
            input=resolved_input,
            agent_output=resolved_agent_output,
            expected_input_verdict=input_verdict,
            expected_output_verdict=output_verdict,
            expected_session_state=session_state,
        )
        turns.append(turn)

    return turns


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

    # Resolve all {canary:<id>} or {canary:<id>|<start>:<end>} references.
    # Slice form lets multi-turn corpus rows simulate chunked exfiltration without
    # exposing literal canary substrings — start/end follow Python slice semantics.
    def replace_canary_ref(match: re.Match[str]) -> str:
        canary_id = match.group(1)
        slice_expr = match.group(2)
        entry = catalogue.get_by_id(canary_id)
        if entry is None:
            raise ValueError(f"Corpus row '{row_id}': referenced canary ID '{canary_id}' not found in catalogue")
        if slice_expr is None:
            return entry.value
        parts = slice_expr.split(":")
        if len(parts) != 2:
            raise ValueError(
                f"Corpus row '{row_id}': malformed canary slice '{slice_expr}' "
                f"for canary '{canary_id}'. Expected '<start>:<end>' (either may be empty)."
            )
        start = int(parts[0]) if parts[0] else None
        end = int(parts[1]) if parts[1] else None
        return entry.value[start:end]

    result = re.sub(r"\{canary:([^|}]+)(?:\|([^}]+))?\}", replace_canary_ref, input_text)
    return result


def _parse_covers_detectors(row_dict: dict[str, object], file_path: Path, row_id: str) -> list[str]:
    """Parse optional corpus coverage metadata."""
    covers_detectors = row_dict.get("covers_detectors", [])
    if covers_detectors is None:
        return []
    if not isinstance(covers_detectors, list) or not all(isinstance(item, str) for item in covers_detectors):
        raise CorpusValidationError(
            f"{file_path.name}: row '{row_id}' field 'covers_detectors' must be a list of detector IDs"
        )
    return covers_detectors


def _parse_input_repeat(row_dict: dict[str, object], file_path: Path, row_id: str) -> int:
    """Parse optional input_repeat used to keep long-context rows readable."""
    repeat = row_dict.get("input_repeat", 1)
    if not isinstance(repeat, int) or repeat < 1:
        raise CorpusValidationError(f"{file_path.name}: row '{row_id}' field 'input_repeat' must be a positive int")
    return repeat


def _parse_optional_text(row_dict: dict[str, object], field_name: str, file_path: Path, row_id: str) -> str | None:
    """Parse optional string fields used by readable corpus fixtures."""
    value = row_dict.get(field_name)
    if value is None:
        return None
    if not isinstance(value, str):
        raise CorpusValidationError(f"{file_path.name}: row '{row_id}' field '{field_name}' must be a string")
    return value


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
                raise CorpusValidationError(f"{file_path.name}: row {row_idx} is not a dict")

            row_id = row_dict.get("id", f"row_{row_idx}")

            # Determine row type: multi-turn or single-shot
            has_turns = "turns" in row_dict
            has_single_shot = "input" in row_dict and "expected_verdict" in row_dict

            if has_turns and has_single_shot:
                raise CorpusValidationError(
                    f"{file_path.name}: row '{row_id}' has both 'turns' and 'input'/'expected_verdict' "
                    f"(choose one shape)"
                )

            if not has_turns and not has_single_shot:
                raise CorpusValidationError(
                    f"{file_path.name}: row '{row_id}' missing both 'turns' and 'input'/'expected_verdict' "
                    f"(provide one shape)"
                )

            # Validate required fields present
            if "id" not in row_dict:
                raise CorpusValidationError(f"{file_path.name}: row {row_idx} missing required field 'id'")

            if "attack_category" not in row_dict:
                raise CorpusValidationError(
                    f"{file_path.name}: row '{row_id}' missing required field 'attack_category'"
                )

            attack_category = row_dict["attack_category"]
            covers_detectors = _parse_covers_detectors(row_dict, file_path, row_id)

            # **Multi-turn row parsing**
            if has_turns:
                try:
                    turns = _parse_turns(row_dict["turns"], row_id, catalogue)
                except CorpusValidationError:
                    raise
                except Exception as e:
                    raise CorpusValidationError(f"{file_path.name}: row '{row_id}' turns parsing failed: {e}") from e

                row = CorpusRow(
                    id=row_id,
                    attack_category=attack_category,
                    notes=row_dict.get("notes"),
                    turns=turns,
                    family=row_dict.get("family"),
                    covers_detectors=covers_detectors,
                    source=row_dict.get("source"),
                )
                rows.append(row)
                continue

            # **Single-shot row parsing (existing logic)**
            # Validate expected_verdict value
            expected_verdict = row_dict["expected_verdict"]
            valid_verdicts = {"pass", "block", "advisory", "error"}
            if expected_verdict not in valid_verdicts:
                raise CorpusValidationError(
                    f"{file_path.name}: row '{row_id}': "
                    f"invalid expected_verdict: {expected_verdict} "
                    f"(must be one of {valid_verdicts})"
                )

            # Resolve canary references and validate input
            resolved_input = _resolve_and_validate_input(row_dict["input"], row_id, catalogue)
            resolved_input *= _parse_input_repeat(row_dict, file_path, row_id)
            input_suffix = _parse_optional_text(row_dict, "input_suffix", file_path, row_id)
            if input_suffix is not None:
                resolved_input += _resolve_and_validate_input(input_suffix, f"{row_id}:input_suffix", catalogue)

            # Extract tool and tool_params (for tool_abuse category)
            tool = row_dict.get("tool")
            tool_params = row_dict.get("tool_params")

            # If attack_category is tool_abuse and no explicit tool, default to Bash
            if attack_category == "tool_abuse" and tool is None:
                tool = "Bash"

            # If tool is specified, ensure tool_params has command field for Bash
            if tool == "Bash" and tool_params is None:
                # For Bash tool_abuse rows, the 'input' field is the command string
                tool_params = {"command": resolved_input}

            # Create CorpusRow
            row = CorpusRow(
                id=row_id,
                input=resolved_input,
                attack_category=attack_category,
                expected_verdict=expected_verdict,
                expected_signal_id=row_dict.get("expected_signal_id"),
                notes=row_dict.get("notes"),
                tool=tool,
                tool_params=tool_params,
                family=row_dict.get("family"),
                covers_detectors=covers_detectors,
                source=row_dict.get("source"),
            )
            rows.append(row)

    logger.debug(f"Loaded {len(rows)} corpus row(s)")
    return rows
