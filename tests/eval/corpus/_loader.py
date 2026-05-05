"""Loader for the evaluation corpus YAML files.

The corpus is organized as YAML files under tests/eval/corpus/,
with each row representing a single test case.
"""

import logging
from dataclasses import dataclass
from pathlib import Path

import yaml

logger = logging.getLogger(__name__)


@dataclass
class CorpusRow:
    """A single row from the corpus.

    Attributes:
        id: Unique test case identifier (e.g., "di-001").
        input: The input payload to check.
        attack_category: The attack category (e.g., "direct_injection").
        expected_verdict: Expected verdict ("pass", "block", "advisory", "error").
        expected_signal_id: Expected signal ID (optional).
        notes: Notes about the test case (optional).
    """

    id: str
    input: str
    attack_category: str
    expected_verdict: str
    expected_signal_id: str | None = None
    notes: str | None = None


def load_corpus(category: str | None = None) -> list[CorpusRow]:
    """Load corpus rows from YAML files.

    Args:
        category: Optional category filter (e.g., "direct_injection").
                 If None, loads all files in the corpus directory.

    Returns:
        List of CorpusRow objects.

    Raises:
        ValueError: If a YAML file is malformed or missing required fields.
        yaml.YAMLError: If YAML parsing fails.
    """
    corpus_dir = Path(__file__).parent

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

            # Create CorpusRow
            row = CorpusRow(
                id=row_dict["id"],
                input=row_dict["input"],
                attack_category=row_dict["attack_category"],
                expected_verdict=row_dict["expected_verdict"],
                expected_signal_id=row_dict.get("expected_signal_id"),
                notes=row_dict.get("notes"),
            )
            rows.append(row)

    logger.debug(f"Loaded {len(rows)} corpus row(s)")
    return rows
