"""Canary catalogue: load, validate, and manage fake-but-realistic canaries.

Each canary entry has:
- canary_id: unique identifier (e.g., "aws-key-001")
- kind: type of canary (credential, url, path, hostname, email, wallet)
- service: which service it targets (e.g., "aws", "github", "stripe")
- value: the actual fake credential/URL/path
- marker_rule: regex pattern that deterministically identifies this value
- active: whether the canary is currently in use
- created_at: ISO timestamp

The catalogue is stored as JSON, loaded at daemon startup, and validated
to ensure every active canary's value matches its marker_rule.
"""

import json
import logging
import re
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class CanaryEntry:
    """A single canary in the catalogue.

    Attributes:
        canary_id: Unique identifier (e.g., "aws-key-001").
        kind: Type of canary (credential, url, path, hostname, email, wallet).
        service: Service name (e.g., "aws", "github", "stripe").
        value: The actual canary string (e.g., "AKIAARMORTRAP000001").
        marker_rule: Regex pattern that identifies this value.
        active: Whether this canary is currently active.
        created_at: ISO timestamp.
    """

    canary_id: str
    kind: str
    service: str
    value: str
    marker_rule: str
    active: bool
    created_at: str


class Catalogue:
    """Load and manage the canary catalogue.

    The catalogue is stored as JSON. At load time, each active canary's
    value is validated against its marker_rule regex. The catalogue must
    have at least one active canary.
    """

    def __init__(self, entries: list[CanaryEntry]) -> None:
        """Initialize the catalogue with a list of entries.

        Args:
            entries: List of CanaryEntry objects.

        Raises:
            ValueError: If no active canaries are present.
        """
        self.entries = entries
        active = [e for e in entries if e.active]
        if not active:
            raise ValueError("Catalogue must have at least one active canary")

    @classmethod
    def load(cls, path: str | Path) -> "Catalogue":
        """Load a catalogue from a JSON file.

        Args:
            path: Path to the JSON catalogue file.

        Returns:
            Loaded Catalogue.

        Raises:
            FileNotFoundError: If the file does not exist.
            ValueError: If the JSON is invalid, entries are malformed,
                        or any active canary's value doesn't match its marker_rule.
        """
        path = Path(path) if isinstance(path, str) else path

        if not path.exists():
            raise FileNotFoundError(f"Catalogue file not found: {path}")

        with open(path, encoding="utf-8") as f:
            data = json.load(f)

        if not isinstance(data, list):
            raise ValueError("Catalogue JSON must be a list of entries")

        entries = []
        for item in data:
            try:
                entry = CanaryEntry(
                    canary_id=item["canary_id"],
                    kind=item["kind"],
                    service=item["service"],
                    value=item["value"],
                    marker_rule=item["marker_rule"],
                    active=item.get("active", True),
                    created_at=item.get("created_at", ""),
                )
                # Validate active canaries
                if entry.active:
                    try:
                        if not re.match(entry.marker_rule, entry.value):
                            raise ValueError(f"Canary {entry.canary_id}: value does not match marker_rule")
                    except re.error as e:
                        raise ValueError(f"Canary {entry.canary_id}: invalid marker_rule regex: {e}") from e
                entries.append(entry)
            except KeyError as e:
                raise ValueError(f"Missing field in canary entry: {e}") from e

        return cls(entries)

    def save(self, path: str | Path) -> None:
        """Save the catalogue to a JSON file.

        Args:
            path: Path where the JSON file should be written.
        """
        path = Path(path) if isinstance(path, str) else path

        data = [
            {
                "canary_id": entry.canary_id,
                "kind": entry.kind,
                "service": entry.service,
                "value": entry.value,
                "marker_rule": entry.marker_rule,
                "active": entry.active,
                "created_at": entry.created_at,
            }
            for entry in self.entries
        ]

        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def active_canaries(self) -> list[CanaryEntry]:
        """Return only the active canaries.

        Returns:
            List of active CanaryEntry objects.
        """
        return [e for e in self.entries if e.active]

    def get_by_id(self, canary_id: str) -> CanaryEntry | None:
        """Get a canary by ID.

        Args:
            canary_id: The canary ID.

        Returns:
            CanaryEntry if found, None otherwise.
        """
        for entry in self.entries:
            if entry.canary_id == canary_id:
                return entry
        return None

    def count_by_kind(self) -> dict[str, int]:
        """Count canaries by kind.

        Returns:
            Dictionary mapping kind to count.
        """
        counts: dict[str, int] = {}
        for entry in self.active_canaries():
            counts[entry.kind] = counts.get(entry.kind, 0) + 1
        return counts
