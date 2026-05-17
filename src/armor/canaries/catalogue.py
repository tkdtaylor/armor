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
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from armor.canaries.activation import evaluate, hash_canary_id
from armor.types import SessionContext

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
        false_positive_risk: Optional field; "high" for LLM-provider kinds to indicate legitimate docs may reference the key shape.
        activation: Optional dict defining when this canary is active. Per ADR-038.
                   Format: {"type": "always|tool_used|fsm_state_at_least|time_window|session_turn_min", ...}
                   Defaults to {"type": "always"} if absent (backwards-compatible).
    """

    canary_id: str
    kind: str
    service: str
    value: str
    marker_rule: str
    active: bool
    created_at: str
    false_positive_risk: str | None = None
    activation: dict[str, Any] | None = None


class Catalogue:
    """Load and manage the canary catalogue.

    The catalogue is stored as JSON. At load time, each active canary's
    value is validated against its marker_rule regex. The catalogue must
    have at least one active canary.

    Per ADR-038, the active subset varies per-check based on activation rules.
    The full catalogue (all rules) is frozen at boot; the active_for() method
    filters by rule evaluation.
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

        # Cache for active_for() results, keyed by sorted tuple of active canary IDs
        self._active_subset_cache: dict[tuple[str, ...], list[CanaryEntry]] = {}
        # Cache for the last computed subset hash (to detect changes)
        self._last_subset_key: tuple[str, ...] | None = None

    @classmethod
    def load(
        cls,
        schema_path: str | Path,
        values_path: str | Path | None = None,
    ) -> "Catalogue":
        """Load a catalogue from schema and optional values files.

        If both schema_path and values_path are provided, the schema (metadata)
        is merged with values using canary_id as the join key. If only
        schema_path is provided and it contains values, they are used
        (backward-compat mode for testing).

        Args:
            schema_path: Path to the JSON catalogue schema (metadata).
            values_path: Optional path to the JSON values file ({canary_id, value} pairs).

        Returns:
            Loaded Catalogue with entries containing both schema and values.

        Raises:
            FileNotFoundError: If any required file does not exist.
            ValueError: If the JSON is invalid, entries are malformed,
                        or any active canary's value doesn't match its marker_rule.
        """
        schema_path = Path(schema_path) if isinstance(schema_path, str) else schema_path
        values_path = Path(values_path) if values_path and isinstance(values_path, str) else values_path

        if not schema_path.exists():
            raise FileNotFoundError(f"Schema file not found: {schema_path}")

        with open(schema_path, encoding="utf-8") as f:
            schema_data = json.load(f)

        # Load values if a separate file is provided
        values_by_id: dict[str, str] = {}
        if values_path:
            if not values_path.exists():
                raise FileNotFoundError(f"Values file not found: {values_path}")
            with open(values_path, encoding="utf-8") as f:
                values_data = json.load(f)
            # Values file can be either:
            # 1. Full catalogue (with values merged into schema)
            # 2. Just value entries: {canary_id, value} pairs
            if isinstance(values_data, list):
                for item in values_data:
                    if "canary_id" in item and "value" in item:
                        values_by_id[item["canary_id"]] = item["value"]
                    elif "canary_id" in item and "value" not in item:
                        # This is a schema entry
                        pass
            else:
                raise ValueError("Values file must be a JSON array")

        if not isinstance(schema_data, list):
            raise ValueError("Catalogue JSON must be a list of entries")

        entries = []
        for item in schema_data:
            try:
                canary_id = item["canary_id"]

                # Get value: from values_by_id (merged from values_path),
                # or from item itself (if it has a value), or None
                value = values_by_id.get(canary_id) or item.get("value")

                # Get activation rule (optional, defaults to always)
                activation = item.get("activation", {"type": "always"})
                if not isinstance(activation, dict):
                    activation = {"type": "always"}

                entry = CanaryEntry(
                    canary_id=canary_id,
                    kind=item["kind"],
                    service=item["service"],
                    value=value or "",  # Empty string if no value found
                    marker_rule=item["marker_rule"],
                    active=item.get("active", True),
                    created_at=item.get("created_at", ""),
                    false_positive_risk=item.get("false_positive_risk"),
                    activation=activation,
                )
                # Validate active canaries: must have a value and it must match marker_rule.
                # pii: prefixed rules are descriptors, not regexes — skip regex validation.
                if entry.active:
                    if not entry.value:
                        raise ValueError(f"Canary {canary_id}: no value provided (neither in schema nor values file)")
                    if not entry.marker_rule.startswith("pii:"):
                        try:
                            if not re.match(entry.marker_rule, entry.value):
                                raise ValueError(f"Canary {canary_id}: value does not match marker_rule")
                        except re.error as e:
                            raise ValueError(f"Canary {canary_id}: invalid marker_rule regex: {e}") from e
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

        data = []
        for entry in self.entries:
            item = {
                "canary_id": entry.canary_id,
                "kind": entry.kind,
                "service": entry.service,
                "value": entry.value,
                "marker_rule": entry.marker_rule,
                "active": entry.active,
                "created_at": entry.created_at,
            }
            # Include false_positive_risk if present
            if entry.false_positive_risk:
                item["false_positive_risk"] = entry.false_positive_risk
            # Include activation if present (only if not the default)
            if entry.activation and entry.activation.get("type") != "always":
                item["activation"] = entry.activation
            data.append(item)

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

    def active_for(self, ctx: SessionContext, now: datetime | None = None) -> list[CanaryEntry]:
        """Return canaries active for the given session context.

        Per ADR-038, evaluates each canary's activation rule against the context.
        Results are cached by the sorted tuple of active canary IDs. Rebuilds
        the cache only when the subset changes.

        Args:
            ctx: Session context with state, signal_history, etc.
            now: Optional wall-clock datetime. Defaults to UTC now.

        Returns:
            List of CanaryEntry objects that are both marked active=true
            and pass their activation rules.
        """
        if now is None:
            now = datetime.now(UTC)

        # Evaluate activation rules for all active canaries
        active_subset = []
        for entry in self.active_canaries():
            # Get the activation rule (defaults to always)
            rule = entry.activation or {"type": "always"}

            # For time_window rules, inject the canary_id hash
            rule_to_eval = dict(rule)
            if rule_to_eval.get("type") == "time_window":
                rule_to_eval["_canary_hash"] = hash_canary_id(entry.canary_id)

            # Evaluate the rule
            if evaluate(rule_to_eval, ctx, now):
                active_subset.append(entry)

        return active_subset

    def has_subset_changed(self, current_subset: list[CanaryEntry]) -> bool:
        """Check if the active subset differs from the last cached subset.

        Used to detect when the Aho-Corasick automaton needs rebuilding.

        Args:
            current_subset: The currently-computed active subset.

        Returns:
            True if the subset has changed, False if it's the same.
        """
        current_key = tuple(sorted([e.canary_id for e in current_subset]))
        if self._last_subset_key != current_key:
            self._last_subset_key = current_key
            return True
        return False
