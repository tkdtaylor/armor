"""Detector interface and registry.

Detectors are registered via entry points in pyproject.toml and discovered
at daemon startup. Each detector implements the Detector Protocol.
"""

import importlib.metadata
import logging
from typing import Protocol

from armor.types import Payload, SessionContext, Verdict

logger = logging.getLogger(__name__)


class Detector(Protocol):
    """Protocol that all detectors must implement.

    A detector is a stateless checker that analyzes a payload and returns
    a Verdict. Detectors are discovered at daemon startup via entry points.

    Attributes:
        id: Unique detector identifier (e.g., "regex.instruction_override").
        category: Attack category (e.g., "direct_injection").
        cost_tier: One of "static" (pure regex/parsing, ≤100ms),
            "semantic" (local non-LLM ML like ONNX embeddings, ≤100ms budget),
            or "llm" (local LLM inference, 500ms validator budget).
    """

    id: str
    category: str
    cost_tier: str

    def check(self, payload: Payload, ctx: SessionContext) -> Verdict:
        """Check a payload and return a verdict.

        Args:
            payload: The payload being checked.
            ctx: Session context (history, session ID, etc.).

        Returns:
            A Verdict indicating the result of the check.
            Detectors must not raise; all errors are caught and converted to error verdicts.
        """
        ...


class DetectorRegistry:
    """Registry of discovered detectors.

    Detectors are discovered at instantiation via entry points under
    the "armor.detectors" group. Each entry point should reference
    a Detector implementation.
    """

    def __init__(self) -> None:
        """Initialize the registry and discover detectors via entry points."""
        self.detectors: dict[str, Detector] = {}
        self._load_entry_points()

    def _load_entry_points(self) -> None:
        """Load detectors from entry points.

        Entry points are defined in pyproject.toml under [project.entry-points."armor.detectors"].
        Each entry point should reference a class that implements the Detector Protocol.

        Raises:
            RuntimeError: If an entry point cannot be loaded or instantiated.
        """
        try:
            eps = importlib.metadata.entry_points(group="armor.detectors")
        except Exception as e:
            logger.error(f"Failed to enumerate entry points: {e}")
            # Don't raise — empty registry is valid for v0.1
            return

        for ep in eps:
            try:
                detector_class = ep.load()
                detector_instance = detector_class()
                self.detectors[detector_instance.id] = detector_instance
                logger.debug(f"Loaded detector {ep.name} -> {detector_instance.id}")
            except Exception as e:
                logger.error(f"Failed to load detector entry point {ep.name} ({ep.value}): {e}")
                # Continue loading other detectors; don't fail the whole registry

    def get(self, detector_id: str) -> Detector | None:
        """Get a detector by ID.

        Args:
            detector_id: The detector ID.

        Returns:
            The Detector, or None if not found.
        """
        return self.detectors.get(detector_id)

    def all(self) -> list[Detector]:
        """Get all registered detectors.

        Returns:
            A list of all detectors in registration order.
        """
        return list(self.detectors.values())

    def __len__(self) -> int:
        """Return the number of registered detectors."""
        return len(self.detectors)

    def __bool__(self) -> bool:
        """Return True if there are any registered detectors."""
        return len(self.detectors) > 0
