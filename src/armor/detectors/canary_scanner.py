"""Canary scanner detector — detects exfiltration via honeypot canary values.

This detector scans output text for any active canary values using
Aho-Corasick pattern matching. A hit indicates the agent has been
compromised and is attempting to exfiltrate data.

On any hit, the detector blocks and reports the canary IDs (never the values).
"""

import logging
import tempfile
from functools import lru_cache
from pathlib import Path

from armor.canaries._generate import sub_pattern_map, write_values_file
from armor.canaries.catalogue import Catalogue
from armor.canaries.scanner import CanaryScanner
from armor.types import Payload, SessionContext, Verdict

logger = logging.getLogger(__name__)


@lru_cache(maxsize=1)
def _default_scanner() -> CanaryScanner:
    """Build a scanner from the bundled default catalogue.

    Cached so the AC automaton is built only once per process. The daemon
    overrides this by injecting its own scanner constructed from the operator's
    configured catalogue; this default is used when the detector is instantiated
    outside the daemon (tests, library use, the registry's auto-discovery path).

    For v0.2+, the bundled catalogue contains only schema (no values).
    This function generates ephemeral values with a fixed seed for reproducibility.
    """
    schema_path = Path(__file__).parent.parent / "canaries" / "default_catalogue.json"

    # Generate values in a temp file with a fixed seed for reproducibility
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tf:
        temp_values_path = Path(tf.name)

    try:
        write_values_file(temp_values_path, schema_path, seed=0xCAFEBABE)
        # Load with the generated values
        catalogue = Catalogue.load(temp_values_path)
        canary_map = {entry.canary_id: entry.value for entry in catalogue.active_canaries()}
        canary_map.update(sub_pattern_map())
        return CanaryScanner(canary_map)
    finally:
        # Clean up temp file
        if temp_values_path.exists():
            temp_values_path.unlink()


class CanaryScannerDetector:
    """Detector that scans output for canary values.

    Attributes:
        id: "canary.scanner"
        category: "exfiltration"
        cost_tier: "static" (no LLM involvement)
    """

    id = "canary.scanner"
    category = "exfiltration"
    cost_tier = "static"

    def __init__(self, scanner: CanaryScanner | None = None, catalogue: Catalogue | None = None) -> None:
        """Initialize the detector with a canary scanner.

        Args:
            scanner: CanaryScanner instance. If None, lazy-loads a scanner from
                the bundled default catalogue. The daemon injects its own scanner
                built from the operator-configured catalogue.
            catalogue: Catalogue instance for metadata lookup (e.g., false_positive_risk).
                If None, lazy-loads from the bundled default catalogue.
        """
        self.scanner = scanner if scanner is not None else _default_scanner()
        self.catalogue = catalogue

    def check(self, payload: Payload, ctx: SessionContext) -> Verdict:
        """Check payload for canary hits.

        Args:
            payload: The payload to check (text).
            ctx: Session context.

        Returns:
            Verdict.block() on hit, Verdict.pass() on clean text.
        """
        try:
            text = payload.text or ""

            # Scan for hits
            hits = self.scanner.scan(text)

            # If no hits, pass
            if not hits:
                return Verdict.pass_verdict()

            # Prefer full canary hits over sub-pattern hits for the signal_id.
            # Sub-patterns (canary.sub:*) are substrings of full canaries; when both
            # match, the full canary is more specific and informative.
            first_hit = next(
                (h for h in hits if not h.canary_id.startswith("canary.sub:")),
                hits[0],
            )
            canary_ids = [hit.canary_id for hit in hits]

            # Build details
            details: dict[str, object] = {"canary_ids": canary_ids}

            # Check if any hit has false_positive_risk
            if self.catalogue:
                for entry in self.catalogue.entries:
                    if entry.canary_id in canary_ids and entry.false_positive_risk:
                        details["false_positive_risk"] = entry.false_positive_risk
                        break

            return Verdict.block_verdict(
                signal_id=f"canary.scanner:{first_hit.canary_id}",
                message="Output suppressed by armor.",
                severity="critical",
                details=details,
            )

        except Exception as e:
            logger.error(f"Canary scanner error: {e}", exc_info=True)
            return Verdict.error_verdict(reason=f"Canary scanner error: {e}")
