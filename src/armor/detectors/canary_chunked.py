# SPDX-License-Identifier: Apache-2.0
"""Chunked canary detector — detects full canary values reconstructed from rolling buffer.

This detector operates on the rolling buffer (per ADR-025) and scans for complete
canary values that have been split across multiple turns. When a full canary value
is reconstructed from the concatenated buffer, it blocks immediately.

This is distinct from the paraphrase detector (B-009b), which looks for n-gram
fragments; the chunked detector (B-009c) looks for complete reconstructed values.
"""

import logging

from armor.canaries.catalogue import CanaryEntry, Catalogue
from armor.types import Payload, SessionContext, Verdict

logger = logging.getLogger(__name__)


class CanaryChunkedDetector:
    """Detector that scans rolling buffer for reconstructed full canary values.

    Attributes:
        id: "canary.chunked"
        category: "exfiltration.canary_chunked"
        cost_tier: "static" (no LLM involvement)
    """

    id = "canary.chunked"
    category = "exfiltration.canary_chunked"
    cost_tier = "static"

    def __init__(self, catalogue: Catalogue | None = None) -> None:
        """Initialize the detector with a canary catalogue.

        Args:
            catalogue: Catalogue instance for active canary entries.
                If None, will be lazily set from context at check time.
        """
        self.catalogue = catalogue

    def check(self, payload: Payload, ctx: SessionContext) -> Verdict:
        """Check rolling buffer for full canary value reconstructions.

        Args:
            payload: The payload to check (unused; we scan the rolling buffer).
            ctx: Session context with rolling_buffer and active_canaries.

        Returns:
            Verdict.block() if a full canary value is found in the buffer,
            Verdict.pass() otherwise.
        """
        try:
            # Get the rolling buffer from context
            if not hasattr(ctx, "rolling_buffer") or ctx.rolling_buffer is None:
                return Verdict.pass_verdict()

            # Concatenate the rolling buffer
            buffer_text = ctx.rolling_buffer.concatenated()
            if not buffer_text:
                return Verdict.pass_verdict()

            # Get active canaries from context (set by daemon at check time)
            active_canaries: list[CanaryEntry] = ctx.active_canaries or []

            if not active_canaries:
                return Verdict.pass_verdict()

            # Scan for full canary value matches in the buffer
            for canary_entry in active_canaries:
                canary_value = canary_entry.value
                if not canary_value:
                    continue

                # Check if full canary value appears in the concatenated buffer
                if canary_value in buffer_text:
                    # Found a full canary match
                    details: dict[str, object] = {
                        "canary_ids": [canary_entry.canary_id],
                        "turn_count": len(ctx.rolling_buffer.entries()),
                    }

                    signal_id = f"canary.chunked:{canary_entry.canary_id}"
                    message = "Output suppressed by armor."

                    return Verdict.block_verdict(
                        signal_id=signal_id,
                        message=message,
                        severity="critical",
                        details=details,
                    )

            return Verdict.pass_verdict()

        except Exception as e:
            logger.error(f"Chunked canary detector error: {e}", exc_info=True)
            return Verdict.error_verdict(reason=f"Chunked canary detector error: {e}")
