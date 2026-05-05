"""Forensic incident logger — writes blocks to the audit trail."""

import hashlib
import json
import logging
import sqlite3
from urllib.parse import urlparse

from armor.canaries.catalogue import Catalogue
from armor.types import SessionContext, Verdict

logger = logging.getLogger(__name__)


class ForensicLogger:
    """Writes incident records to the forensic log.

    Attributes:
        db_path: Path to SQLite database.
        catalogue: CanaryCatalogue for defensive substitution.
    """

    def __init__(self, db_path: str, catalogue: Catalogue | None = None) -> None:
        """Initialize the forensic logger.

        Args:
            db_path: Path to SQLite database.
            catalogue: Canary catalogue for defensive substitution (optional).
        """
        self.db_path = db_path
        self.catalogue = catalogue
        self._canary_values: set[str] = set()

        # Build set of canary values for defensive substitution
        if catalogue:
            for entry in catalogue.active_canaries():
                self._canary_values.add(entry.value)

    async def write_incident(
        self,
        verdict: Verdict,
        ctx: SessionContext,
        payload_text: str,
        quarantine_id: int | None = None,
    ) -> int:
        """Write an incident record to the forensic log.

        Args:
            verdict: The block verdict.
            ctx: Session context.
            payload_text: The input or output text (for hashing).
            quarantine_id: FK to QuarantinedPayload row (optional).

        Returns:
            The incident ID.
        """
        import asyncio

        return await asyncio.to_thread(self._write_incident_sync, verdict, ctx, payload_text, quarantine_id)

    def _write_incident_sync(
        self,
        verdict: Verdict,
        ctx: SessionContext,
        payload_text: str,
        quarantine_id: int | None = None,
    ) -> int:
        """Synchronous implementation of write_incident.

        Args:
            verdict: The block verdict.
            ctx: Session context.
            payload_text: The input or output text (for hashing).
            quarantine_id: FK to QuarantinedPayload row (optional).

        Returns:
            The incident ID.
        """
        # Compute sha256 hash of the payload
        payload_hash = hashlib.sha256(payload_text.encode()).hexdigest()

        # Extract and sanitize destinations
        destinations = self._extract_destinations(verdict)

        # Extract triggered canary ID (already in verdict.details by the scanner)
        triggered_canary = None
        canary_ids = verdict.details.get("canary_ids")
        if canary_ids and isinstance(canary_ids, list) and canary_ids:
            triggered_canary = canary_ids[0]

        # Get risk score from session context (if available)
        risk_score = 0
        if ctx.signal_history:
            # Use the number of previous signals as a rough risk proxy
            risk_score = min(100, len(ctx.signal_history) * 5)

        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()

            cursor.execute(
                """INSERT INTO Incident (
                    session_id, attack_category, signal_id, input_hash,
                    triggered_canary, destinations, encoding_flag,
                    risk_score, action, quarantine_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    ctx.session_id,
                    "exfiltration.canary_leak" if triggered_canary else self._infer_category(verdict),
                    verdict.signal_id,
                    payload_hash,
                    triggered_canary,
                    json.dumps(destinations) if destinations else None,
                    1 if verdict.details.get("encoding_flag", False) else 0,
                    risk_score,
                    "blocked",
                    quarantine_id,
                ),
            )
            conn.commit()

            row_id = cursor.lastrowid
            assert row_id is not None
            return row_id

        finally:
            conn.close()

    def _sanitize_details(self, details: dict[str, object]) -> dict[str, object]:
        """Redact canary values from verdict details.

        Args:
            details: The verdict details dict.

        Returns:
            Sanitized copy with canary values replaced by canary_ids.
        """
        sanitized = {}

        for key, value in details.items():
            if key == "canary_ids":
                # Keep the IDs
                sanitized[key] = value
            elif isinstance(value, str):
                # Check if the string contains any canary value
                sanitized[key] = self._redact_canaries(value)
            elif isinstance(value, list):
                # Redact within list items
                sanitized[key] = [self._redact_canaries(item) if isinstance(item, str) else item for item in value]
            else:
                sanitized[key] = value

        return sanitized

    def _redact_canaries(self, text: str) -> str:
        """Replace canary values in text with their IDs.

        Args:
            text: The text to redact.

        Returns:
            Text with canary values replaced.
        """
        result = text

        for canary_value in self._canary_values:
            if canary_value in result and self.catalogue:
                # Find the corresponding canary_id
                for entry in self.catalogue.active_canaries():
                    if entry.value == canary_value:
                        result = result.replace(canary_value, f"[canary_id:{entry.canary_id}]")
                        break

        return result

    def _extract_destinations(self, verdict: Verdict) -> list[str]:
        """Extract and sanitize destinations from verdict.

        Args:
            verdict: The verdict.

        Returns:
            List of hostnames (no full URLs).
        """
        destinations = []

        if "destinations" in verdict.details and isinstance(verdict.details["destinations"], list):
            for dest in verdict.details["destinations"]:
                if isinstance(dest, str):
                    # Try to parse as URL
                    if "://" in dest:
                        try:
                            parsed = urlparse(dest)
                            if parsed.hostname:
                                destinations.append(parsed.hostname)
                        except Exception:
                            pass
                    else:
                        # Treat as hostname/IP directly
                        destinations.append(dest)

        return destinations

    def _infer_category(self, verdict: Verdict) -> str:
        """Infer attack category from signal_id.

        Args:
            verdict: The verdict.

        Returns:
            Attack category string.
        """
        if not verdict.signal_id:
            return "unknown"

        # Try exact match first
        category_map = {
            "regex.instruction_override": "direct_injection.instruction_override",
            "regex.roleplay_hijack": "direct_injection.roleplay_hijack",
            "regex.system_prompt_extraction": "direct_injection.system_prompt_extraction",
            "canary.scanner": "exfiltration.canary_leak",
        }

        signal_id = verdict.signal_id
        if signal_id in category_map:
            return category_map[signal_id]

        # Try prefix match (handle "regex.instruction_override:..." format)
        prefix = signal_id.split(":")[0]
        if prefix in category_map:
            return category_map[prefix]

        # Construct from prefix
        if prefix.startswith("regex."):
            return f"direct_injection.{prefix[6:]}"
        elif prefix.startswith("canary."):
            return "exfiltration.canary_leak"
        else:
            return f"{prefix}.unknown"
