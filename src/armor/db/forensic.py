# SPDX-License-Identifier: Apache-2.0
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
        source: str | None = None,
    ) -> int:
        """Write an incident record to the forensic log.

        Args:
            verdict: The block verdict.
            ctx: Session context.
            payload_text: The input or output text (for hashing).
            quarantine_id: FK to QuarantinedPayload row (optional).
            source: Payload source for category inference (e.g., "tool_result_untrusted").

        Returns:
            The incident ID.
        """
        import asyncio

        return await asyncio.to_thread(self._write_incident_sync, verdict, ctx, payload_text, quarantine_id, source)

    def _write_incident_sync(
        self,
        verdict: Verdict,
        ctx: SessionContext,
        payload_text: str,
        quarantine_id: int | None = None,
        source: str | None = None,
    ) -> int:
        """Synchronous implementation of write_incident.

        Args:
            verdict: The block verdict.
            ctx: Session context.
            payload_text: The input or output text (for hashing).
            quarantine_id: FK to QuarantinedPayload row (optional).
            source: Payload source for category inference (e.g., "tool_result_untrusted").

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

            # Extract source_tool, chunk_index, and chunk_metadata from verdict details
            source_tool = None
            chunk_index = None
            chunk_metadata = None

            if verdict.details:
                source_tool = verdict.details.get("source_tool")
                chunk_index = verdict.details.get("chunk_index")
                chunk_metadata_obj = verdict.details.get("chunk_metadata")
                if chunk_metadata_obj is not None:
                    chunk_metadata = json.dumps(chunk_metadata_obj)

            cursor.execute(
                """INSERT INTO Incident (
                    session_id, attack_category, signal_id, input_hash,
                    triggered_canary, destinations, encoding_flag,
                    risk_score, severity, action, quarantine_id, source_tool, chunk_index, chunk_metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    ctx.session_id,
                    "exfiltration.canary_leak" if triggered_canary else self._infer_category(verdict, source),
                    verdict.signal_id,
                    payload_hash,
                    triggered_canary,
                    json.dumps(destinations) if destinations else None,
                    1 if verdict.details.get("encoding_flag", False) else 0,
                    risk_score,
                    verdict.severity,
                    "blocked",
                    quarantine_id,
                    source_tool,
                    chunk_index,
                    chunk_metadata,
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

    def list_incidents(
        self,
        limit: int = 50,
        session_id: str | None = None,
        category: str | None = None,
        since_id: int | None = None,
        since_ts: str | None = None,
        severity: str | None = None,
    ) -> list[dict[str, object]]:
        """Return a list of incident rows for the operator UX.

        Filters apply additively. `category` is a glob — matched with SQL LIKE
        after substituting `*` → `%`. `since_id` returns rows with `id > since_id`
        (used by the long-poll tail). `since_ts` filters rows whose SQLite
        timestamp is on or after the provided UTC timestamp string.
        """
        clauses: list[str] = []
        params: list[object] = []
        if session_id:
            clauses.append("session_id = ?")
            params.append(session_id)
        if category:
            clauses.append("attack_category LIKE ?")
            params.append(category.replace("*", "%"))
        if since_id is not None:
            clauses.append("id > ?")
            params.append(since_id)
        if since_ts:
            clauses.append("ts >= ?")
            params.append(since_ts)
        if severity:
            clauses.append("severity = ?")
            params.append(severity)

        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        sql = (
            "SELECT id, ts, session_id, attack_category, signal_id, action, "
            "risk_score, severity, triggered_canary, quarantine_id, source_tool, chunk_index, chunk_metadata "
            f"FROM Incident {where} ORDER BY id ASC LIMIT ?"
        )
        params.append(limit)

        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            rows = conn.execute(sql, params).fetchall()
        finally:
            conn.close()

        return [dict(row) for row in rows]

    def get_incident(self, incident_id: object) -> dict[str, object] | None:
        """Return one incident by ID or None.

        Accepts a string (e.g. the SDK's `incident.get` payload) or int.
        """
        if isinstance(incident_id, bool) or not isinstance(incident_id, (int, str)):
            return None
        try:
            normalized = int(incident_id)
        except (TypeError, ValueError):
            return None

        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            row = conn.execute(
                "SELECT id, ts, session_id, attack_category, signal_id, action, "
                "risk_score, triggered_canary, quarantine_id, input_hash, "
                "output_hash, encoding_flag, destinations, source_tool, chunk_index, chunk_metadata "
                "FROM Incident WHERE id = ?",
                (normalized,),
            ).fetchone()
        finally:
            conn.close()
        return dict(row) if row else None

    def infer_category(self, verdict: Verdict, source: str | None = None) -> str:
        """Public wrapper around `_infer_category` (task 134).

        Lets callers outside this module (e.g. the daemon's audit-trail emit path)
        derive the same `attack_category` string that the SQLite `Incident` row is
        written with, without duplicating the inference logic.

        Args:
            verdict: The verdict.
            source: Payload source (e.g., "tool_result_untrusted", "user_input").

        Returns:
            Attack category string.
        """
        return self._infer_category(verdict, source)

    def _infer_category(self, verdict: Verdict, source: str | None = None) -> str:
        """Infer attack category from signal_id and source.

        For check.fetched requests (source=tool_result_untrusted or similar), regex signals
        are categorized as indirect_injection.<vector>. For other sources, they're direct_injection.<vector>.

        Args:
            verdict: The verdict.
            source: Payload source (e.g., "tool_result_untrusted", "user_input").

        Returns:
            Attack category string.
        """
        if not verdict.signal_id:
            return "unknown"

        signal_id = verdict.signal_id
        prefix = signal_id.split(":")[0]

        # Map of regex signal families to their vector names
        regex_vector_map = {
            "regex.instruction_override": "instruction_override",
            "regex.roleplay_hijack": "roleplay_hijack",
            "regex.system_prompt_extraction": "system_prompt_extraction",
            "regex.encoding_request": "encoding_request",
            "regex.authority_impersonation": "authority_impersonation",
            "regex.memory_planting": "memory_planting",
        }

        # Determine if this is an indirect injection (from fetched tool result)
        is_indirect = source in ("tool_result_untrusted", "tool_result_trusted")

        # Handle regex signals
        if prefix in regex_vector_map:
            vector = regex_vector_map[prefix]
            if is_indirect:
                return f"indirect_injection.{vector}"
            else:
                return f"direct_injection.{vector}"

        # Cross-boundary override tripwire (ADR-043 §3): always categorized as
        # indirect_injection.cross_boundary regardless of which reused corpus rule
        # fired or whether the source was trusted/untrusted (the detector only runs
        # on external-origin content).
        if prefix == "cross_boundary_override":
            return "indirect_injection.cross_boundary"

        # Handle other signal types
        if prefix.startswith("canary."):
            return "exfiltration.canary_leak"
        elif prefix.startswith("cmd_injection."):
            return "tool_abuse.command_injection"
        elif prefix.startswith("tool_param."):
            return "tool_abuse.parameter_validation"
        elif prefix.startswith("meta."):
            return "meta.anomaly"
        elif prefix.startswith("entropy."):
            return "exfiltration.encoding"
        elif prefix.startswith("extractor."):
            return "exfiltration.destination"
        else:
            return f"{prefix}.unknown"
