# SPDX-License-Identifier: Apache-2.0
"""Session store: LRU cache + SQLite persistence for session state."""

import asyncio
import json
import logging
import sqlite3
import time
from dataclasses import dataclass, field
from datetime import datetime

from armor.session.rolling_buffer import RollingBuffer
from armor.session.state_machine import SessionState, apply_signal
from armor.types import Verdict

logger = logging.getLogger(__name__)


@dataclass
class SessionRow:
    """In-memory representation of a session row."""

    session_id: str
    created_at: str
    last_seen_at: str
    current_state: str
    risk_score: float
    turn_count: int
    signal_history: list[dict[str, object]] = field(default_factory=list)
    last_signal_at: float = 0.0  # Unix timestamp of last signal (for cooldown calculation)


class SessionStore:
    """LRU-cached session store with SQLite persistence.

    Attributes:
        db_path: Path to SQLite database.
        cache_size: Max sessions in memory (default 1024).
        _locks: Per-session asyncio.Lock for concurrency control.
        _cache: LRU dict of SessionRow keyed by session_id.
    """

    def __init__(self, db_path: str, cache_size: int = 1024) -> None:
        """Initialize the session store.

        Args:
            db_path: Path to SQLite database.
            cache_size: Maximum in-memory sessions (default 1024).
        """
        self.db_path = db_path
        self.cache_size = cache_size
        self._locks: dict[str, asyncio.Lock] = {}
        self._cache: dict[str, SessionRow] = {}
        self._cache_access_order: list[str] = []  # Track LRU order

    async def get_or_create(self, session_id: str) -> SessionRow:
        """Get or create a session.

        Args:
            session_id: The session ID.

        Returns:
            SessionRow for the session.
        """
        # Get or create per-session lock
        if session_id not in self._locks:
            self._locks[session_id] = asyncio.Lock()

        async with self._locks[session_id]:
            # Check cache first
            if session_id in self._cache:
                self._update_lru(session_id)
                return self._cache[session_id]

            # Load from DB or create
            row = await asyncio.to_thread(self._load_or_create_from_db, session_id)

            # Cache it
            self._cache[session_id] = row
            self._update_lru(session_id)

            # Evict if cache is full
            if len(self._cache) > self.cache_size:
                self._evict_lru()

            return row

    async def apply_and_persist(
        self,
        session_id: str,
        verdict: Verdict,
        config: dict[str, object] | None = None,
    ) -> tuple[str, float]:
        """Apply a signal to the session state machine and persist.

        This is the main integration point: applies cooldown decay, updates state based
        on the new signal, and persists to DB. Used by the daemon to gate detectors
        and update session state atomically.

        Args:
            session_id: The session ID.
            verdict: The verdict (signal) to apply.
            config: Configuration dict (thresholds, weights, decay rate).

        Returns:
            Tuple of (new_state_str, new_risk_score).
        """
        if session_id not in self._locks:
            self._locks[session_id] = asyncio.Lock()

        async with self._locks[session_id]:
            # Get or create session
            if session_id in self._cache:
                row = self._cache[session_id]
            else:
                row = await asyncio.to_thread(self._load_or_create_from_db, session_id)
                self._cache[session_id] = row
                self._update_lru(session_id)

            # Apply state machine
            current_state = SessionState(row.current_state)
            now = datetime.now()
            last_signal_at = datetime.fromtimestamp(row.last_signal_at)

            new_state, new_score = apply_signal(
                current_state=current_state,
                current_score=row.risk_score,
                signal=verdict,
                last_signal_at=last_signal_at,
                now=now,
                config=config or {},
            )

            # Update row with new state and score
            row.current_state = new_state.value
            row.risk_score = new_score
            row.last_signal_at = now.timestamp()

            # Update turn count and last_seen_at
            row.turn_count += 1
            row.last_seen_at = time.strftime("%Y-%m-%d %H:%M:%S")

            # Add signal to history
            if verdict.signal_id:
                signal = {
                    "ts": time.time(),
                    "kind": verdict.signal_id.split(":")[0],  # Category before colon
                    "signal_id": verdict.signal_id,
                    "severity": verdict.severity,
                }
                row.signal_history.append(signal)

                # Keep only last 50 signals
                if len(row.signal_history) > 50:
                    row.signal_history = row.signal_history[-50:]

            # Persist to DB
            await asyncio.to_thread(self._persist_to_db, row)

            return (new_state.value, new_score)

    async def close_session(self, session_id: str) -> None:
        """Mark a session as closed.

        Currently a no-op: row deletion is out of scope for the in-process
        daemon. A periodic sweeper for ended sessions and their rolling-buffer
        rows is tracked separately as a deferred hygiene task (see
        data-model.md → SessionRollingBuffer "Cleanup").

        Args:
            session_id: The session ID.
        """
        return

    def _update_lru(self, session_id: str) -> None:
        """Update LRU access order for a session."""
        if session_id in self._cache_access_order:
            self._cache_access_order.remove(session_id)
        self._cache_access_order.append(session_id)

    def _evict_lru(self) -> None:
        """Evict the least-recently-used session from cache."""
        if self._cache_access_order:
            oldest_id = self._cache_access_order.pop(0)
            del self._cache[oldest_id]
            logger.debug(f"Evicted session {oldest_id} from LRU cache")

    def _load_or_create_from_db(self, session_id: str) -> SessionRow:
        """Load a session from DB or create a new one.

        This is a synchronous method called via asyncio.to_thread.

        Args:
            session_id: The session ID.

        Returns:
            SessionRow.
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.cursor()

            # Try to load existing session
            cursor.execute(
                "SELECT session_id, created_at, last_seen_at, current_state, risk_score, turn_count, signal_history, last_signal_at FROM Session WHERE session_id = ?",
                (session_id,),
            )
            row = cursor.fetchone()

            if row:
                return SessionRow(
                    session_id=row["session_id"],
                    created_at=row["created_at"],
                    last_seen_at=row["last_seen_at"],
                    current_state=row["current_state"],
                    risk_score=float(row["risk_score"]),
                    turn_count=row["turn_count"],
                    signal_history=json.loads(row["signal_history"]),
                    last_signal_at=float(row["last_signal_at"]),
                )

            # Create new session
            now_str = time.strftime("%Y-%m-%d %H:%M:%S")
            now_timestamp = time.time()
            cursor.execute(
                "INSERT INTO Session (session_id, created_at, last_seen_at, current_state, risk_score, turn_count, signal_history, last_signal_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (session_id, now_str, now_str, "Normal", 0.0, 0, json.dumps([]), now_timestamp),
            )
            conn.commit()

            return SessionRow(
                session_id=session_id,
                created_at=now_str,
                last_seen_at=now_str,
                current_state="Normal",
                risk_score=0.0,
                turn_count=0,
                signal_history=[],
                last_signal_at=now_timestamp,
            )

        finally:
            conn.close()

    def _persist_to_db(self, row: SessionRow) -> None:
        """Persist a session row to DB.

        This is a synchronous method called via asyncio.to_thread.

        Args:
            row: The SessionRow to persist.
        """
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()

            cursor.execute(
                "UPDATE Session SET last_seen_at = ?, current_state = ?, risk_score = ?, turn_count = ?, signal_history = ?, last_signal_at = ? WHERE session_id = ?",
                (
                    row.last_seen_at,
                    row.current_state,
                    row.risk_score,
                    row.turn_count,
                    json.dumps(row.signal_history),
                    row.last_signal_at,
                    row.session_id,
                ),
            )
            conn.commit()

        finally:
            conn.close()

    def save_rolling_buffer(self, session_id: str, buffer: RollingBuffer) -> None:
        """Persist rolling buffer entries to the SessionRollingBuffer table.

        This is a synchronous method. It appends all current entries in the buffer
        to the database. Existing entries are not deleted (append-only semantics).

        Args:
            session_id: The session ID.
            buffer: The RollingBuffer instance to persist.
        """
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()
            now_str = time.strftime("%Y-%m-%d %H:%M:%S")

            for entry in buffer.entries():
                cursor.execute(
                    "INSERT INTO SessionRollingBuffer (session_id, turn_id, text, created_at) VALUES (?, ?, ?, ?)",
                    (session_id, entry.turn_id, entry.text, now_str),
                )

            conn.commit()

        finally:
            conn.close()

    def load_rolling_buffer(
        self, session_id: str, capacity_chars: int = 8192, capacity_turns: int = 20
    ) -> RollingBuffer:
        """Load rolling buffer entries from the SessionRollingBuffer table.

        Reconstructs the RollingBuffer from the database, applying the capacity
        limits. Returns an empty buffer if the session has no entries.

        Args:
            session_id: The session ID.
            capacity_chars: Character capacity for the buffer (default 8192).
            capacity_turns: Turn capacity for the buffer (default 20).

        Returns:
            RollingBuffer instance reconstructed from database entries.
        """
        buffer = RollingBuffer(capacity_chars=capacity_chars, capacity_turns=capacity_turns)

        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.cursor()

            # Load all entries for this session, ordered by creation (oldest first)
            cursor.execute(
                "SELECT turn_id, text FROM SessionRollingBuffer WHERE session_id = ? ORDER BY created_at ASC",
                (session_id,),
            )
            rows = cursor.fetchall()

            # Re-append entries to reconstruct the buffer (and apply capacity limits)
            for row in rows:
                buffer.append(row["turn_id"], row["text"])

            return buffer

        finally:
            conn.close()

    def list_sessions(self, state: str | None = None) -> list[dict[str, object]]:
        """Return all sessions (optionally filtered by state) for the operator UX."""
        sql = "SELECT session_id, created_at, last_seen_at, current_state, risk_score, turn_count FROM Session"
        params: list[object] = []
        if state:
            sql += " WHERE current_state = ?"
            params.append(state)
        sql += " ORDER BY last_seen_at DESC"

        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            rows = conn.execute(sql, params).fetchall()
        finally:
            conn.close()
        return [dict(r) for r in rows]

    def get_session_view(self, session_id: str) -> dict[str, object] | None:
        """Return one session's full view (state, risk, signal-history summary).

        Never includes raw rolling-buffer text — only a hash and signal counts.
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            row = conn.execute(
                "SELECT session_id, created_at, last_seen_at, current_state, "
                "risk_score, turn_count, signal_history, last_signal_at "
                "FROM Session WHERE session_id = ?",
                (session_id,),
            ).fetchone()
        finally:
            conn.close()

        if row is None:
            return None

        signal_history = json.loads(row["signal_history"] or "[]")
        return {
            "session_id": row["session_id"],
            "created_at": row["created_at"],
            "last_seen_at": row["last_seen_at"],
            "current_state": row["current_state"],
            "risk_score": float(row["risk_score"]),
            "turn_count": row["turn_count"],
            "signal_count": len(signal_history),
            "signal_history": signal_history,
        }

    def clear_rolling_buffer(self, session_id: str) -> None:
        """Clear all rolling buffer entries for a session.

        Used when a session ends or is explicitly reset.

        Args:
            session_id: The session ID.
        """
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM SessionRollingBuffer WHERE session_id = ?", (session_id,))
            conn.commit()

        finally:
            conn.close()
