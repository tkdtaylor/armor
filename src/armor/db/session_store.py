"""Session store: LRU cache + SQLite persistence for session state."""

import asyncio
import json
import logging
import sqlite3
import time
from dataclasses import dataclass, field

from armor.types import Verdict

logger = logging.getLogger(__name__)

# Severity to risk score increment mapping
SEVERITY_WEIGHTS = {
    "low": 1,
    "medium": 3,
    "high": 5,
    "critical": 10,
}


@dataclass
class SessionRow:
    """In-memory representation of a session row."""

    session_id: str
    created_at: str
    last_seen_at: str
    state: str
    risk_score: int
    turn_count: int
    signal_history: list[dict[str, object]] = field(default_factory=list)


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

    async def update_after_check(self, session_id: str, verdict: Verdict) -> None:
        """Update session after a check.

        Updates turn_count, last_seen_at, signal_history, and risk_score.

        Args:
            session_id: The session ID.
            verdict: The verdict from the check.
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

            # Update turn count
            row.turn_count += 1

            # Update last_seen_at
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

            # Update risk score on block (monotone non-decreasing)
            if verdict.blocked:
                increment = SEVERITY_WEIGHTS.get(verdict.severity, 1)
                row.risk_score = min(100, row.risk_score + increment)

            # Persist to DB
            await asyncio.to_thread(self._persist_to_db, row)

    async def close_session(self, session_id: str) -> None:
        """Mark a session as closed (for future cleanup).

        In v0.1, this is a no-op. In v0.4+, this will schedule deletion after 24h.

        Args:
            session_id: The session ID.
        """
        # TODO: Implement 24h deletion in task 022
        pass

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
                "SELECT session_id, created_at, last_seen_at, state, risk_score, turn_count, signal_history FROM Session WHERE session_id = ?",
                (session_id,),
            )
            row = cursor.fetchone()

            if row:
                return SessionRow(
                    session_id=row["session_id"],
                    created_at=row["created_at"],
                    last_seen_at=row["last_seen_at"],
                    state=row["state"],
                    risk_score=row["risk_score"],
                    turn_count=row["turn_count"],
                    signal_history=json.loads(row["signal_history"]),
                )

            # Create new session
            now = time.strftime("%Y-%m-%d %H:%M:%S")
            cursor.execute(
                "INSERT INTO Session (session_id, created_at, last_seen_at, state, risk_score, turn_count, signal_history) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (session_id, now, now, "Normal", 0, 0, json.dumps([])),
            )
            conn.commit()

            return SessionRow(
                session_id=session_id,
                created_at=now,
                last_seen_at=now,
                state="Normal",
                risk_score=0,
                turn_count=0,
                signal_history=[],
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
                "UPDATE Session SET last_seen_at = ?, state = ?, risk_score = ?, turn_count = ?, signal_history = ? WHERE session_id = ?",
                (
                    row.last_seen_at,
                    row.state,
                    row.risk_score,
                    row.turn_count,
                    json.dumps(row.signal_history),
                    row.session_id,
                ),
            )
            conn.commit()

        finally:
            conn.close()
