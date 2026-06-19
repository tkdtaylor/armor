# SPDX-License-Identifier: Apache-2.0
"""Exponential moving average (EMA) cache for topic-coherence EMA tracking.

Maintains per-session rolling windows of embeddings for EMA calculation.
"""

import logging
from collections import deque

import numpy as np

logger = logging.getLogger(__name__)


class EMACache:
    """In-memory cache of rolling embedding windows per session.

    Each session has a rolling window of the N most recent embeddings,
    and a computed EMA vector. When a session ends or is cleared, its
    state is garbage-collected.

    Attributes:
        _sessions: Dict mapping session_id -> (window, ema_vector).
        window_size: Number of embeddings to keep in the rolling window.
        decay_factor: EMA decay factor (alpha). Higher = more recent weight.
    """

    def __init__(self, window_size: int = 5, decay_factor: float = 0.3) -> None:
        """Initialize the EMA cache.

        Args:
            window_size: Number of embeddings to keep (default 5 turns).
            decay_factor: EMA alpha parameter (default 0.3, meaning recent turns weighted 30%).
        """
        self.window_size = window_size
        self.decay_factor = decay_factor
        self._sessions: dict[str, tuple[deque[np.ndarray], np.ndarray | None]] = {}

    def update(self, session_id: str, embedding: np.ndarray) -> np.ndarray | None:
        """Update the EMA for a session with a new embedding.

        On the first call for a session, seeds the window and returns None (no EMA yet).
        On subsequent calls, computes and returns the new EMA.

        Args:
            session_id: The session identifier.
            embedding: New embedding vector (should be normalized).

        Returns:
            The updated EMA vector if the window has ≥1 prior embedding,
            or None on the first call (warm-up: no advisory on turn 1).
        """
        if session_id not in self._sessions:
            # First embedding for this session: seed the window
            window: deque[np.ndarray] = deque(maxlen=self.window_size)
            window.append(embedding)
            self._sessions[session_id] = (window, None)
            logger.debug(f"EMA cache: seeded session {session_id} with first embedding")
            return None

        window, current_ema = self._sessions[session_id]

        # Check if we have at least one prior embedding
        if current_ema is None and len(window) == 1:
            # Second embedding: compute initial EMA from the window
            # For now, use simple averaging
            window.append(embedding)
            ema_vec = np.mean(np.array(list(window)), axis=0)
            # Normalize
            norm = np.linalg.norm(ema_vec)
            ema: np.ndarray = (ema_vec / norm) if norm > 0 else ema_vec
            self._sessions[session_id] = (window, ema)
            logger.debug(f"EMA cache: initialized EMA for session {session_id}")
            return ema

        # Subsequent embeddings: update EMA using exponential moving average formula
        # EMA_new = alpha * x + (1 - alpha) * EMA_old
        if current_ema is not None:
            window.append(embedding)
            new_ema = self.decay_factor * embedding + (1 - self.decay_factor) * current_ema
            # Normalize
            norm = np.linalg.norm(new_ema)
            normalized_ema = (new_ema / norm) if norm > 0 else new_ema
            self._sessions[session_id] = (window, normalized_ema)
            return normalized_ema

        return None

    def get(self, session_id: str) -> np.ndarray | None:
        """Get the current EMA for a session.

        Args:
            session_id: The session identifier.

        Returns:
            The current EMA vector, or None if not yet computed.
        """
        if session_id in self._sessions:
            _, ema = self._sessions[session_id]
            return ema
        return None

    def clear(self, session_id: str) -> None:
        """Clear the EMA state for a session.

        Args:
            session_id: The session identifier.
        """
        if session_id in self._sessions:
            del self._sessions[session_id]
            logger.debug(f"EMA cache: cleared session {session_id}")

    def clear_all(self) -> None:
        """Clear all sessions from the cache."""
        self._sessions.clear()
        logger.debug("EMA cache: cleared all sessions")

    def __len__(self) -> int:
        """Return the number of cached sessions."""
        return len(self._sessions)
