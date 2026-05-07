"""Session state machine with cooldown rules.

This module implements a five-state finite state machine (Normal → Watching → Elevated
→ High → Blocked) that aggregates detector signals into a session-level risk level,
gates expensive detectors on that level, and decays back toward Normal over time.

The core function apply_signal() is pure: given inputs, it deterministically produces
outputs without side effects or implicit time calls.

`clear_blocked()` is the only sanctioned exit from `Blocked`. It is invoked by
the `armor sessions unblock` operator command and writes a row to
`OperatorAuditLog` in the same transaction as the state mutation.
"""

import os
import sqlite3
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from armor.db import operator_audit
from armor.types import Verdict


class InvalidStateTransition(Exception):  # noqa: N818  — spec-mandated name (TC-036-08)
    """Raised when an operator-clear action is requested for a non-Blocked session."""


class SessionState(StrEnum):
    """Five states of the session FSM, ordered by risk level."""

    NORMAL = "Normal"
    WATCHING = "Watching"
    ELEVATED = "Elevated"
    HIGH = "High"
    BLOCKED = "Blocked"

    def __lt__(self, other: object) -> bool:
        """Compare state severity."""
        if not isinstance(other, SessionState):
            return NotImplemented
        order = [
            SessionState.NORMAL,
            SessionState.WATCHING,
            SessionState.ELEVATED,
            SessionState.HIGH,
            SessionState.BLOCKED,
        ]
        return order.index(self) < order.index(other)

    def __le__(self, other: object) -> bool:
        """Compare state severity."""
        if not isinstance(other, SessionState):
            return NotImplemented
        return self < other or self == other

    def __gt__(self, other: object) -> bool:
        """Compare state severity."""
        if not isinstance(other, SessionState):
            return NotImplemented
        return not (self <= other)

    def __ge__(self, other: object) -> bool:
        """Compare state severity."""
        if not isinstance(other, SessionState):
            return NotImplemented
        return not (self < other)


def _get_threshold(config: dict[str, Any], threshold_name: str, default: float) -> float:
    """Extract a threshold value from config with fallback.

    Args:
        config: Configuration dictionary.
        threshold_name: Name of the threshold (e.g., 'watching', 'elevated', 'high').
        default: Default value if not found.

    Returns:
        The threshold value.
    """
    # Try nested config[session.thresholds.X]
    session_config = config.get("session", {})
    if isinstance(session_config, dict):
        thresholds = session_config.get("thresholds", {})
        if isinstance(thresholds, dict):
            val = thresholds.get(threshold_name, default)
            if isinstance(val, (int, float)):
                return float(val)
    return default


def _get_decay_rate(config: dict[str, Any], default: float = 0.1) -> float:
    """Extract the cooldown decay rate from config with fallback.

    Args:
        config: Configuration dictionary.
        default: Default value if not found (default 0.1 per minute).

    Returns:
        The cooldown decay rate (per minute).
    """
    session_config = config.get("session", {})
    if isinstance(session_config, dict):
        val = session_config.get("cooldown_decay_per_min", default)
        if isinstance(val, (int, float)):
            return float(val)
    return default


def _get_detector_weight(config: dict[str, Any], detector_id: str, default: float = 1.0) -> float:
    """Extract a per-detector signal weight from config with fallback.

    Args:
        config: Configuration dictionary.
        detector_id: The detector ID (e.g., 'llm.validator', 'regex.encoding_request').
        default: Default value if not found (default 1.0).

    Returns:
        The signal weight for this detector.
    """
    session_config = config.get("session", {})
    if isinstance(session_config, dict):
        signal_weights = session_config.get("signal_weights", {})
        if isinstance(signal_weights, dict):
            val = signal_weights.get(detector_id, default)
            if isinstance(val, (int, float)):
                return float(val)
    return default


def apply_signal(
    current_state: SessionState,
    current_score: float,
    signal: Verdict,
    last_signal_at: datetime,
    now: datetime,
    config: dict[str, Any] | None = None,
) -> tuple[SessionState, float]:
    """Apply a signal to the session state machine (pure function).

    This function is deterministic and has no side effects. It composes the following
    steps:
    1. Compute cooldown decay based on elapsed time since last_signal_at.
    2. Step back the state if post-decay score falls below the current state's threshold.
    3. Apply the new signal (advisory contributes confidence*weight; block jumps to Blocked).
    4. Step forward the state if post-signal score exceeds the next rung's threshold.
    5. Return (new_state, new_score).

    Args:
        current_state: The session's current state (Normal, Watching, Elevated, High, or Blocked).
        current_score: The session's current risk score (non-negative float).
        signal: The new signal (Verdict with decision="advisory" or "block").
        last_signal_at: Timestamp of the last signal (for cooldown calculation).
        now: Current wall-clock time. Passed by caller (no implicit time.time() call).
        config: Configuration dict with thresholds, weights, and decay rate.
                If None, uses hardcoded defaults (for backward compat).

    Returns:
        Tuple of (new_state, new_score).

    Design notes:
    - Blocked is terminal under signal pressure. The only exit is the operator
      action `clear_blocked()` (called by `armor sessions unblock`), which
      atomically transitions Blocked → Watching and writes an
      `OperatorAuditLog` row.
    - Score floor: clamped at 0.0; decay cannot drive negative.
    - Step-back is one rung per call: prevents "falling off the ladder" in a single call.
    - Multi-rung step-forward is allowed: a single large advisory can jump multiple rungs.
    """
    if config is None:
        config = {}

    # Load thresholds with defaults
    threshold_watching = _get_threshold(config, "watching", 0.4)
    threshold_elevated = _get_threshold(config, "elevated", 0.9)
    threshold_high = _get_threshold(config, "high", 1.5)
    decay_rate = _get_decay_rate(config, 0.1)

    # Step 1: If in Blocked, short-circuit (Blocked is terminal)
    if current_state == SessionState.BLOCKED:
        return (SessionState.BLOCKED, current_score)

    # Step 2: Apply cooldown decay
    elapsed = (now - last_signal_at).total_seconds() / 60.0  # Convert to minutes
    decay_amount = decay_rate * elapsed
    decayed_score = max(0.0, current_score - decay_amount)

    # Step 3: Check if decay moves us down a rung (single rung per call)
    post_decay_state = current_state
    if current_state == SessionState.WATCHING and decayed_score < threshold_watching:
        post_decay_state = SessionState.NORMAL
    elif current_state == SessionState.ELEVATED and decayed_score < threshold_watching:
        post_decay_state = SessionState.WATCHING
    elif current_state == SessionState.HIGH and decayed_score < threshold_elevated:
        post_decay_state = SessionState.ELEVATED

    # Step 4: Apply the new signal
    new_score = decayed_score
    new_state = post_decay_state

    if signal.decision == "block":
        # Block signal: jump directly to Blocked regardless of score
        return (SessionState.BLOCKED, new_score)

    if signal.decision == "advisory":
        # Advisory signal: add confidence * weight to score
        confidence = signal.details.get("confidence", 0.0)
        if not isinstance(confidence, (int, float)):
            confidence = 0.0
        detector_id = signal.signal_id.split(":")[0] if signal.signal_id else "unknown"
        weight = _get_detector_weight(config, detector_id, 1.0)
        new_score = decayed_score + (confidence * weight)

    # Step 5: Check if new score moves us up (can skip multiple rungs in one call)
    if new_state == SessionState.NORMAL:
        if new_score >= threshold_high:
            new_state = SessionState.HIGH
        elif new_score >= threshold_elevated:
            new_state = SessionState.ELEVATED
        elif new_score >= threshold_watching:
            new_state = SessionState.WATCHING

    elif new_state == SessionState.WATCHING:
        if new_score >= threshold_high:
            new_state = SessionState.HIGH
        elif new_score >= threshold_elevated:
            new_state = SessionState.ELEVATED
    elif new_state == SessionState.ELEVATED and new_score >= threshold_high:
        new_state = SessionState.HIGH

    # Step 6: Return new state and score
    return (new_state, new_score)


def _default_actor() -> str:
    return os.environ.get("USER", "operator") or "operator"


def clear_blocked(
    session_id: str,
    actor: str | None = None,
    reason: str = "",
    *,
    db_path: str,
) -> SessionState:
    """Atomically clear a Blocked session and write an audit-log row.

    Pre-conditions:
      - The session exists.
      - The session's `current_state` is `Blocked`.
      - `reason` is a non-empty string.

    Post-conditions on success:
      - `Session.current_state == "Watching"`.
      - Exactly one new row in `OperatorAuditLog` with
        `(actor, action="session.unblock", session_id, reason)`.

    The state mutation and the audit-log insert run in a single SQLite
    transaction. If either fails, both are rolled back and the session
    remains `Blocked` with no audit row written.
    """
    if not reason or not reason.strip():
        raise ValueError("clear_blocked requires a non-empty reason")

    effective_actor = actor or _default_actor()
    ts = datetime.now(UTC).isoformat().replace("+00:00", "Z")

    conn = sqlite3.connect(db_path)
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT current_state FROM Session WHERE session_id = ?",
            (session_id,),
        )
        row = cur.fetchone()
        if row is None:
            raise InvalidStateTransition(f"unknown session {session_id!r}")
        if row[0] != SessionState.BLOCKED.value:
            raise InvalidStateTransition(f"session {session_id!r} is in state {row[0]!r}, not Blocked")

        try:
            cur.execute("BEGIN")
            cur.execute(
                "UPDATE Session SET current_state = ? WHERE session_id = ?",
                (SessionState.WATCHING.value, session_id),
            )
            operator_audit._insert_unblock_row(cur, session_id, effective_actor, reason, ts)
            conn.commit()
        except Exception:
            conn.rollback()
            raise
    finally:
        conn.close()

    return SessionState.WATCHING
