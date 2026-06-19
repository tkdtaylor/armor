# SPDX-License-Identifier: Apache-2.0
"""Token-count anomaly detector for detecting context overflow and token-budget exploitation.

Detects when a user suddenly submits significantly longer input than their session history,
which can signal an attempt to consume token budget or overflow context limits.

Example:
  "help me debug this" (5 turns, ~200 bytes each)
  -> "here is a 100 KB file to analyze" (advisory)

The detector tracks running mean and std-dev of input lengths per session using Welford's
online algorithm. On each turn, it computes z-score and fires advisory for:
- z-score > threshold (default 3.0), or
- absolute length > cap (default 32768 bytes)
"""

import logging
import math
from dataclasses import dataclass

from armor.types import Payload, SessionContext, Verdict

logger = logging.getLogger(__name__)


@dataclass
class SessionLengthStats:
    """Running statistics for input lengths in a session using Welford's algorithm.

    Attributes:
        count: Number of turns observed (n).
        mean: Running mean of input lengths.
        M2: Running sum of squares of differences (used for variance).
    """

    count: int = 0
    mean: float = 0.0
    M2: float = 0.0

    def update(self, length: float) -> None:
        """Update running stats with a new length using Welford's algorithm.

        Args:
            length: The new input length to incorporate.
        """
        self.count += 1
        delta = length - self.mean
        self.mean += delta / self.count
        delta2 = length - self.mean
        self.M2 += delta * delta2

    def variance(self) -> float:
        """Compute the sample variance.

        Returns:
            Sample variance (0 if count < 2).
        """
        if self.count < 2:
            return 0.0
        return self.M2 / (self.count - 1)

    def std_dev(self) -> float:
        """Compute the sample standard deviation.

        Returns:
            Sample std-dev (0 if count < 2).
        """
        return math.sqrt(self.variance())


# Global per-session length stats cache (in-memory; lost on daemon restart per ADR-037)
# Keyed by session_id; bounded by session.cache_size
_length_stats_cache: dict[str, SessionLengthStats] = {}


class TokenCountAnomaly:
    """Detector for anomalous input lengths within a session.

    Uses running mean and std-dev to detect context-overflow and token-budget-exploitation
    attempts. Emits advisory verdicts when input length deviates significantly from session
    baseline.

    Attributes:
        id: Detector identifier.
        category: Attack category ("meta" for system-level).
        cost_tier: "static" (local computation, no LLM).
        absolute_cap_bytes: Max input length (default 32768).
        sigma_threshold: Z-score threshold for advisory (default 3.0).
        min_history_turns: Minimum turns to establish baseline (default 3).
    """

    id: str = "meta.token_count_anomaly"
    category: str = "meta"
    cost_tier: str = "static"

    def __init__(
        self,
        absolute_cap_bytes: int = 32768,
        sigma_threshold: float = 3.0,
        min_history_turns: int = 3,
    ) -> None:
        """Initialize the token-count-anomaly detector.

        Args:
            absolute_cap_bytes: Absolute max input length in bytes (default 32768).
            sigma_threshold: Z-score threshold for advisory (default 3.0).
            min_history_turns: Minimum turns to warm up (default 3).
        """
        self.absolute_cap_bytes = absolute_cap_bytes
        self.sigma_threshold = sigma_threshold
        self.min_history_turns = min_history_turns

    def check(self, payload: Payload, ctx: SessionContext) -> Verdict:
        """Check a payload for anomalous input length.

        Computes payload byte length, compares against running session stats,
        and returns advisory if z-score exceeds threshold OR length exceeds cap.

        Args:
            payload: The payload being checked.
            ctx: Session context (includes session_id).

        Returns:
            Advisory verdict if anomaly detected,
            pass verdict otherwise, or error verdict on exception.
        """
        try:
            # Handle empty payload
            if not payload.text:
                return Verdict.pass_verdict(message="Empty payload")

            # Compute payload length in bytes
            length_bytes = len(payload.text.encode("utf-8"))

            # Initialize or retrieve session stats
            if ctx.session_id not in _length_stats_cache:
                _length_stats_cache[ctx.session_id] = SessionLengthStats()

            stats = _length_stats_cache[ctx.session_id]

            # Warm-up phase: first min_history_turns are baseline-building
            if stats.count < self.min_history_turns:
                stats.update(length_bytes)
                # Even during warm-up, check absolute cap
                if length_bytes > self.absolute_cap_bytes:
                    confidence = min(1.0, length_bytes / self.absolute_cap_bytes)
                    return Verdict.advisory_verdict(
                        signal_id=f"{self.id}:absolute_cap",
                        severity="medium",
                        message="Input exceeds absolute length cap",
                        details={
                            "confidence": confidence,
                            "length_bytes": length_bytes,
                            "absolute_cap_bytes": self.absolute_cap_bytes,
                            "absolute_cap_exceeded": True,
                        },
                    )
                return Verdict.pass_verdict(
                    message=f"Token-count anomaly warm-up (turn {stats.count}/{self.min_history_turns})"
                )

            # Have established baseline: check both z-score and absolute cap
            # Compute z-score: (x - mean) / std_dev
            std_dev = stats.std_dev()
            z_score = (length_bytes - stats.mean) / std_dev if std_dev > 0 else abs(length_bytes - stats.mean)

            # Check if absolute cap is exceeded
            absolute_cap_exceeded = length_bytes > self.absolute_cap_bytes
            z_score_exceeded = z_score > self.sigma_threshold

            # Fire advisory if either condition is met
            if absolute_cap_exceeded or z_score_exceeded:
                # Scale confidence: prefer z-score if available, else absolute cap
                if z_score_exceeded:
                    confidence = min(1.0, z_score / self.sigma_threshold)
                else:
                    confidence = min(1.0, length_bytes / self.absolute_cap_bytes)

                # Update stats before returning (so next turn uses this data)
                stats.update(length_bytes)

                # Determine which signal fired
                if absolute_cap_exceeded and z_score_exceeded:
                    signal_reason = "anomaly_and_cap"
                elif absolute_cap_exceeded:
                    signal_reason = "absolute_cap"
                else:
                    signal_reason = "anomaly"

                return Verdict.advisory_verdict(
                    signal_id=f"{self.id}:{signal_reason}",
                    severity="medium",
                    message="Input length anomaly detected",
                    details={
                        "confidence": confidence,
                        "length_bytes": length_bytes,
                        "mean_bytes": float(stats.mean),
                        "std_dev_bytes": float(std_dev),
                        "z_score": float(z_score),
                        "sigma_threshold": self.sigma_threshold,
                        "absolute_cap_bytes": self.absolute_cap_bytes,
                        "absolute_cap_exceeded": absolute_cap_exceeded,
                    },
                )

            # Length within normal range: update stats and pass
            stats.update(length_bytes)
            return Verdict.pass_verdict(
                message="Token count within normal range",
                details={
                    "length_bytes": length_bytes,
                    "mean_bytes": float(stats.mean),
                    "std_dev_bytes": float(std_dev),
                    "z_score": float(z_score),
                },
            )

        except Exception as e:
            logger.error(f"Token-count-anomaly detector error: {e}", exc_info=True)
            return Verdict.error_verdict(
                reason=f"Token-count-anomaly detector error: {e!s}",
                details={"detector_id": self.id, "error": str(e)},
            )


def clear_session_cache(session_id: str) -> None:
    """Clear the length stats for a specific session.

    Args:
        session_id: The session to clear.
    """
    if session_id in _length_stats_cache:
        del _length_stats_cache[session_id]
        logger.debug(f"Token-count cache: cleared session {session_id}")


def clear_all_cache() -> None:
    """Clear all cached length stats."""
    _length_stats_cache.clear()
    logger.debug("Token-count cache: cleared all sessions")
