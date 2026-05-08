"""Detector for tool-call rate anomalies.

Detects abnormally bursty per-tool call patterns within a session using a sliding window.
State is in-memory, per-session, per-tool. Expires entries older than the configured window.
"""

import logging
import time
from collections import defaultdict, deque
from collections.abc import Callable
from typing import ClassVar

from armor.types import Payload, SessionContext, Verdict

logger = logging.getLogger(__name__)

# Global per-session, per-tool state: dict[session_id, dict[tool_name, deque[(timestamp, tool_name)]]]
_session_windows: dict[str, dict[str, deque[tuple[float, str]]]] = defaultdict(lambda: defaultdict(deque))


class ToolRateAnomaly:
    """Detector for tool-call rate anomalies within a session.

    Uses a sliding window per (session_id, tool_name) to track call timestamps.
    When the number of calls within the window exceeds the threshold for that tool,
    emits an advisory verdict with confidence based on the excess ratio.

    Attributes:
        id: Detector identifier.
        category: Attack category ("meta" for system-level).
        cost_tier: "static" (in-memory, no ML).
        window_seconds: Sliding window duration (default 60).
        thresholds: Dict of tool_name -> max_calls_per_window (default thresholds provided).
    """

    id: str = "meta.tool_rate_anomaly"
    category: str = "meta"
    cost_tier: str = "static"

    # Default thresholds: calls per 60-second window
    DEFAULT_THRESHOLDS: ClassVar[dict[str, int]] = {
        "WebFetch": 10,
        "Read": 30,
        "Bash": 20,
        "Write": 15,
        "Grep": 60,
        "default": 30,
    }

    def __init__(
        self,
        window_seconds: int = 60,
        thresholds: dict[str, int] | None = None,
    ) -> None:
        """Initialize the tool-rate anomaly detector.

        Args:
            window_seconds: Sliding window duration in seconds (default 60).
            thresholds: Dict mapping tool_name to max calls per window.
                       If a tool is not in this dict, uses thresholds.get("default").
        """
        self.window_seconds = window_seconds
        self.thresholds = thresholds or self.DEFAULT_THRESHOLDS.copy()

        # Ensure default threshold is present
        if "default" not in self.thresholds:
            self.thresholds["default"] = self.DEFAULT_THRESHOLDS["default"]

    def check(
        self,
        payload: Payload,
        ctx: SessionContext,
        now_fn: Callable[[], float] | None = None,
    ) -> Verdict:
        """Check a tool-call payload for rate anomalies.

        Args:
            payload: The payload being checked (should have tool name).
            ctx: Session context (includes session_id).
            now_fn: Callable to get current time (for testing). Defaults to time.time.

        Returns:
            Advisory verdict if burst detected, pass otherwise.
        """
        try:
            # Default to time.time if not provided
            if now_fn is None:
                now_fn = time.time

            # Get current time
            try:
                now = now_fn()
            except Exception as e:
                logger.error(f"Error calling now_fn: {e}")
                now = time.time()

            # Extract tool name
            tool_name = payload.tool
            if not tool_name or not isinstance(tool_name, str) or not tool_name.strip():
                return Verdict.pass_verdict(message="No tool specified")

            # Get the sliding window for this (session_id, tool_name)
            session_windows = _session_windows[ctx.session_id]
            window = session_windows[tool_name]

            # Trim old entries outside the window
            window_start = now - self.window_seconds
            while window and window[0][0] < window_start:
                window.popleft()

            # Add the current call
            window.append((now, tool_name))

            # Count current entries in the window
            observed = len(window)

            # Get threshold for this tool
            threshold = self.thresholds.get(tool_name, self.thresholds.get("default", 30))

            # Check if over threshold
            if observed > threshold:
                # Compute confidence: min(1.0, observed / threshold - 1.0)
                confidence = min(1.0, max(0.0, observed / threshold - 1.0))

                signal_id = f"{self.id}:{tool_name}"
                return Verdict.advisory_verdict(
                    signal_id=signal_id,
                    severity="medium",
                    message=f"Tool call rate anomaly detected for {tool_name}",
                    details={
                        "observed": observed,
                        "threshold": threshold,
                        "window_seconds": self.window_seconds,
                        "confidence": confidence,
                        "tool": tool_name,
                    },
                )

            # Below threshold: pass
            return Verdict.pass_verdict(
                message="Tool call rate within normal range",
                details={
                    "observed": observed,
                    "threshold": threshold,
                    "window_seconds": self.window_seconds,
                    "tool": tool_name,
                },
            )

        except Exception as e:
            logger.error(f"Tool-rate anomaly detector error: {e}", exc_info=True)
            return Verdict.error_verdict(
                reason=f"Tool-rate anomaly detector error: {e!s}",
                details={"detector_id": self.id, "error": str(e)},
            )
