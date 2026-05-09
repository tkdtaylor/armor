"""Core type definitions for the armor security layer.

Includes Verdict, Payload, SessionContext, and severity/decision enums.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from armor.canaries.catalogue import CanaryEntry
    from armor.session.rolling_buffer import RollingBuffer
    from armor.session.state_machine import SessionState

# Cost tier for detector budget allocation
CostTier = Literal["static", "semantic", "llm"]


class Decision(StrEnum):
    """Verdict decision type."""

    PASS = "pass"
    BLOCK = "block"
    ADVISORY = "advisory"
    ERROR = "error"


class Source(StrEnum):
    """Payload provenance / trust label (per ADR-041).

    Indicates the origin of the payload, used to scale detector strictness
    via per-source multipliers. One multiplier per source is applied to
    detector confidence before verdicts materialize.
    """

    USER_INPUT = "user_input"
    MODEL_OUTPUT = "model_output"
    TOOL_PARAMS = "tool_params"
    TOOL_RESULT_TRUSTED = "tool_result_trusted"
    TOOL_RESULT_UNTRUSTED = "tool_result_untrusted"


class Severity(StrEnum):
    """Severity level for advisory verdicts."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    def __lt__(self, other: object) -> bool:
        """Compare severity levels."""
        if not isinstance(other, Severity):
            return NotImplemented
        order = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        return order.index(self) < order.index(other)

    def __le__(self, other: object) -> bool:
        """Compare severity levels."""
        if not isinstance(other, Severity):
            return NotImplemented
        return self < other or self == other

    def __gt__(self, other: object) -> bool:
        """Compare severity levels."""
        if not isinstance(other, Severity):
            return NotImplemented
        return not (self <= other)

    def __ge__(self, other: object) -> bool:
        """Compare severity levels."""
        if not isinstance(other, Severity):
            return NotImplemented
        return not (self < other)


@dataclass(frozen=True)
class Verdict:
    """Result of running a detector or the full pipeline on a payload.

    Attributes:
        decision: Verdict outcome (pass, block, advisory, error).
        signal_id: Identifier of the triggered signal (if any).
        severity: Severity level (only relevant for advisory verdicts).
        message: Human-readable explanation.
        details: Detector-specific structured details (e.g., matched regex, offset).
    """

    decision: Literal["pass", "block", "advisory", "error"]
    signal_id: str | None
    severity: Literal["low", "medium", "high", "critical"]
    message: str
    details: dict[str, object] = field(default_factory=dict)

    @classmethod
    def pass_verdict(
        cls,
        message: str = "Input passed all checks",
        details: dict[str, object] | None = None,
    ) -> Verdict:
        """Create a pass verdict."""
        return cls(
            decision="pass",
            signal_id=None,
            severity="low",
            message=message,
            details=details or {},
        )

    @classmethod
    def block_verdict(
        cls,
        signal_id: str,
        message: str = "Input blocked",
        severity: Literal["low", "medium", "high", "critical"] = "critical",
        details: dict[str, object] | None = None,
    ) -> Verdict:
        """Create a block verdict."""
        return cls(
            decision="block",
            signal_id=signal_id,
            severity=severity,
            message=message,
            details=details or {},
        )

    @classmethod
    def advisory_verdict(
        cls,
        signal_id: str,
        severity: Literal["low", "medium", "high", "critical"] = "medium",
        message: str = "Advisory signal detected",
        details: dict[str, object] | None = None,
    ) -> Verdict:
        """Create an advisory verdict."""
        return cls(
            decision="advisory",
            signal_id=signal_id,
            severity=severity,
            message=message,
            details=details or {},
        )

    @classmethod
    def error_verdict(
        cls,
        reason: str = "Detector error",
        details: dict[str, object] | None = None,
    ) -> Verdict:
        """Create an error verdict."""
        return cls(
            decision="error",
            signal_id=None,
            severity="low",
            message=reason,
            details=details or {},
        )

    @property
    def blocked(self) -> bool:
        """Check if the verdict is a block."""
        return self.decision == "block"

    @property
    def passed(self) -> bool:
        """Check if the verdict is a pass."""
        return self.decision == "pass"

    @property
    def is_error(self) -> bool:
        """Check if the verdict is an error."""
        return self.decision == "error"


@dataclass(frozen=True)
class Payload:
    """Input or output payload being checked.

    Attributes:
        text: The text payload (for input/output checks).
        tool: Tool name (for tool-call checks).
        params: Tool parameters (for tool-call checks).
        source: Payload provenance label (per ADR-041); defaults to USER_INPUT for backwards compat.
    """

    text: str = ""
    tool: str | None = None
    params: dict[str, object] | None = None
    source: Source = Source.USER_INPUT


@dataclass
class Signal:
    """A single signal in the session history.

    Attributes:
        timestamp: When the signal was recorded.
        kind: Signal kind (detector name or category).
        signal_id: The specific signal ID.
        severity: Severity of the signal.
    """

    timestamp: float
    kind: str
    signal_id: str
    severity: str


@dataclass
class SessionContext:
    """Session-level context passed to detectors.

    Attributes:
        session_id: Unique session identifier.
        signal_history: Rolling history of signals (list of Signal objects).
        state: Session state enum level per FSM (SessionState.NORMAL, WATCHING, ELEVATED, HIGH, BLOCKED).
               Used for gating detector cost tiers and honeypot invocation (see ADR-024, B-011).
               None (default) is equivalent to NORMAL. Type-narrowed to SessionState | None
               to enforce compile-time type safety.
        rolling_buffer: Multi-turn rolling buffer for exfiltration detection across turns.
                        See ADR-025. None if not initialized.
        turn_count: Number of turns in this session (increments on each check).
                   Used for activation rules like session_turn_min. Inferred from
                   signal_history length if not set explicitly. (Per ADR-038.)
        active_canaries: List of canary entries active for this session per ADR-038.
                        Subset of the full catalogue based on activation rules.
    """

    session_id: str
    signal_history: list[Signal] = field(default_factory=list)
    state: SessionState | None = None
    rolling_buffer: RollingBuffer | None = None
    turn_count: int = 0
    active_canaries: list[CanaryEntry] = field(default_factory=list)

    @classmethod
    def empty(cls, session_id: str) -> SessionContext:
        """Create an empty SessionContext for backward-compatible test construction.

        Returns a context with all fields zero/empty for use in tests that
        construct SessionContext directly.

        Args:
            session_id: The session ID for the context.

        Returns:
            SessionContext with empty defaults.
        """
        return cls(
            session_id=session_id,
            signal_history=[],
            state=None,
            rolling_buffer=None,
            turn_count=0,
            active_canaries=[],
        )


@dataclass
class HealthReport:
    """Health status report from the armor daemon.

    Attributes:
        daemon_reachable: Whether the daemon is responding.
        socket_reachable: Whether the daemon's Unix socket server is active.
        db_reachable: Whether the SQLite database is accessible.
        model_loaded: Whether the validator LLM is loaded and ready.
        version: Version of the armor daemon.
        uptime_seconds: Daemon uptime in seconds (if available).
        active_connections: Current number of active daemon connections.
        max_concurrent: Configured concurrent connection cap.
        total_checks: Number of check operations completed since daemon start.
        p95_input_latency_ms: Rolling P95 latency for check.input operations.
        p95_output_latency_ms: Rolling P95 latency for check.output operations.
    """

    daemon_reachable: bool
    db_reachable: bool
    model_loaded: bool
    version: str
    socket_reachable: bool | None = None
    uptime_seconds: float | None = None
    active_connections: int | None = None
    max_concurrent: int | None = None
    total_checks: int | None = None
    p95_input_latency_ms: float | None = None
    p95_output_latency_ms: float | None = None


@dataclass
class Incident:
    """A security incident recorded in the forensic log.

    Attributes:
        id: Unique incident identifier.
        timestamp: When the incident was recorded.
        session_id: Associated session ID.
        payload_hash: Hash of the quarantined payload (for integrity).
        verdict_decision: The verdict decision (block, advisory, etc.).
        signal_id: The triggered signal ID (if any).
        details: Structured incident details from the detector.
    """

    id: str
    timestamp: float
    session_id: str
    payload_hash: str
    verdict_decision: str
    signal_id: str | None
    details: dict[str, object] = field(default_factory=dict)
