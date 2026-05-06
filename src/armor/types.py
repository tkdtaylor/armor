"""Core type definitions for the armor security layer.

Includes Verdict, Payload, SessionContext, and severity/decision enums.
"""

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Literal


class Decision(StrEnum):
    """Verdict decision type."""

    PASS = "pass"
    BLOCK = "block"
    ADVISORY = "advisory"
    ERROR = "error"


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
    ) -> "Verdict":
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
    ) -> "Verdict":
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
    ) -> "Verdict":
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
    ) -> "Verdict":
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
    """

    text: str = ""
    tool: str | None = None
    params: dict[str, object] | None = None


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
        state: Session state level (v0.3 placeholder; task 022 will populate with enum).
               "elevated" enables honeypot invocation. None (default) disables it.
    """

    session_id: str
    signal_history: list[Signal] = field(default_factory=list)
    state: str | None = None
