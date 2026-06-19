# SPDX-License-Identifier: Apache-2.0
"""Rolling buffer for multi-turn output aggregation.

Maintains a bounded buffer of the last N outputs (by character count or turn count,
whichever fills first). Used to detect exfiltration patterns that span multiple turns.

The buffer is FIFO from the front: when a limit is hit, the oldest turn is evicted.
Concatenation preserves turn order (oldest first).
"""

from collections import deque
from dataclasses import dataclass


@dataclass
class BufferEntry:
    """A single turn's data in the rolling buffer.

    Attributes:
        turn_id: Unique identifier for the turn.
        text: The turn's output text.
    """

    turn_id: str
    text: str


class RollingBuffer:
    """Bounded FIFO rolling buffer for multi-turn output aggregation.

    Maintains two limits: capacity_chars (max characters in buffer) and capacity_turns (max turns).
    Whichever fills first triggers FIFO eviction from the front.

    Attributes:
        capacity_chars: Maximum character count (default 8192, ~8 KB).
        capacity_turns: Maximum turn count (default 20).
    """

    def __init__(self, capacity_chars: int = 8192, capacity_turns: int = 20) -> None:
        """Initialize the rolling buffer.

        Args:
            capacity_chars: Maximum characters in the buffer.
            capacity_turns: Maximum turns in the buffer.

        Raises:
            ValueError: If either capacity is <= 0.
        """
        if capacity_chars <= 0:
            raise ValueError(f"capacity_chars must be positive, got {capacity_chars}")
        if capacity_turns <= 0:
            raise ValueError(f"capacity_turns must be positive, got {capacity_turns}")

        self.capacity_chars = capacity_chars
        self.capacity_turns = capacity_turns
        self._buffer: deque[BufferEntry] = deque()

    def append(self, turn_id: str, text: str) -> None:
        """Append a turn's output to the buffer.

        If appending this turn would exceed either limit, evict entries from the front
        (oldest first) until both limits are satisfied.

        Args:
            turn_id: Unique identifier for this turn.
            text: The turn's output text.
        """
        # Add the new entry
        new_entry = BufferEntry(turn_id=turn_id, text=text)
        self._buffer.append(new_entry)

        # Enforce capacity limits
        self._evict_to_fit()

    def _evict_to_fit(self) -> None:
        """Evict entries from the front until both capacity limits are satisfied."""
        while self._current_char_count() > self.capacity_chars or len(self._buffer) > self.capacity_turns:
            if self._buffer:
                self._buffer.popleft()

    def _current_char_count(self) -> int:
        """Return the current character count in the buffer.

        Returns:
            Sum of character lengths of all text entries.
        """
        return sum(len(entry.text) for entry in self._buffer)

    def concatenated(self, separator: str = "") -> str:
        """Return the concatenated buffer contents.

        Returns turns in append order (oldest first, newest last), joined with separator.

        Args:
            separator: String to insert between turns (default empty string to avoid
                      introducing ambiguity for downstream canary scanners).

        Returns:
            Concatenated string of all buffered output.
        """
        return separator.join(entry.text for entry in self._buffer)

    def entries(self) -> list[BufferEntry]:
        """Return a copy of the current buffer entries in order (oldest first).

        Returns:
            List of BufferEntry objects.
        """
        return list(self._buffer)

    def turn_ids(self) -> list[str]:
        """Return the turn IDs currently in the buffer (oldest first).

        Returns:
            List of turn ID strings.
        """
        return [entry.turn_id for entry in self._buffer]

    def clear(self) -> None:
        """Clear the buffer entirely.

        Used when a session ends or is explicitly reset.
        """
        self._buffer.clear()

    def __len__(self) -> int:
        """Return the number of turns in the buffer."""
        return len(self._buffer)

    def __bool__(self) -> bool:
        """Return True if the buffer is non-empty."""
        return bool(self._buffer)
