"""JSON-structured logging for the armor daemon."""

import json
import logging
import sys
from typing import Any


class JSONFormatter(logging.Formatter):
    """Format log records as JSON lines."""

    def format(self, record: logging.LogRecord) -> str:
        """Format a log record as JSON.

        Args:
            record: The log record to format

        Returns:
            A JSON string representing the log record
        """
        log_obj: dict[str, Any] = {
            "timestamp": self.formatTime(record),
            "level": record.levelname,
            "message": record.getMessage(),
            "logger": record.name,
        }

        # Add exception info if present
        if record.exc_info:
            log_obj["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_obj)


def setup_logging(level: str = "info") -> None:
    """Set up JSON-structured logging for the daemon.

    Args:
        level: Log level (debug, info, warning, error)
    """
    # Map string level names to logging levels
    level_map = {
        "debug": logging.DEBUG,
        "info": logging.INFO,
        "warning": logging.WARNING,
        "error": logging.ERROR,
    }

    numeric_level = level_map.get(level.lower(), logging.INFO)

    # Configure the root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(numeric_level)

    # Remove any existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Create stderr handler with JSON formatter
    handler = logging.StreamHandler(sys.stderr)
    handler.setLevel(numeric_level)
    formatter = JSONFormatter()
    handler.setFormatter(formatter)
    root_logger.addHandler(handler)
