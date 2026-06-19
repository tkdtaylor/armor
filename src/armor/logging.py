# SPDX-License-Identifier: Apache-2.0
"""Structured logging utilities for armor.

The daemon emits one JSON object per line by default (ADR-029) so the
operator UX commands (`armor incidents tail`, `armor sessions list`) and any
log-aggregation pipeline can parse stderr without ad-hoc heuristics.

Set `logging.format = "text"` in `armor.toml` to fall back to a plain
human-readable format for local debugging only.
"""

import json
import logging
import sys
from datetime import UTC, datetime
from typing import Any

_LEVEL_MAP = {
    "debug": logging.DEBUG,
    "info": logging.INFO,
    "warning": logging.WARNING,
    "warn": logging.WARNING,
    "error": logging.ERROR,
}


class StructuredFormatter(logging.Formatter):
    """Format log records as structured JSON with armor-specific fields."""

    def format(self, record: logging.LogRecord) -> str:
        """Format a log record as a JSON object."""
        event = record.__dict__.get("event", record.getMessage())

        log_obj: dict[str, Any] = {
            "ts": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "level": record.levelname.lower(),
            "event": event,
        }

        if record.getMessage() != event:
            log_obj["message"] = record.getMessage()

        for field in ["session_id", "request_id", "detector_id", "decision", "latency_ms"]:
            if field in record.__dict__:
                log_obj[field] = record.__dict__[field]

        if record.exc_info:
            log_obj["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_obj)


def _resolve_level(level: str) -> int:
    return _LEVEL_MAP.get(level.lower(), logging.INFO)


def setup_logging(level: str = "info", log_format: str = "json") -> None:
    """Configure the root logger.

    Args:
        level: Log level name (`debug`, `info`, `warning`, `error`).
        log_format: `json` (default, per ADR-029) or `text` (legacy human-readable).
    """
    numeric_level = _resolve_level(level)

    root_logger = logging.getLogger()
    root_logger.setLevel(numeric_level)

    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    handler = logging.StreamHandler(sys.stderr)
    handler.setLevel(numeric_level)

    formatter: logging.Formatter
    if log_format.lower() == "text":
        formatter = logging.Formatter(
            fmt="%(asctime)s %(levelname)s %(name)s: %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S",
        )
    else:
        formatter = StructuredFormatter()

    handler.setFormatter(formatter)
    root_logger.addHandler(handler)


# Back-compat alias retained for existing callers; prefer `setup_logging`.
setup_structured_logging = setup_logging
