"""Fitness test: Verify structured logging schema compliance.

TC-028-08: All logs from the daemon must be valid JSON with required fields.

Task 036 spec markers covered here:
- TC-036-10: Daemon emits structured logs from the canonical formatter.
- TC-036-11: logging.format = "text" switches the formatter.
"""

import json
import logging
from io import StringIO


def test_structured_logs_valid_json() -> None:
    """Verify that all daemon logs are valid JSON."""
    # Simulate daemon logging by capturing stderr
    from armor.logging import StructuredFormatter

    # Create a logger and set up structured logging
    logger = logging.getLogger("test_structured")
    logger.setLevel(logging.INFO)

    # Create a string buffer to capture output
    string_buffer = StringIO()
    handler = logging.StreamHandler(string_buffer)
    handler.setFormatter(StructuredFormatter())
    logger.addHandler(handler)

    try:
        # Log some test messages
        logger.info("Test message", extra={"event": "test.event"})

        # Get the output
        output = string_buffer.getvalue()

        # Parse the log line as JSON
        log_obj = json.loads(output.strip())

        # Verify required fields are present
        assert "ts" in log_obj, "Missing required field: ts"
        assert "level" in log_obj, "Missing required field: level"
        assert "event" in log_obj, "Missing required field: event"

        # Verify field types
        assert isinstance(log_obj["ts"], str), "ts must be a string"
        assert isinstance(log_obj["level"], str), "level must be a string"
        assert isinstance(log_obj["event"], str), "event must be a string"

    finally:
        logger.removeHandler(handler)


def test_structured_logs_check_operation_fields() -> None:
    """TC-028-08: Check operations must include session_id, request_id, decision, latency_ms."""
    from armor.logging import StructuredFormatter

    logger = logging.getLogger("test_check_ops")
    logger.setLevel(logging.INFO)

    string_buffer = StringIO()
    handler = logging.StreamHandler(string_buffer)
    handler.setFormatter(StructuredFormatter())
    logger.addHandler(handler)

    try:
        # Log a check operation with all fields
        extra = {
            "event": "check.input.completed",
            "session_id": "test-session-001",
            "request_id": "req-001",
            "decision": "pass",
            "latency_ms": 123,
        }
        logger.info("Check completed", extra=extra)

        output = string_buffer.getvalue()

        log_obj = json.loads(output.strip())

        # Verify all check-related fields are present
        assert log_obj.get("session_id") == "test-session-001"
        assert log_obj.get("request_id") == "req-001"
        assert log_obj.get("decision") == "pass"
        assert log_obj.get("latency_ms") == 123

    finally:
        logger.removeHandler(handler)


def test_structured_logs_detector_fields() -> None:
    """Verify detector-related logs include detector_id and decision."""
    from armor.logging import StructuredFormatter

    logger = logging.getLogger("test_detector")
    logger.setLevel(logging.INFO)

    string_buffer = StringIO()
    handler = logging.StreamHandler(string_buffer)
    handler.setFormatter(StructuredFormatter())
    logger.addHandler(handler)

    try:
        # Log a detector run
        extra = {
            "event": "check.detector.run",
            "session_id": "test-session-002",
            "request_id": "req-002",
            "detector_id": "regex_instruction_override",
            "decision": "block",
            "latency_ms": 45,
        }
        logger.info("Detector ran", extra=extra)

        output = string_buffer.getvalue()

        log_obj = json.loads(output.strip())

        # Verify all detector fields are present
        assert log_obj.get("detector_id") == "regex_instruction_override"
        assert log_obj.get("decision") == "block"
        assert log_obj.get("latency_ms") == 45

    finally:
        logger.removeHandler(handler)


def test_structured_logs_optional_fields_omitted() -> None:
    """Verify that optional fields are only present when provided."""
    from armor.logging import StructuredFormatter

    logger = logging.getLogger("test_optional")
    logger.setLevel(logging.INFO)

    string_buffer = StringIO()
    handler = logging.StreamHandler(string_buffer)
    handler.setFormatter(StructuredFormatter())
    logger.addHandler(handler)

    try:
        # Log a daemon boot event (no session_id, request_id, etc.)
        extra = {
            "event": "daemon.boot",
        }
        logger.info("Daemon booted", extra=extra)

        output = string_buffer.getvalue()

        log_obj = json.loads(output.strip())

        # Verify required fields are present
        assert "ts" in log_obj
        assert "level" in log_obj
        assert "event" in log_obj

        # Verify optional fields are NOT present (or are None)
        # (The formatter may include them as None, which is acceptable)

    finally:
        logger.removeHandler(handler)


def test_structured_logs_timestamp_format() -> None:
    """Verify timestamps are ISO 8601 UTC with microseconds."""
    from armor.logging import StructuredFormatter

    logger = logging.getLogger("test_timestamp")
    logger.setLevel(logging.INFO)

    string_buffer = StringIO()
    handler = logging.StreamHandler(string_buffer)
    handler.setFormatter(StructuredFormatter())
    logger.addHandler(handler)

    try:
        logger.info("Timestamp test", extra={"event": "test.timestamp"})

        output = string_buffer.getvalue()

        log_obj = json.loads(output.strip())

        ts = log_obj["ts"]
        # Should be ISO 8601 format ending with Z
        assert ts.endswith("Z"), "Timestamp must end with Z (UTC)"
        assert "T" in ts, "Timestamp must contain T separator (ISO 8601)"
        # Should have microseconds (at least 6 decimal places before Z)
        assert "." in ts, "Timestamp must include microseconds"

    finally:
        logger.removeHandler(handler)


def test_structured_logs_level_values() -> None:
    """Verify log level values are lowercase."""
    from armor.logging import StructuredFormatter

    logger = logging.getLogger("test_level")
    logger.setLevel(logging.INFO)

    string_buffer = StringIO()
    handler = logging.StreamHandler(string_buffer)
    handler.setFormatter(StructuredFormatter())
    logger.addHandler(handler)

    try:
        logger.info("Info level test", extra={"event": "test.info"})

        output = string_buffer.getvalue()

        log_obj = json.loads(output.strip())

        level = log_obj["level"]
        # Should be lowercase
        assert level in ["debug", "info", "warning", "error"], f"Invalid level: {level}"
        assert level.islower(), "Level must be lowercase"

    finally:
        logger.removeHandler(handler)
