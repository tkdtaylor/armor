"""Unit tests for daemon logging."""

import json
import logging
from io import StringIO

from armor.daemon.logging import JSONFormatter, setup_logging


class TestJSONFormatter:
    """Tests for JSON log formatting."""

    def test_format_basic_log(self) -> None:
        """Test formatting a basic log record."""
        formatter = JSONFormatter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="Test message",
            args=(),
            exc_info=None,
        )

        result = formatter.format(record)

        # Verify it's valid JSON
        data = json.loads(result)
        assert data["message"] == "Test message"
        assert data["level"] == "INFO"
        assert data["logger"] == "test"

    def test_format_with_exception(self) -> None:
        """Test formatting a log record with exception info."""
        formatter = JSONFormatter()

        try:
            raise ValueError("Test error")
        except ValueError:
            import sys

            exc_info = sys.exc_info()

            record = logging.LogRecord(
                name="test",
                level=logging.ERROR,
                pathname="test.py",
                lineno=1,
                msg="Error occurred",
                args=(),
                exc_info=exc_info,
            )

            result = formatter.format(record)

            # Verify it's valid JSON
            data = json.loads(result)
            assert data["message"] == "Error occurred"
            assert data["level"] == "ERROR"
            assert "exception" in data
            assert "ValueError" in data["exception"]

    def test_format_with_args(self) -> None:
        """Test formatting a log record with message arguments."""
        formatter = JSONFormatter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="Message with %s and %d",
            args=("string", 42),
            exc_info=None,
        )

        result = formatter.format(record)

        data = json.loads(result)
        assert data["message"] == "Message with string and 42"


class TestSetupLogging:
    """Tests for logging setup."""

    def test_setup_logging_debug(self) -> None:
        """Test setup_logging with debug level."""
        setup_logging("debug")
        root_logger = logging.getLogger()

        assert root_logger.level == logging.DEBUG

    def test_setup_logging_info(self) -> None:
        """Test setup_logging with info level."""
        setup_logging("info")
        root_logger = logging.getLogger()

        assert root_logger.level == logging.INFO

    def test_setup_logging_warning(self) -> None:
        """Test setup_logging with warning level."""
        setup_logging("warning")
        root_logger = logging.getLogger()

        assert root_logger.level == logging.WARNING

    def test_setup_logging_error(self) -> None:
        """Test setup_logging with error level."""
        setup_logging("error")
        root_logger = logging.getLogger()

        assert root_logger.level == logging.ERROR

    def test_setup_logging_invalid_level_defaults_to_info(self) -> None:
        """Test that invalid level defaults to info."""
        setup_logging("invalid")
        root_logger = logging.getLogger()

        assert root_logger.level == logging.INFO

    def test_logging_produces_json(self) -> None:
        """Test that logging output is valid JSON."""
        setup_logging("info")

        # Create a string buffer to capture output
        output = StringIO()

        # Add a handler that writes to our buffer
        handler = logging.StreamHandler(output)
        handler.setFormatter(JSONFormatter())
        logger = logging.getLogger("test.json")
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)

        # Log a message
        logger.info("Test JSON output")

        # Verify output is valid JSON
        result = output.getvalue().strip()
        data = json.loads(result)
        assert data["message"] == "Test JSON output"
