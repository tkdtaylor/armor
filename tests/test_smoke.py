"""Smoke test to verify basic project setup."""

import json
from io import StringIO
from unittest.mock import patch

import armor
from armor.cli import main


def test_import_armor() -> None:
    """Test that armor can be imported and has __version__."""
    assert hasattr(armor, "__version__")
    assert isinstance(armor.__version__, str)
    assert len(armor.__version__) > 0


def test_cli_health() -> None:
    """Test that armor health command returns the correct JSON."""
    output = StringIO()
    with patch("sys.stdout", output):
        exit_code = main(["health", "--json"])

    # Daemon is not running, so health check should return critical
    assert exit_code == 2
    data = json.loads(output.getvalue().strip())
    assert data["status"] == "unreachable"
