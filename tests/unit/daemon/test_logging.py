# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the daemon logging entry-point.

The daemon uses the canonical `armor.logging` module (ADR-029); the legacy
`armor.daemon.logging` module was removed by task 036.
"""

import json
import logging
import sys

import pytest

from armor.logging import StructuredFormatter, setup_logging


def test_trusted_source_tools_log_omits_configured_names(
    tmp_path, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """TC-110-01: trusted source tool names are not logged in clear text."""
    monkeypatch.setenv("ARMOR_DISABLE_LLM", "true")
    config_path = tmp_path / "armor.toml"
    config_path.write_text('[pipeline.fetched]\ntrusted_source_tools = ["corp_secret_wiki", "internal_jira_query"]\n')

    caplog.set_level(logging.INFO, logger="armor.daemon.server")

    from armor.daemon.server import DaemonServer

    server = DaemonServer(
        socket_path=str(tmp_path / "armor.sock"),
        db_path=str(tmp_path / "armor.db"),
        config_path=str(config_path),
    )

    assert server.trusted_source_tools == ["corp_secret_wiki", "internal_jira_query"]
    assert "Loaded 2 trusted source tool(s)" in caplog.text
    assert "corp_secret_wiki" not in caplog.text
    assert "internal_jira_query" not in caplog.text


def test_structured_formatter_basic() -> None:
    formatter = StructuredFormatter()
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname="test.py",
        lineno=1,
        msg="hello",
        args=(),
        exc_info=None,
    )
    record.__dict__["event"] = "test.basic"
    payload = json.loads(formatter.format(record))
    assert payload["event"] == "test.basic"
    assert payload["level"] == "info"
    assert payload["message"] == "hello"


def test_setup_logging_json_default(capsys: pytest.CaptureFixture[str]) -> None:
    setup_logging("info")
    logging.getLogger().info("boot", extra={"event": "daemon.boot"})
    captured = capsys.readouterr()
    line = captured.err.strip().splitlines()[-1]
    payload = json.loads(line)
    assert payload["event"] == "daemon.boot"
    assert payload["level"] == "info"


def test_setup_logging_text_format(capsys: pytest.CaptureFixture[str]) -> None:
    """TC-036-11: `text` format produces non-JSON human-readable lines."""
    setup_logging("info", log_format="text")
    logging.getLogger().info("boot")
    captured = capsys.readouterr()
    line = captured.err.strip().splitlines()[-1]
    assert not line.startswith("{")
    assert "boot" in line
    with pytest.raises(json.JSONDecodeError):
        json.loads(line)


@pytest.fixture(autouse=True)
def _reset_root_logger() -> None:
    """Re-attach a sane stderr handler after each test so other tests can log."""
    yield
    root = logging.getLogger()
    for h in root.handlers[:]:
        root.removeHandler(h)
    handler = logging.StreamHandler(sys.stderr)
    root.addHandler(handler)
    root.setLevel(logging.INFO)
