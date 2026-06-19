# SPDX-License-Identifier: Apache-2.0
"""Health metric contract tests for task 097."""

from __future__ import annotations

import dataclasses
from pathlib import Path

import pytest

from armor.daemon.server import DaemonServer
from armor.sdk.client import ArmorClient

ROOT = Path(__file__).resolve().parents[3]


@pytest.mark.asyncio
async def test_tc_097_03_p95_input_latency_reflects_observed_window(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """TC-097-03: P95 input latency is computed from observed samples."""
    monkeypatch.setenv("ARMOR_DISABLE_LLM", "true")
    server = DaemonServer(socket_path=str(tmp_path / "armor.sock"), db_path=str(tmp_path / "armor.db"))

    for latency_ms in range(1, 21):
        server._record_check_metric("check.input", float(latency_ms))

    health = (await server._handle_health_full())["health"]

    assert health["total_checks"] == 20
    assert health["p95_input_latency_ms"] == 19.0
    assert 1.0 <= health["p95_input_latency_ms"] <= 20.0
    assert "p95_output_latency_ms" not in health
    assert "db_capacity_percent" not in health


def test_tc_097_04_sdk_health_report_fields_match_daemon_response() -> None:
    """TC-097-04: SDK HealthReport maps every health response key."""
    response = {
        "health": {
            "socket_reachable": True,
            "db_reachable": True,
            "model_loaded": False,
            "version": "0.9.0",
            "uptime_seconds": 12,
            "active_connections": 1,
            "max_concurrent": 64,
            "total_checks": 7,
            "p95_input_latency_ms": 3.5,
            "p95_output_latency_ms": 4.5,
        }
    }

    report = ArmorClient._parse_health_report(response)
    report_fields = {field.name for field in dataclasses.fields(report)}

    assert set(response["health"]) <= report_fields
    assert report.daemon_reachable is True
    assert report.socket_reachable is True
    assert report.total_checks == 7
    assert report.p95_input_latency_ms == 3.5
    assert report.p95_output_latency_ms == 4.5


@pytest.mark.asyncio
async def test_tc_097_05_data_model_health_field_set_matches_response(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """TC-097-05: docs/spec/data-model.md matches health.full fields."""
    monkeypatch.setenv("ARMOR_DISABLE_LLM", "true")
    server = DaemonServer(socket_path=str(tmp_path / "armor.sock"), db_path=str(tmp_path / "armor.db"))
    server._record_check_metric("check.input", 2.0)
    server._record_check_metric("check.output", 3.0)

    health = (await server._handle_health_full())["health"]
    spec = (ROOT / "docs" / "spec" / "data-model.md").read_text(encoding="utf-8")

    expected_fields = {
        "socket_reachable",
        "db_reachable",
        "model_loaded",
        "version",
        "uptime_seconds",
        "active_connections",
        "max_concurrent",
        "total_checks",
        "p95_input_latency_ms",
        "p95_output_latency_ms",
    }

    assert set(health) == expected_fields
    for field in expected_fields:
        assert field in spec
    assert "`db_capacity_percent` is intentionally absent" in spec
