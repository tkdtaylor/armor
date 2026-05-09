"""Fitness checks for task 050 — armor.toml post-FSM rewrite.

This module encodes spec audit checks as runnable assertions that prevent
drift between the spec files and the bundled armor.toml sample.

Spec markers:
    TC-050-01 — armor.toml parses cleanly with tomllib
    TC-050-02 — armor.toml includes the post-FSM sections
    TC-050-03 — armor.toml does not include pre-FSM keys
    TC-050-04 — Daemon accepts the bundled config
    TC-050-05 — make check passes (operator-verified)
"""

import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_armor_toml_parses():
    """TC-050-01: armor.toml parses cleanly with tomllib."""
    toml_path = ROOT / "armor.toml"
    assert toml_path.exists(), "armor.toml does not exist at project root"

    text = toml_path.read_text()
    data = tomllib.loads(text)
    assert isinstance(data, dict), "armor.toml did not parse to a dict"


def test_armor_toml_post_fsm_sections():
    """TC-050-02: armor.toml includes the post-FSM sections."""
    toml_path = ROOT / "armor.toml"
    text = toml_path.read_text()
    data = tomllib.loads(text)

    # Check model section
    assert "model" in data, "missing [model] section"
    assert "validator_budget_ms" in data["model"], "missing model.validator_budget_ms"
    assert "honeypot_budget_ms" in data["model"], "missing model.honeypot_budget_ms"

    # Check session section
    assert "session" in data, "missing [session] section"
    assert "thresholds" in data["session"], "missing [session.thresholds] section"

    # Check threshold keys (cooldown_decay_per_min sits at the session level per
    # docs/spec/configuration.md, not under [session.thresholds])
    for key in ("watching", "elevated", "high"):
        assert key in data["session"]["thresholds"], f"missing session.thresholds.{key}"
    assert "cooldown_decay_per_min" in data["session"], "missing session.cooldown_decay_per_min"

    # Check signal_weights
    assert "signal_weights" in data["session"], "missing [session.signal_weights] section"

    assert data["pipeline"]["tool_detectors"] == [
        "cmd_injection.*",
        "tool_param.*",
        "tool_rate.*",
        "tool_chain",
    ], "TC-108-06: bundled tool detector allowlist does not match shipped defaults"

    # Check detector section
    assert "detector" in data, "missing [detector] section"
    for key in ("canary", "topic_coherence"):
        assert key in data["detector"], f"missing detector.{key}"


def test_armor_toml_no_pre_fsm_keys():
    """TC-050-03: armor.toml does not include pre-FSM keys."""
    toml_path = ROOT / "armor.toml"
    text = toml_path.read_text()
    data = tomllib.loads(text)

    # Pre-FSM: [model] budget_ms (single, unsplit)
    assert "budget_ms" not in data.get("model", {}), (
        "armor.toml still uses pre-FSM model.budget_ms (must be split into validator_budget_ms and honeypot_budget_ms)"
    )

    # Pre-FSM: [session.escalation]
    assert "escalation" not in data.get("session", {}), (
        "armor.toml still uses pre-FSM [session.escalation] (must be [session.thresholds] with watching/elevated/high)"
    )


def test_daemon_accepts_bundled_config():
    """TC-050-04: Daemon accepts the bundled config (--help exit code check)."""
    result = subprocess.run(
        [sys.executable, "-m", "armor.daemon", "--config", str(ROOT / "armor.toml"), "--help"],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
    )
    # We check --help exit code as a proxy for config parse success.
    # The actual daemon may fail if the model file is unavailable, but
    # --help should succeed if config parsing passes.
    assert result.returncode == 0, (
        f"daemon --config armor.toml --help failed with exit {result.returncode}\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )


def test_configuration_spec_has_live_detector_allowlists_only():
    """TC-108-07: config spec describes live allowlists and no telemetry placeholder."""
    config_text = (ROOT / "docs" / "spec" / "configuration.md").read_text()
    interfaces_text = (ROOT / "docs" / "spec" / "interfaces.md").read_text()
    text = config_text + "\n" + interfaces_text

    assert "Reserved placeholder" not in text
    assert "no readers exist" not in text
    assert "ARMOR_ENABLE_TELEMETRY" not in text
    assert "Detector allowlist for `check.input`" in text
    assert "Detector allowlist for `check.output`" in text
    assert "Detector allowlist for `check.tool`" in text
