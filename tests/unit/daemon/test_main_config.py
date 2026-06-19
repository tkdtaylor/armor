# SPDX-License-Identifier: Apache-2.0
"""Unit tests for daemon __main__ configuration loading (task 077).

Tests the precedence chain for canary_values_path: env var > CLI flag > TOML config > None.
"""

import json
import os
import subprocess
import tempfile
from pathlib import Path

import pytest


def _create_minimal_canary_file(path: Path) -> None:
    """Create a minimal valid canary values file."""
    canary_data = [
        {
            "canary_id": "test-key-000",
            "kind": "credential",
            "service": "test",
            "value": "TESTVALUE0000000001",
            "marker_rule": r"^TESTVALUE\d+$",
            "active": True,
            "created_at": "2026-05-08T00:00:00Z",
        }
    ]
    with open(path, "w") as f:
        json.dump(canary_data, f)


def test_load_canary_values_path_from_toml() -> None:
    """TC-077-01: TOML-only path is honored when no env/CLI provided."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir_path = Path(tmpdir)
        config_file = tmpdir_path / "armor.toml"
        canary_file = tmpdir_path / "cv.json"
        db_file = tmpdir_path / "armor.db"
        socket_file = tmpdir_path / "armor.sock"

        # Create a minimal valid canary values file
        _create_minimal_canary_file(canary_file)

        # Write TOML config with canary_values_path
        config_file.write_text(f'[daemon]\ncanary_values_path = "{canary_file}"\n')

        # Start daemon with config file but no --canary-values flag and no env var
        env = os.environ.copy()
        env.pop("ARMOR_CANARY_VALUES_PATH", None)
        env["ARMOR_DISABLE_LLM"] = "true"  # Disable LLM to avoid exit 78
        env["ARMOR_DISABLE_LLM"] = "true"  # Disable LLM to avoid exit 78 on missing model

        proc = subprocess.Popen(
            [
                "uv",
                "run",
                "armor",
                "daemon",
                "--socket",
                str(socket_file),
                "--db",
                str(db_file),
                "--config",
                str(config_file),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
        )

        try:
            # Wait for socket to exist (daemon started successfully)
            import time

            start_time = time.time()
            while time.time() - start_time < 5.0:
                if socket_file.exists():
                    break
                time.sleep(0.05)
            else:
                # Timeout: check if there's an error
                proc.terminate()
                _stdout, stderr = proc.communicate(timeout=2)
                pytest.fail(f"Daemon failed to start with TOML canary_values_path.\nStderr: {stderr}")

            # If we got here, daemon started successfully with the TOML config
            assert socket_file.exists(), "Socket should exist after daemon start"
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()


def test_cli_overrides_toml() -> None:
    """TC-077-02: CLI flag --canary-values overrides TOML value."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir_path = Path(tmpdir)
        config_file = tmpdir_path / "armor.toml"
        toml_cv = tmpdir_path / "toml_cv.json"
        cli_cv = tmpdir_path / "cli_cv.json"
        db_file = tmpdir_path / "armor.db"
        socket_file = tmpdir_path / "armor.sock"

        # Create both valid canary files
        _create_minimal_canary_file(toml_cv)
        _create_minimal_canary_file(cli_cv)

        # TOML has toml_cv.json
        config_file.write_text(f'[daemon]\ncanary_values_path = "{toml_cv}"\n')

        # Start daemon with both TOML and CLI flags (CLI should win)
        env = os.environ.copy()
        env.pop("ARMOR_CANARY_VALUES_PATH", None)
        env["ARMOR_DISABLE_LLM"] = "true"  # Disable LLM to avoid exit 78

        proc = subprocess.Popen(
            [
                "uv",
                "run",
                "armor",
                "daemon",
                "--socket",
                str(socket_file),
                "--db",
                str(db_file),
                "--config",
                str(config_file),
                "--canary-values",
                str(cli_cv),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
        )

        try:
            import time

            start_time = time.time()
            while time.time() - start_time < 5.0:
                if socket_file.exists():
                    break
                time.sleep(0.05)
            else:
                proc.terminate()
                _stdout, stderr = proc.communicate(timeout=2)
                pytest.fail(f"Daemon failed to start with CLI override.\nStderr: {stderr}")

            assert socket_file.exists()
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()


def test_env_var_overrides_cli_and_toml() -> None:
    """TC-077-03: Env var ARMOR_CANARY_VALUES_PATH overrides CLI and TOML."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir_path = Path(tmpdir)
        config_file = tmpdir_path / "armor.toml"
        toml_cv = tmpdir_path / "toml_cv.json"
        cli_cv = tmpdir_path / "cli_cv.json"
        env_cv = tmpdir_path / "env_cv.json"
        db_file = tmpdir_path / "armor.db"
        socket_file = tmpdir_path / "armor.sock"

        # Create all three valid canary files
        _create_minimal_canary_file(toml_cv)
        _create_minimal_canary_file(cli_cv)
        _create_minimal_canary_file(env_cv)

        # TOML has toml_cv.json
        config_file.write_text(f'[daemon]\ncanary_values_path = "{toml_cv}"\n')

        # Start daemon with all three (env var should win)
        env = os.environ.copy()
        env["ARMOR_CANARY_VALUES_PATH"] = str(env_cv)
        env["ARMOR_DISABLE_LLM"] = "true"  # Disable LLM to avoid exit 78

        proc = subprocess.Popen(
            [
                "uv",
                "run",
                "armor",
                "daemon",
                "--socket",
                str(socket_file),
                "--db",
                str(db_file),
                "--config",
                str(config_file),
                "--canary-values",
                str(cli_cv),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
        )

        try:
            import time

            start_time = time.time()
            while time.time() - start_time < 5.0:
                if socket_file.exists():
                    break
                time.sleep(0.05)
            else:
                proc.terminate()
                _stdout, stderr = proc.communicate(timeout=2)
                pytest.fail(f"Daemon failed to start with env var override.\nStderr: {stderr}")

            assert socket_file.exists()
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()


def test_toml_omitted_falls_through_to_cli_env() -> None:
    """TC-077-04: TOML omits canary_values_path → resolution falls through to CLI/env/None."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir_path = Path(tmpdir)
        config_file = tmpdir_path / "armor.toml"
        cli_cv = tmpdir_path / "cli_cv.json"
        db_file = tmpdir_path / "armor.db"
        socket_file = tmpdir_path / "armor.sock"

        # Create valid CLI canary file
        _create_minimal_canary_file(cli_cv)

        # TOML doesn't have canary_values_path at all
        config_file.write_text("[daemon]\nmax_concurrent = 32\n")

        env = os.environ.copy()
        env.pop("ARMOR_CANARY_VALUES_PATH", None)
        env["ARMOR_DISABLE_LLM"] = "true"  # Disable LLM to avoid exit 78

        proc = subprocess.Popen(
            [
                "uv",
                "run",
                "armor",
                "daemon",
                "--socket",
                str(socket_file),
                "--db",
                str(db_file),
                "--config",
                str(config_file),
                "--canary-values",
                str(cli_cv),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
        )

        try:
            import time

            start_time = time.time()
            while time.time() - start_time < 5.0:
                if socket_file.exists():
                    break
                time.sleep(0.05)
            else:
                proc.terminate()
                _stdout, stderr = proc.communicate(timeout=2)
                pytest.fail(f"Daemon failed to start with omitted TOML key.\nStderr: {stderr}")

            assert socket_file.exists()
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()


def test_toml_malformed_key_raises_error() -> None:
    """TC-077-05: TOML key present but malformed (non-string) → startup error."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir_path = Path(tmpdir)
        config_file = tmpdir_path / "armor.toml"
        db_file = tmpdir_path / "armor.db"
        socket_file = tmpdir_path / "armor.sock"

        # TOML has a non-string value for canary_values_path
        config_file.write_text("[daemon]\ncanary_values_path = 123\n")

        env = os.environ.copy()
        env.pop("ARMOR_CANARY_VALUES_PATH", None)
        env["ARMOR_DISABLE_LLM"] = "true"  # Disable LLM to avoid exit 78

        proc = subprocess.Popen(
            [
                "uv",
                "run",
                "armor",
                "daemon",
                "--socket",
                str(socket_file),
                "--db",
                str(db_file),
                "--config",
                str(config_file),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
        )

        try:
            import time

            start_time = time.time()
            while time.time() - start_time < 5.0:
                if socket_file.exists():
                    # Daemon shouldn't have started
                    break
                time.sleep(0.05)
            else:
                pass  # Daemon didn't start (expected)

            # Wait for process to finish and check stderr for error
            _stdout, stderr = proc.communicate(timeout=5)

            # Should have exited with non-zero code and error message
            assert proc.returncode != 0, f"Should fail on malformed TOML key.\nStderr: {stderr}"
            # Error should reference the configuration issue
            assert "daemon.canary_values_path" in stderr or "Configuration" in stderr, (
                f"Error should mention the configuration issue.\nStderr: {stderr}"
            )
        finally:
            try:
                proc.terminate()
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
