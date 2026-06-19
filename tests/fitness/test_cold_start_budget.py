# SPDX-License-Identifier: Apache-2.0
"""Fitness check: daemon cold-start within budget.

Per task 017, the daemon must accept connections within 5 s of process start
on a typical dev box. The test launches the daemon as a subprocess (with a
unique socket path so parallel runs don't collide) and times from ``Popen``
to the first successful ``connect()`` on the AF_UNIX socket.

``ARMOR_DISABLE_LLM=true`` is set in the daemon environment so the cold-start
measurement reflects only import + socket-bind cost; loading model weights
is excluded by design (and would otherwise hard-fail the daemon when no
model is present).

Spec markers:
    TC-034-01 — healthy daemon → ≤ 5,000 ms; observed value printed.
    TC-034-02 — slow daemon → fail; daemon process cleaned up.
    TC-034-03 — daemon process reaped after the check.
    TC-034-04 — socket file removed after the check.
    TC-034-05 — daemon binary missing → SKIPPED.
    TC-034-06 — polling cadence ≤ 10 ms; test-side overhead bounded.
    TC-091-12 — cold-start check still fires after the consolidation.
"""

from __future__ import annotations

import contextlib
import os
import shutil
import signal
import socket
import subprocess
import time

import pytest

COLD_START_BUDGET_MS = 5_000
DEADLINE_S = 10.0
POLL_INTERVAL_S = 0.01


@pytest.mark.smoke
def test_daemon_cold_start_within_budget() -> None:
    """TC-034-01..06 / TC-091-12: daemon ready within 5,000 ms of process start."""
    if shutil.which("uv") is None:
        pytest.skip("uv not on PATH")

    socket_path = f"/tmp/armor.cold-start.{os.getpid()}.sock"
    daemon_process: subprocess.Popen[bytes] | None = None
    elapsed_ms: float | None = None

    try:
        env = os.environ.copy()
        # Cold-start measures import + bind, not model load. Without this the
        # daemon hard-exits when no model is present (per ADR-018 enforcement).
        env["ARMOR_DISABLE_LLM"] = "true"

        cmd = [
            "uv",
            "run",
            "armor",
            "daemon",
            "--socket",
            socket_path,
            "--db",
            ":memory:",
            "--log-level",
            "warning",
        ]

        t0 = time.time()
        try:
            daemon_process = subprocess.Popen(
                cmd,
                env=env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                preexec_fn=os.setsid,
            )
        except FileNotFoundError:
            pytest.skip("uv command not available")

        deadline = t0 + DEADLINE_S
        while time.time() < deadline:
            try:
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                sock.connect(socket_path)
                t1 = time.time()
                sock.close()
                elapsed_ms = (t1 - t0) * 1000
                break
            except (ConnectionRefusedError, OSError, TimeoutError):
                time.sleep(POLL_INTERVAL_S)

        assert elapsed_ms is not None, (
            f"Daemon did not accept connections within {DEADLINE_S} s deadline (socket: {socket_path})"
        )
        print(f"observed={elapsed_ms:.0f}ms budget={COLD_START_BUDGET_MS}ms")
        assert elapsed_ms <= COLD_START_BUDGET_MS, (
            f"Cold-start exceeded budget: {elapsed_ms:.0f}ms > {COLD_START_BUDGET_MS}ms"
        )

    finally:
        if daemon_process is not None and daemon_process.poll() is None:
            try:
                os.killpg(os.getpgid(daemon_process.pid), signal.SIGTERM)
                start_kill = time.time()
                while time.time() - start_kill < 2.0 and daemon_process.poll() is None:
                    time.sleep(0.05)
                if daemon_process.poll() is None:
                    with contextlib.suppress(ProcessLookupError):
                        os.killpg(os.getpgid(daemon_process.pid), signal.SIGKILL)
                with contextlib.suppress(subprocess.TimeoutExpired):
                    daemon_process.wait(timeout=1.0)
            except Exception:
                pass
        with contextlib.suppress(OSError):
            if os.path.exists(socket_path):
                os.remove(socket_path)
