"""Fitness check: Daemon cold-start under budget.

TC-034-01: Healthy daemon → exit 0; recorded elapsed ≤ 5,000 ms; observed value printed.
TC-034-02: Slow daemon (artificial pre-accept sleep injected) → exit non-zero; observed elapsed printed; daemon process cleaned up.
TC-034-03: Daemon process is reaped (no `armor` processes survive) after the check completes — pass or fail.
TC-034-04: Socket file removed after the check completes — pass or fail.
TC-034-05: Daemon binary missing / `uv run` unavailable → exit 0 with `SKIPPED:` line.
TC-034-06: Polling cadence does not exceed 10 ms; total wall-clock overhead beyond daemon launch is bounded (assert ≤ 100 ms of test-side overhead).

Per task 017, measure daemon startup latency from launch to first socket accept.
Target: < 5 seconds (task 017 baseline ~3-4 seconds + 50% buffer).

Launches the daemon as a subprocess with a unique socket path to avoid collisions
in parallel test runs. Measures real cold-start time: from Popen to first successful
socket connection.
"""

import contextlib
import os
import signal
import socket
import subprocess
import sys
import time


def check_daemon_cold_start() -> bool:
    """Measure daemon cold-start: launch → first socket accept.

    Returns:
        True if cold-start is within budget (≤ 5 s), False if over budget.
        Exits with code 0 and "SKIPPED:" message if daemon unavailable.
    """
    # Create unique socket path to avoid collisions in parallel runs
    socket_path = f"/tmp/armor.cold-start.{os.getpid()}.sock"

    # Use in-memory database to avoid filesystem overhead
    db_path = ":memory:"

    daemon_process = None
    try:
        # Record start time immediately before Popen
        t0 = time.time()

        # Launch daemon with minimal config (no LLM model)
        # Use --log-level warning to reduce startup overhead from logging
        cmd = [
            "uv",
            "run",
            "armor",
            "daemon",
            "--socket",
            socket_path,
            "--db",
            db_path,
            "--log-level",
            "warning",
        ]

        try:
            daemon_process = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                preexec_fn=os.setsid,  # Create new process group for cleanup
            )
        except FileNotFoundError:
            # uv command not found
            print("SKIPPED: uv command not available")
            return True  # Exit 0 for skip
        except Exception as e:
            print(f"SKIPPED: Could not launch daemon: {e}")
            return True  # Exit 0 for skip

        # Poll socket with ≤ 10 ms cadence up to 10 s ceiling
        deadline = t0 + 10.0
        poll_interval = 0.01  # 10 ms

        while time.time() < deadline:
            try:
                # Attempt connection
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                sock.settimeout(0.5)  # Quick timeout per attempt
                sock.connect(socket_path)

                # Record successful connect time
                t1 = time.time()
                sock.close()

                # Calculate elapsed time
                elapsed_ms = (t1 - t0) * 1000

                # Print result
                print(f"observed={elapsed_ms:.0f}ms budget=5000ms")

                # Check against budget (5 seconds)
                if elapsed_ms <= 5000:
                    return True  # Success
                else:
                    print(f"FAIL: Cold-start exceeded budget: {elapsed_ms:.0f}ms > 5000ms")
                    return False

            except (ConnectionRefusedError, OSError):
                # Socket not ready yet, continue polling
                time.sleep(poll_interval)
            except TimeoutError:
                # Timeout on this attempt, continue
                time.sleep(poll_interval)

        # Deadline exceeded
        print("FAIL: Daemon did not accept connections within 10 s deadline")
        return False

    finally:
        # Teardown: SIGTERM → 2 s grace → SIGKILL
        if daemon_process is not None and daemon_process.poll() is None:
            try:
                # Send SIGTERM to the process group
                os.killpg(os.getpgid(daemon_process.pid), signal.SIGTERM)

                # Wait up to 2 seconds for graceful shutdown
                start_kill = time.time()
                while time.time() - start_kill < 2.0:
                    if daemon_process.poll() is not None:
                        break
                    time.sleep(0.05)

                # If still running, force kill
                if daemon_process.poll() is None:
                    with contextlib.suppress(ProcessLookupError):
                        os.killpg(os.getpgid(daemon_process.pid), signal.SIGKILL)

                # Wait for final reaping
                daemon_process.wait(timeout=1.0)
            except Exception:
                pass  # Best effort cleanup

        # Remove socket file
        try:
            if os.path.exists(socket_path):
                os.remove(socket_path)
        except OSError:
            pass  # Socket may have been cleaned up by daemon


if __name__ == "__main__":
    if not check_daemon_cold_start():
        sys.exit(1)
