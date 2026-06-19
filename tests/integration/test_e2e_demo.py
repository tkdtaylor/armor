# SPDX-License-Identifier: Apache-2.0
"""Integration test for the end-to-end demo script.

This test runs the demo.sh script as a subprocess and verifies that it
completes successfully with the expected output.
"""

import subprocess
import tempfile
from pathlib import Path


def test_e2e_demo_script():
    """Run the demo script and verify it exits successfully.

    The demo script is the canonical demonstration of armor v0.1 working end-to-end:
    - Direct injection blocks with forensic incident
    - Canary exfiltration blocks with canary_id (never the value) logged
    - Cleanup occurs on exit
    """
    demo_script = Path(__file__).parent.parent.parent / "scripts" / "demo.sh"
    assert demo_script.exists(), f"Demo script not found at {demo_script}"

    # Run the demo script as a subprocess with output to a temp file
    # This avoids buffer deadlocks that can occur with capture_output=True
    with tempfile.NamedTemporaryFile(mode="w+", suffix=".txt", delete=False) as stdout_file:
        stdout_path = stdout_file.name

    try:
        with open(stdout_path, "w") as stdout_file:
            result = subprocess.run(
                ["bash", str(demo_script)],
                stdout=stdout_file,
                stderr=subprocess.STDOUT,
                timeout=180,  # 3 minute timeout (allow time for daemon startup and checks)
            )

        # Read the output
        with open(stdout_path) as f:
            output = f.read()

        # Verify successful completion
        assert result.returncode == 0, f"Demo script failed with exit code {result.returncode}\nOutput:\n{output}"

        # Verify the success message is printed
        assert "Demo PASSED" in output, f"Expected 'Demo PASSED' in output, got:\n{output}"

    finally:
        Path(stdout_path).unlink(missing_ok=True)

    # Verify cleanup: demo temp directories should be gone (trap cleanup)
    # We don't explicitly check /tmp here since the demo cleanup is responsible for it
    # and temp file cleanup on exit is tested via the demo script's trap mechanism
