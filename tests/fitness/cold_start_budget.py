"""Fitness check: Daemon cold-start under budget.

Per task 017, measure daemon startup latency from launch to first socket accept.
Target: < 5 seconds (task 017 baseline ~3-4 seconds + 50% buffer).

This is a deferred full-integration test. For v0.3, we verify that the
critical path imports are fast. A full daemon cold-start test will be added
when the daemon is fully integrated and testable.

Runs: Check that core imports are fast
Expects: < 1 second for import latency (not the full daemon startup)
"""

import sys
import time


def check_imports_fast() -> bool:
    """Verify that critical imports don't have expensive side effects.

    Returns:
        True if imports complete quickly, False otherwise.
    """
    start = time.time()

    # Import critical modules
    try:
        import armor.daemon.server
        import armor.detectors
        import armor.llm.honeypot

        # Test that imports succeeded by checking they're callable
        assert callable(armor.daemon.server.DaemonServer)
        assert callable(armor.detectors.DetectorRegistry)
    except Exception as e:
        print(f"FAIL: Import failed: {e}")
        return False

    elapsed_ms = (time.time() - start) * 1000

    # Imports should be fast (< 1000ms even on slow machines)
    if elapsed_ms > 1000:
        print(f"FAIL: Imports took {elapsed_ms:.0f}ms (> 1000ms budget)")
        return False

    print(f"PASS: Core imports completed in {elapsed_ms:.0f}ms (< 1000ms)")
    return True


if __name__ == "__main__":
    if not check_imports_fast():
        sys.exit(1)
