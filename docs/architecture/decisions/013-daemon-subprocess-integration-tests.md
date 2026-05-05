# ADR-013 — Daemon client-connection tests via subprocess integration tests, not pytest-asyncio

**Status:** Accepted
**Date:** 2026-05-05
**Deciders:** armor core team

## Context

Six daemon server tests (`test_single_client_request`, `test_concurrent_clients`, `test_max_concurrent_enforcement`, `test_handle_malformed_json`, `test_json_per_line_output`, `test_graceful_shutdown_removes_socket`) were marked `@pytest.mark.skip` to unblock CI in v0.1. They exercise the full async client-connection round-trip (Unix socket open, NDJSON request, response read, connection close) but hang silently in `pytest-asyncio` with `asyncio_mode=auto` and per-test event loops.

The hang occurs because:

1. `pytest-asyncio` creates a new event loop for each test
2. `asyncio.start_unix_server` spawns background `_handle_client` tasks pinned to that loop
3. When the test finishes and the loop is torn down, the background tasks don't shut down cleanly
4. The loop waits for pending tasks; the tasks wait for the loop to be available; deadlock

The issue is fundamental to mixing per-test event loops with long-lived async server state — no amount of tweaking the shutdown path will fully solve it because pytest-asyncio's fixture teardown is inherently racy with background task cleanup.

## Decision

**Convert these 6 tests to subprocess-based integration tests.**

Instead of using `@pytest.mark.asyncio` and trying to exercise the server within the same process, start the daemon as a subprocess (`subprocess.Popen(["uv","run","armor","daemon",...])`), connect to it from the test process using a synchronous socket client, and verify the request/response round-trip.

This pattern:
- Avoids pytest-asyncio per-test event loop racy cleanup
- Isolates the daemon's event loop to its own process (never shares with test runner)
- Matches the approach already validated in `test_e2e_demo.py`
- Tests the actual real-world scenario (daemon and client are separate processes)
- Is more robust because subprocess lifecycle is explicit and reliable

## Alternatives considered

1. **Fix the shutdown path to be 100% compatible with pytest-asyncio per-test loops**
   - Pros: Would run async tests in-process, faster iteration
   - Cons: The core issue is in pytest-asyncio's fixture teardown; the daemon can't fully unwind before the loop is gone. Unfixable without modifying pytest-asyncio itself.

2. **Use `asyncio_default_test_loop_scope=session` for these tests**
   - Pros: Simpler code change; keeps tests in pytest-asyncio style
   - Cons: Session-scoped event loops are an anti-pattern in pytest (breaks test isolation); risks cross-pollinating state between tests

3. **Restructure daemon to not use `asyncio.start_unix_server`**
   - Pros: Would eliminate the background task issue
   - Cons: `asyncio.start_unix_server` is the correct choice for async Unix socket servers; changing it would be architectural damage for a test-only problem

## Rationale

- **Real-world behavior**: The daemon and client are always separate processes in production. Testing them separately matches reality better than in-process testing.
- **Eliminates async test brittleness**: Subprocess tests are synchronous from the harness perspective — no asyncio cleanup race conditions.
- **Proven pattern**: `test_e2e_demo.py` already uses this approach successfully; daemon startup in subprocess works reliably.
- **Better isolation**: Each test's daemon instance is a fresh subprocess, no shared state leaking between tests.

## Consequences

- **Slower tests**: Subprocess startup overhead (~200-500ms per test) vs in-process async tests (~10ms). Offset by the fact that we're no longer debugging hangs.
- **Simpler code**: Tests are synchronous; no `await`, `async def`, or asyncio machinery. Clear control flow.
- **Clearer error messages**: When a test fails, the daemon's stderr is captured and included in the failure output.
- **Future async tests**: Any new async integration tests should follow this subprocess pattern, not try in-process pytest-asyncio again.

## Implementation notes

- Create `tests/integration/test_daemon_server_clients.py` with the 6 tests ported to subprocess style
- Each test spawns `subprocess.Popen(["uv","run","armor","daemon",...])`  with a temp socket and DB
- Connect to the socket using `socket.socket(socket.AF_UNIX)` (synchronous)
- Verify request/response round-trips
- Use `timeout` on socket operations to prevent hangs
- Clean up subprocesses with `terminate()` + `wait(timeout=5)` in `finally` blocks

## See also

- Task 007 (e2e demo test) — validated subprocess-based daemon testing
- The original skip of these tests
- `tests/integration/test_e2e_demo.py` — the pattern to follow
