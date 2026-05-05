# ADR-008 — Daemon concurrency model: asyncio + asyncio.to_thread for SQLite

**Status:** Accepted
**Date:** 2026-05-05
**Deciders:** armor core team

## Context

The daemon must handle multiple concurrent clients (10–100 simultaneous hooks or agents speaking to the socket) while performing I/O-bound operations:

1. **IPC**: Accept and serve NDJSON requests on a Unix socket — many concurrent clients, each idling between requests.
2. **Static detectors**: CPU-bound (regex, Aho-Corasick), sub-millisecond latency — fine to run on the asyncio event loop.
3. **Validator LLM**: CPU-bound but high-latency (100–500 ms per call) — can block the event loop if not isolated.
4. **SQLite write**: Session state and forensic logs must be persisted atomically. SQLite's Python bindings are synchronous and not asyncio-native.

The decision is how to handle concurrency in Python without introducing threading complexity or sacrificing responsiveness.

## Decision

**Use asyncio as the primary concurrency model. Offload blocking I/O (SQLite writes and LLM inference) to thread pool via `asyncio.to_thread()` (Python 3.10+).**

The daemon is structured as:

- **Main loop**: `asyncio.run()` driving a Unix socket server.
- **Request handler**: Async coroutine per client connection.
- **Short-circuit path (static detectors)**: Runs on the event loop directly (sub-millisecond, non-blocking).
- **Long-circuit path (LLM, SQLite)**: Wrapped in `await asyncio.to_thread()` to prevent blocking the event loop.

Concretely:

```python
async def handle_request(reader, writer):
    # Receive request
    payload = await reader.readline()

    # Run static detectors (fast, on the event loop)
    verdict = run_static_detectors(payload)

    # If LLM is needed, offload to thread pool
    if need_llm_check(verdict):
        verdict = await asyncio.to_thread(run_llm_check, payload)

    # SQLite write via thread pool
    if verdict == "block":
        await asyncio.to_thread(write_forensic_record, payload, verdict)

    # Respond
    writer.write(format_response(verdict))
    await writer.drain()
```

This keeps the socket handler responsive (no blocking calls on the event loop) while delegating heavy work to threads, which can run on multiple CPU cores if the system has them.

## Alternatives considered

1. **Pure threading with `concurrent.futures.ThreadPoolExecutor`**
   - Pros: Simpler code (no async), easier to reason about.
   - Cons: No centralized event loop; each thread competes for GIL; harder to enforce latency budgets. Also overkill — most checks are fast (static detectors).

2. **`asyncio` with `queue.Queue` and worker threads**
   - Pros: Decouples the socket from the worker pool; allows controlling thread count.
   - Cons: More machinery; harder to debug; violates the principle of "simple pieces."

3. **Blocking I/O on the event loop**
   - Pros: Simplest to write.
   - Cons: One slow SQLite write blocks all other clients; unacceptable.

## Rationale

- **Python 3.10+ native support**: `asyncio.to_thread()` is the stdlib answer; no external async library needed.
- **Single event loop**: All socket I/O is multiplexed on one loop, avoiding the overhead of one thread per connection.
- **Backward-compat**: The main codebase (detectors, models) remains synchronous; only the daemon glues them into the async world.
- **Latency isolation**: Static detectors don't block on LLM; LLM doesn't block on SQLite; socket stays responsive.

## Consequences

- **Detector interface stays synchronous** — `Detector.check(payload, ctx) -> Verdict` is a sync function. The daemon handles the async wrapping.
- **No detector hot-swap during request** — the detector registry is read-only after boot. Detectors are discovered at daemon start via entry points.
- **Max concurrent is bounded** — the default is 64 to prevent resource exhaustion; limits are enforced in the socket accept loop.
- **SQLite WAL mode required** — multiple threads are writing to the database; WAL mode enables concurrent readers + single writer without full locking.

## Implementation notes

- Use `asyncio.StreamReader` / `asyncio.StreamWriter` for Unix socket handling.
- Wrap LLM inference in `asyncio.to_thread(partial(llm_instance.infer, ...))`.
- Use a semaphore or counter to enforce `max_concurrent` before accepting new connections.
- Graceful shutdown: close the listener, wait for in-flight requests to complete (timeout after 5s), then exit.

## See also

- [B-008: Daemon serves multiple concurrent hooks via Unix socket](../behaviors.md#b-008-daemon-serves-multiple-concurrent-hooks-via-unix-socket)
- Task 002 (daemon skeleton) — implements this ADR
- Task 006 (SQLite session store) — implements the SQLite write path
- Task 015 (validator LLM) — implements the LLM inference path
