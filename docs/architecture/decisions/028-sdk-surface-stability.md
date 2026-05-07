# ADR-028 — Python SDK surface stability and daemon-unreachable behavior

**Date:** 2026-05-06
**Status:** Accepted
**Task:** 026
**Authors:** Kevin

## Context

Task 026 ships `armor` as a first-class importable Python library, not just a CLI tool. The library provides `ArmorClient` and `AsyncArmorClient` classes that wrap the daemon IPC transport with a typed, ergonomic public surface.

Key constraints:
- **Stability contract:** The SDK surface must be stable across minor versions; breaking changes require a major bump.
- **Daemon-unreachable behavior:** The SDK must have a defined, documented behavior when the daemon socket is unreachable or the daemon is not running. This is a critical design choice: should SDK calls raise an exception or return an error verdict?
- **Type safety:** All public methods must be fully typed and pass `mypy --strict`.
- **Docstring completeness:** 95%+ docstring coverage on `src/armor/sdk/` to ensure API discoverability and maintainability.

## Decision

### 1. Daemon-unreachable behavior: Raise, not error verdict

**Chosen:** Raise `DaemonUnreachableError` on daemon contact failure.

**Rationale:**

The SDK must fail **closed and loudly** rather than silently degrading:
- **Fail-closed principle:** When the security system is unavailable, the application should reject the operation, not proceed with reduced confidence.
- **Debuggability:** An exception with a clear error message is unambiguous and forces the caller to handle the error explicitly. A Verdict with decision="error" can be silently ignored or mishandled.
- **Correctness:** The daemon is a hard dependency for the SDK. If it's unreachable, it's a configuration/deployment error that should be surfaced immediately, not hidden behind a "error" verdict.
- **Precedent:** Other security libraries (e.g., TLS certificate validation) raise exceptions on failures, not return degraded verdicts.

Callers who want to degrade gracefully can catch `DaemonUnreachableError` and either:
1. Return a safe default (e.g., block the operation)
2. Log and retry
3. Emit a fallback verdict of their own construction

### 2. Public surface re-export stability

The top-level `armor` package exports:
```python
from armor import (
    ArmorClient,         # Sync client
    AsyncArmorClient,    # Async client
    Verdict,             # Verdict dataclass
    HealthReport,        # Health status dataclass
    Incident,            # Forensic incident dataclass
)
```

These are the **stable public API**. All other modules are internal and may change.

**Semver contract:**
- **Patch (X.Y.Z):** Bug fixes, documentation, internal optimizations. Safe to upgrade.
- **Minor (X.Y):** New methods on existing classes, new dataclass fields (with defaults). Safe to upgrade if you're not relying on `isinstance` checks.
- **Major (X):** Method signature changes, removed fields, behavioral changes. Requires code review and testing.

Forbidden on patch/minor:
- Removing or renaming public classes
- Removing or renaming public methods
- Adding required (non-optional) parameters to public methods
- Changing the return type of a public method
- Changing `DaemonUnreachableError` to a different exception type

### 3. Type safety

All SDK code passes `mypy --strict` with no errors or `# type: ignore` pragmas (except in deliberate stubs for test doubles). This ensures:
- Static verification of method signatures
- IDE autocomplete and type-checking in user code
- Early detection of refactoring mistakes

### 4. Docstring standards

**NumPy-format docstrings** on all public symbols (classes, methods, functions) with:
- Brief one-line summary
- **Parameters** section describing each argument
- **Returns** section describing the return type and value
- **Raises** section documenting exceptions (e.g., `DaemonUnreachableError`)
- **Example** section for complex behavior

Docstring coverage target: ≥95% on `src/armor/sdk/`.

### 5. Session binding via context manager

The `client.session(session_id)` context manager binds a session ID to all checks made within its scope:

```python
with client.session("user-123") as s:
    v1 = s.check_input("msg 1")   # Implicitly uses session_id="user-123"
    v2 = s.check_input("msg 2")   # Implicitly uses session_id="user-123"
```

This pattern:
- Reduces boilerplate (no need to pass `session_id` to each call)
- Makes session scope explicit and intentional
- Fails gracefully if the context is exited (context manager is a no-op on exit)

Both sync and async clients support this, using `contextlib.contextmanager` and `contextlib.asynccontextmanager` respectively.

## Consequences

### Positive
- **Clear error semantics:** Callers know exactly when the daemon is unreachable vs. the input/output is blocked.
- **Predictable upgrade path:** The semver contract is unambiguous.
- **Type-safe library:** IDE support and compile-time checking prevent silent bugs.
- **Documented API:** High docstring coverage ensures new users can learn the API from the docstrings.
- **Framework agility:** Examples show integration with Anthropic, OpenAI, and LangChain SDKs without requiring core changes.

### Negative
- **Strict error handling:** Callers must explicitly handle `DaemonUnreachableError`. Some may prefer a degraded verdict instead.
- **Docstring maintenance burden:** High coverage target means every public symbol must be documented, increasing review time on SDK changes.
- **Limited flexibility:** Semver contract is rigid; future SDK enhancements that would otherwise be backward-compatible may be blocked if they require signature changes.

### Migration
No migration needed — this is the first version of the SDK public surface. Future versions will adhere to the semver contract defined here.

## Related ADRs

- **ADR-001:** Foundational tech stack (Python 3.12, dataclasses, type hints)
- **ADR-013:** Daemon subprocess integration tests (test isolation pattern for SDK integration tests)
