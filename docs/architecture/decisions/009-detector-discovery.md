# ADR-009 — Detector discovery via entry points

**Status:** Accepted
**Date:** 2026-05-05
**Deciders:** armor core team

## Context

The daemon must discover and load detectors at startup without hard-coding a list. Detectors live in separate modules under `src/armor/detectors/`, and new detectors (task 004/005/etc.) will add their own implementations.

The question is: how does the daemon find detectors at boot time?

## Decision

**Use Python entry points (`[project.entry-points."armor.detectors"]` in `pyproject.toml`), enumerated at daemon startup via `importlib.metadata.entry_points()`.**

Each detector module implements the `Detector` Protocol and registers itself in `pyproject.toml`:

```toml
[project.entry-points."armor.detectors"]
example = "armor.detectors.example:ExampleDetector"
```

At daemon boot, the `DetectorRegistry` calls:

```python
import importlib.metadata

def load_entry_point_detectors() -> dict[str, Detector]:
    detectors = {}
    for ep in importlib.metadata.entry_points(group="armor.detectors"):
        detector_class = ep.load()
        instance = detector_class()  # instantiate
        detectors[instance.id] = instance
    return detectors
```

The registry is populated once at daemon start, then read-only for the lifetime of the daemon process.

## Rationale

- **Standard Python convention**: Entry points are the idiomatic way to support plugins in Python packages. No custom registry files needed.
- **Zero coupling**: Detectors don't need to import each other or a central registry. Each is self-contained.
- **Clear dependencies**: The detector's package declares its entry point; tooling (pip, poetry, uv) enforces the plugin contract.
- **Easy to test**: Mock entry points in unit tests by patching `importlib.metadata.entry_points()`.
- **v0.1 compatible**: If no entry points are registered (empty `[project.entry-points."armor.detectors"]`), the registry is empty, and the daemon returns `pass` for all checks — safe and expected.

## Alternatives considered

1. **Explicit registry module**: A central `src/armor/detectors/registry.py` that imports all detectors.
   - Pros: Deterministic, no dynamic loading.
   - Cons: Tight coupling; every new detector requires editing the registry module. Violates Unix philosophy.

2. **Plugin file (YAML/JSON)**: A configuration file listing detector module paths.
   - Pros: Explicit, non-Python, easy to audit.
   - Cons: Requires file I/O at startup; adds a new configuration surface; less idiomatic for Python.

3. **Directory scan**: Scan `src/armor/detectors/` for modules matching a pattern (e.g., `^det_.*\.py$`).
   - Pros: Automatic discovery without any config.
   - Cons: Fragile; depends on naming conventions; harder to test; doesn't work with installed packages (only source installs).

4. **Module-level registration**: Each detector module calls a global `register_detector()` function on import.
   - Pros: Dynamic, flexible.
   - Cons: Side effects on import; difficult to order; hard to test in isolation.

## Consequences

- **No hot reload in v1**: Detectors are discovered once at daemon startup. Adding a new detector requires a daemon restart. Hot reload is explicitly deferred to v2+.
- **Entry points must be syntactically valid**: A malformed entry point (class not found, syntax error) causes daemon startup to fail. This is intentional — fail fast.
- **Detector instantiation**: The detector class is instantiated once at boot. This means detector __init__ runs once; any state initialization happens then. Detectors must be stateless or thread-safe (they're called concurrently by the daemon's asyncio event loop via `asyncio.to_thread`).

## Implementation notes

- `DetectorRegistry.__init__()` enumerates entry points and populates `self.detectors`.
- Errors during entry-point loading (missing class, invalid module) cause the registry to raise with a clear message naming the problematic entry point. The daemon's startup handler logs this and exits with code 78 (config error).
- The registry exposes `get(detector_id: str) -> Detector | None` and `all() -> list[Detector]`.
- For local development, detectors are editable (`pip install -e .` or `uv sync`), so entry points are live-linked to the source.

## See also

- [B-001 through B-003: Check operations](../../spec/behaviors.md) — the pipeline that runs discovered detectors
- Task 003 (this task) — implements detector discovery
- Task 004 (P0 regex detectors) — first set of concrete detectors; will populate entry points
- Task 005 (canary scanner) — second detector; will add entry point
