# ADR-010: Canary Catalogue Storage — JSON file at v0.1

**Status:** Accepted
**Decision date:** 2026-05-05
**Supersedes:** None

## Context

Task 005 implements the canary catalogue — a set of fake credentials, URLs, and other honeypot values that are seeded into the validator LLM's context and detectable in agent output via Aho-Corasick scanning.

The catalogue must be:
- Available at daemon startup (immutable for the daemon's lifetime)
- Validatable (each `value` must match its `marker_rule` regex)
- Surveyable (operators can list active canaries without seeing values)
- Rotatable (canaries eventually need refreshing, though v0.1 doesn't auto-regenerate)

Two storage options exist:

### Option A: JSON file (chosen)
- **Pros:**
  - Simple, declarative. Package ships with `default_catalogue.json` baked in.
  - Load happens once at daemon boot; no runtime DB I/O for reads.
  - Easy to version-control and audit (git diff).
  - Enables pre-generation of seeded values at build time (no runtime RNG).
  - No coupling with task 006 (SQLite state store). Catalogue rotation can be file replacement + daemon restart in v0.1.

- **Cons:**
  - Rotation requires daemon restart (no live reload).
  - Catalogue snapshots eventually stale (operators must regenerate and restart manually at v0.1).

### Option B: SQLite table (deferred to v0.3)
- **Pros:**
  - Live reload possible (future enhancement).
  - Audit trail possible (record row creation timestamps).

- **Cons:**
  - Requires SQLite at boot (task 006 dependency). Creating a 005↔006 dependency loop complicates the task DAG.
  - Runtime load() cost (query on every daemon restart).
  - Temptation to store plaintext values in DB (security risk unless encrypted at rest).

## Decision

**Use JSON file storage for v0.1.** Load the catalogue from a JSON file path (configurable via `--catalogue` flag, defaulting to a bundled package resource). Validation happens at boot; daemon refuses to start (exit 78) on invalid catalogue.

Catalogue rotation in v0.1: operator replaces the JSON file and restarts the daemon. No live reload.

The `armor canary regenerate` subcommand and live-reload enhancements land in v0.3+ after task 006 (SQLite state) and task 016 (model rotation) are complete.

## Consequences

1. **Default catalogue is committed:** `src/armor/canaries/default_catalogue.json` is generated once by running `_seed.py` (with a fixed seed) and checked into git. Future runs of `_seed.py` will overwrite it; that's fine.

2. **Daemon `--catalogue` flag:** Daemon accepts `--catalogue <path>` (or defaults to the bundled JSON path). At boot, catalogue is loaded, validated, and frozen for the daemon's lifetime.

3. **Catalogue mutation:** Inactive canaries can be added/removed by editing the JSON and restarting; the active set is snapshotted at boot. Active canaries do not change mid-session.

4. **SQLite canary table (v0.2+):** When task 006 lands, the `CanaryCatalogue` entity in the data model moves to SQLite. A migration path from JSON → SQLite will be added in a later ADR.

5. **No `armor canary regenerate` at v0.1:** The CLI subcommand is planned but deferred. It lands at v0.3 when the seeding algorithm is stable and the SQLite catalogue is in place.

## Alternatives considered

- **Inline seeding at daemon boot:** Generate canaries on every startup (no JSON file). Rejected because deterministic reproduction (for testing and audits) is essential; embedding the seed in code is fragile.

- **Environment variable catalogue:** Pass entire catalogue as a large env var. Rejected because env vars are logged/recorded in many systems; not suitable for storing credential patterns.

## Related decisions

- **ADR-005:** Use `pyahocorasick` for pattern matching (the library that scans for canary values).
- **ADR-004:** Use SQLite for session state (separate from catalogue storage in v0.1, will merge in v0.3).
