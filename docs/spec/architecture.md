# Architecture — System Structure

**Project:** armor
**Last updated:** 2026-05-05

This file is the **catalog** that pairs with [`docs/architecture/diagrams.md`](../architecture/diagrams.md). The diagram shows the model visually; this file lists every container, component, and edge in tabular form so a drift audit can mechanically verify the model against the code.

When the diagram and this catalog disagree, one of them is wrong — fix it in the same commit. When the code disagrees with both, fix the code.

Containers are deployable units. Components are modules within a container. Both reference source paths.

---

## Containers

| Container | Role | Source path | Deployable as |
|-----------|------|-------------|---------------|
| `armor-daemon` | Long-lived Python process running the detector pipeline; single entry point for hooks and library clients | [src/armor/daemon/](../../src/armor/daemon/) | Docker image (`docker/`); `uv run armor daemon …` |
| `armor-cli` | Command-line entry for `armor daemon` (run server) and `armor check` (one-shot check via Unix socket) | [src/armor/cli.py](../../src/armor/cli.py), [src/armor/__main__.py](../../src/armor/__main__.py) | Console script `armor` (declared in `pyproject.toml`) |
| `armor-sdk` | Importable Python library — `Pipeline`, detectors, types, in-process client for embedding inside agents | [src/armor/](../../src/armor/) (excluding `daemon/`) | Python package `armor` |
| `armor-store` | SQLite database — session state, forensic incidents, quarantine table | [src/armor/db/](../../src/armor/db/) (managed in-process by daemon) | SQLite file in a mounted volume (path from `--db`) |

The daemon container is the single network-facing surface. The CLI and SDK either start a daemon (CLI) or connect to one (CLI via `check`, SDK via `client.py`).

---

## Components — `armor-sdk` / shared

| Component | Source | Responsibility | Depends on |
|-----------|--------|----------------|------------|
| `pipeline` | [src/armor/pipeline.py](../../src/armor/pipeline.py) | Composes detectors into a single pass; accepts a payload + `SessionContext`, returns the composed `Verdict` | `types`, `detectors/*`, `db/session_store` |
| `types` | [src/armor/types.py](../../src/armor/types.py) | `Verdict`, `SessionContext`, payload types — the shared vocabulary the rest of the system speaks | (leaf) |
| `client` | [src/armor/client.py](../../src/armor/client.py) | Library/CLI side of the IPC contract — opens a Unix socket to a running daemon and sends a check request | `types` |
| `cli` | [src/armor/cli.py](../../src/armor/cli.py) | Argument parsing and dispatch for `armor daemon` and `armor check` subcommands | `daemon/server`, `client` |

## Components — `armor-daemon`

| Component | Source | Responsibility | Depends on |
|-----------|--------|----------------|------------|
| `daemon.server` | [src/armor/daemon/server.py](../../src/armor/daemon/server.py) | Unix-socket server; reads a check request, invokes `pipeline`, returns the verdict | `pipeline`, `db/session_store`, `db/forensic`, `daemon.logging` |
| `daemon.logging` | [src/armor/daemon/logging.py](../../src/armor/daemon/logging.py) | Structured logging for daemon-side events; substitutes `canary_id` for canary values before persisting | `types` |

## Components — detectors

| Component | Source | Responsibility | Depends on |
|-----------|--------|----------------|------------|
| `detectors.canary_scanner` | [src/armor/detectors/canary_scanner.py](../../src/armor/detectors/canary_scanner.py) | Aho-Corasick scan for canary values in payload; emits `block` + `canary_id` on hit | `canaries.scanner`, `types` |
| `detectors.regex_instruction_override` | [src/armor/detectors/regex_instruction_override.py](../../src/armor/detectors/regex_instruction_override.py) | Regex matches for "ignore previous instructions" family attacks | `types` |
| `detectors.regex_roleplay_hijack` | [src/armor/detectors/regex_roleplay_hijack.py](../../src/armor/detectors/regex_roleplay_hijack.py) | Regex matches for persona-swap / DAN-style jailbreaks | `types` |
| `detectors.regex_system_prompt_extraction` | [src/armor/detectors/regex_system_prompt_extraction.py](../../src/armor/detectors/regex_system_prompt_extraction.py) | Regex matches for system-prompt extraction attempts | `types` |

## Components — canaries

| Component | Source | Responsibility | Depends on |
|-----------|--------|----------------|------------|
| `canaries.catalogue` | [src/armor/canaries/catalogue.py](../../src/armor/canaries/catalogue.py) | Loads the bundled canary catalogue (`default_catalogue.json`) and any user-provided extras | `_seed` |
| `canaries.scanner` | [src/armor/canaries/scanner.py](../../src/armor/canaries/scanner.py) | Builds the Aho-Corasick automaton from catalogue values; provides `scan(text) -> list[hit]` | `catalogue` |
| `canaries._seed` | [src/armor/canaries/_seed.py](../../src/armor/canaries/_seed.py) | Deterministic value generator used to (re-)seed the bundled catalogue | (leaf) |

## Components — `armor-store` (db layer)

| Component | Source | Responsibility | Depends on |
|-----------|--------|----------------|------------|
| `db.migrations` | [src/armor/db/migrations.py](../../src/armor/db/migrations.py) | Applies `schema.sql` and any future schema bumps idempotently | (leaf) |
| `db.session_store` | [src/armor/db/session_store.py](../../src/armor/db/session_store.py) | Persists per-session risk state, recent verdicts, and turn counters | `migrations`, `types` |
| `db.forensic` | [src/armor/db/forensic.py](../../src/armor/db/forensic.py) | Writes blocked-attack incident records — input, attempted output, `canary_id` (never the value), destination | `migrations`, `types` |
| `db.quarantine` | [src/armor/db/quarantine.py](../../src/armor/db/quarantine.py) | Encrypted quarantine of high-risk artifacts gated by `ARMOR_QUARANTINE_KEY` | `migrations` |
| `db.sweeper` | [src/armor/db/sweeper.py](../../src/armor/db/sweeper.py) | Periodic cleanup — TTL eviction of old session rows and forensic records past retention | `session_store`, `forensic` |

---

## Cross-container edges

The runtime edges that cross container boundaries — these are the integration points and what a hook author needs to know about:

| From | To | Transport | Purpose |
|------|-----|----------|---------|
| Hook (Claude Code) | `armor-daemon` | Unix domain socket (path from `--socket`) | Per-turn `check input` / `check output` request |
| `armor-sdk` (library client) | `armor-daemon` | Unix domain socket (same as above) | Same request shape; lets agent code embed armor without spawning the CLI |
| `armor-cli` (`armor check`) | `armor-daemon` | Unix domain socket | Dev / CI smoke test of a single payload |
| `armor-daemon` | `armor-store` (SQLite file) | Direct file I/O via `db/*` | Persists session and forensic state; mounted as a Docker volume |

Edges that **must not exist** (invariants):

- No outbound network call from `armor-daemon` code path. `requests`/`httpx`/`urllib3` imports inside `src/armor/daemon/` fail CI.
- No detector invokes another detector directly. Composition happens in `pipeline`.
- No code path writes a canary value verbatim into `db.forensic` rows — substitution to `canary_id` is the writer's responsibility, asserted by a unit test.

---

## How this catalog is maintained

- **Same-commit rule.** When a task adds a container, splits a component, moves a source path, or changes a `Depends on` edge, this file and `diagrams.md` change in the same commit.
- **Drift audit input.** The `architect` agent's drift-audit mode reads this file to verify each row's source path exists, each `Depends on` edge resolves to a real import / call site, and the row set matches the boxes in `diagrams.md`.
- **Catalog + diagram parity.** Every C4 box in `diagrams.md` must have a matching row here, and vice versa. If a row does not appear in the diagram, either the diagram is missing a box or the row is stale — fix one, in the same commit.
