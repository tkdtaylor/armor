# Architecture — System Structure

**Project:** armor
**Last updated:** 2026-05-06

This file is the **catalog** that pairs with [`docs/architecture/diagrams.md`](../architecture/diagrams.md). The diagram shows the model visually; this file lists every container, component, and edge in tabular form so a drift audit can mechanically verify the model against the code.

When the diagram and this catalog disagree, one of them is wrong — fix it in the same commit. When the code disagrees with both, fix the code.

Containers are deployable units. Components are modules within a container. Both reference source paths.

---

## Containers

| Container | Role | Source path | Deployable as |
|-----------|------|-------------|---------------|
| `armor-daemon` | Long-lived Python process running the detector pipeline; single entry point for hooks and library clients | [src/armor/daemon/](../../src/armor/daemon/) | Docker image (`docker/`); `uv run armor daemon …` |
| `armor-cli` | Command-line entry for `armor daemon` (run server) and `armor check` (one-shot check via Unix socket) | [src/armor/cli.py](../../src/armor/cli.py), [src/armor/__main__.py](../../src/armor/__main__.py) | Console script `armor` (declared in `pyproject.toml`) |
| `armor-sdk` | Importable Python library — `Pipeline`, detectors, types, and Python-side wrapper for connecting to a daemon via Unix socket | [src/armor/](../../src/armor/) (excluding `daemon/`) | Python package `armor` |
| `armor-store` | SQLite database — session state, forensic incidents, quarantine table | [src/armor/db/](../../src/armor/db/) (managed in-process by daemon) | SQLite file in a mounted volume (path from `--db`) |

The daemon container is the single network-facing surface. The CLI and SDK either start a daemon (CLI) or connect to one (CLI via `check`, SDK via `client.py`).

---

## Components — `armor-sdk` / shared

| Component | Source | Responsibility | Depends on |
|-----------|--------|----------------|------------|
| `pipeline` | [src/armor/pipeline.py](../../src/armor/pipeline.py) | Composes detectors into a single pass; accepts a payload + `SessionContext`, returns the composed `Verdict`. Gates the `llm` cost tier on session state per ADR-024. | `types`, `detectors/*`, `db/session_store`, `session.state_machine` |
| `types` | [src/armor/types.py](../../src/armor/types.py) | `Verdict`, `SessionContext`, payload types — the shared vocabulary the rest of the system speaks | (leaf) |
| `client` | [src/armor/client.py](../../src/armor/client.py) | Low-level transport — `DaemonClient` that opens a Unix socket to a running daemon and sends a check request | `types` |
| `armor.sdk.client` | [src/armor/sdk/client.py](../../src/armor/sdk/client.py) | Public SDK wrapper — `ArmorClient` class re-exports daemon health and incident queries via the low-level client | `client`, `types` |
| `armor.sdk.async_client` | [src/armor/sdk/async_client.py](../../src/armor/sdk/async_client.py) | Async variant of the public SDK wrapper — `AsyncArmorClient` for async agent integration | `client`, `types` |
| `cli` | [src/armor/cli.py](../../src/armor/cli.py) | Argument parsing and dispatch for `armor daemon` and `armor check` subcommands | `daemon/server`, `client` |

## Components — `armor-daemon`

| Component | Source | Responsibility | Depends on |
|-----------|--------|----------------|------------|
| `daemon.server` | [src/armor/daemon/server.py](../../src/armor/daemon/server.py) | Unix-socket server; reads a check request, invokes `pipeline`, returns the verdict; persists FSM transitions on every check | `pipeline`, `db/session_store`, `db/forensic`, `armor.logging`, `daemon.honeypot_gate`, `session.state_machine` |
| `armor.logging` | [src/armor/logging.py](../../src/armor/logging.py) | Structured logging for daemon-side events; substitutes `canary_id` for canary values before persisting | `types` |
| `daemon.honeypot_gate` | [src/armor/daemon/honeypot_gate.py](../../src/armor/daemon/honeypot_gate.py) | Decides when to invoke the honeypot LLM path (gated by session state and per-path budget) | `llm.honeypot`, `session.state_machine` |

## Components — detectors

| Component | Source | Cost tier | Responsibility | Depends on |
|-----------|--------|-----------|----------------|------------|
| `detectors.canary_scanner` | [src/armor/detectors/canary_scanner.py](../../src/armor/detectors/canary_scanner.py) | static | Aho-Corasick scan for canary values in payload; emits `block` + `canary_id` on hit. Also re-scans `RollingBuffer.concatenated()` for chunked exfiltration per ADR-025. | `canaries.catalogue`, `canaries.scanner`, `types`, `session.rolling_buffer` |
| `detectors.regex_instruction_override` | [src/armor/detectors/regex_instruction_override.py](../../src/armor/detectors/regex_instruction_override.py) | static | Regex matches for "ignore previous instructions" family attacks | `types` |
| `detectors.regex_roleplay_hijack` | [src/armor/detectors/regex_roleplay_hijack.py](../../src/armor/detectors/regex_roleplay_hijack.py) | static | Regex matches for persona-swap / DAN-style jailbreaks | `types` |
| `detectors.regex_system_prompt_extraction` | [src/armor/detectors/regex_system_prompt_extraction.py](../../src/armor/detectors/regex_system_prompt_extraction.py) | static | Regex matches for system-prompt extraction attempts | `types` |
| `detectors.regex_encoding_request` | [src/armor/detectors/regex_encoding_request.py](../../src/armor/detectors/regex_encoding_request.py) | static | Regex matches for "encode this in base64/hex/rot13" exfiltration-prep requests | `types` |
| `detectors.entropy_decode` | [src/armor/detectors/entropy_decode.py](../../src/armor/detectors/entropy_decode.py) | static | Shannon-entropy substring scan + opportunistic decode-and-rescan; runs against single-turn output AND the rolling buffer (separate threshold) | `canaries._generate`, `canaries.catalogue`, `canaries.scanner`, `types` |
| `detectors.destination_extractor` | [src/armor/detectors/destination_extractor.py](../../src/armor/detectors/destination_extractor.py) | static | Extracts URLs / IPs / emails from output; flags non-whitelisted destinations | `types` |
| `detectors.cmd_injection_bash` | [src/armor/detectors/cmd_injection_bash.py](../../src/armor/detectors/cmd_injection_bash.py) | static | Denylist scanner for `Bash` tool calls (filesystem destruction, credential reads, container escape) | `types` |
| `detectors.tool_param_schema` | [src/armor/detectors/tool_param_schema.py](../../src/armor/detectors/tool_param_schema.py) | static | Schema-driven parameter-tampering check for tool calls; uses the bundled `tool_schemas.json` per ADR-016 | `types` |
| `detectors.topic_coherence` | [src/armor/detectors/topic_coherence.py](../../src/armor/detectors/topic_coherence.py) | static | Cosine-distance against a per-session EMA of MiniLM embeddings; advisory only; soft-fails on budget exceedance per ADR-026 | `embeddings.ema_cache`, `embeddings.onnx_embedder`, `types` |
| `detectors.jailbreak_template` | [src/armor/detectors/jailbreak_template.py](../../src/armor/detectors/jailbreak_template.py) | static + llm | Static templates (DAN, developer-mode, fictional framing) plus optional validator-LLM judgment | `llm.validator`, `types` |
| `detectors.llm_validator` | [src/armor/detectors/llm_validator.py](../../src/armor/detectors/llm_validator.py) | llm | Calls `llm.validator` with a structured-output prompt; emits `advisory` with confidence; gated by `session.state ≥ Watching` | `llm.validator`, `types` |

## Components — session

| Component | Source | Responsibility | Depends on |
|-----------|--------|----------------|------------|
| `session.state_machine` | [src/armor/session/state_machine.py](../../src/armor/session/state_machine.py) | Pure `apply_signal(state, score, signal, now) -> (state, score)`; FSM rules per ADR-024 (forward by signal, backward by linear cooldown, Blocked terminal) | `types` |
| `session.rolling_buffer` | [src/armor/session/rolling_buffer.py](../../src/armor/session/rolling_buffer.py) | Per-session bounded output buffer (`capacity_chars` / `capacity_turns`); fed by output checks; consumed by canary + entropy scanners per ADR-025 | (leaf) |

## Components — embeddings

| Component | Source | Responsibility | Depends on |
|-----------|--------|----------------|------------|
| `embeddings.onnx_embedder` | [src/armor/embeddings/onnx_embedder.py](../../src/armor/embeddings/onnx_embedder.py) | Singleton wrapper around `onnxruntime` for `all-MiniLM-L6-v2`; loads once at daemon start; `encode(text) -> np.ndarray` | (leaf — `onnxruntime` + `transformers` tokenizer) |
| `embeddings.ema_cache` | [src/armor/embeddings/ema_cache.py](../../src/armor/embeddings/ema_cache.py) | Per-session EMA store for the topic-coherence detector | (leaf) |

## Components — LLM (validator + honeypot)

| Component | Source | Responsibility | Depends on |
|-----------|--------|----------------|------------|
| `llm.loader` | [src/armor/llm/loader.py](../../src/armor/llm/loader.py) | Loads the quantised GGUF model once at daemon boot via `llama-cpp-python` | (leaf — `llama-cpp-python`) |
| `llm.session` | [src/armor/llm/session.py](../../src/armor/llm/session.py) | Wraps a single loaded model; both validator and honeypot share the same session | `loader` |
| `llm.validator` | [src/armor/llm/validator.py](../../src/armor/llm/validator.py) | Validator system prompt + structured-output parser per ADR-020; soft-fail on budget per ADR-023 | `session` |
| `llm.honeypot` | [src/armor/llm/honeypot.py](../../src/armor/llm/honeypot.py) | Honeypot system prompt with canary values injected at prompt-build time per ADR-021; never logs values | `session`, `canaries.catalogue` |

## Components — canaries

| Component | Source | Responsibility | Depends on |
|-----------|--------|----------------|------------|
| `canaries.catalogue` | [src/armor/canaries/catalogue.py](../../src/armor/canaries/catalogue.py) | Loads the bundled canary catalogue (`default_catalogue.json`) and any user-provided extras | `_generate` |
| `canaries.scanner` | [src/armor/canaries/scanner.py](../../src/armor/canaries/scanner.py) | Builds the Aho-Corasick automaton from catalogue values; provides `scan(text) -> list[hit]` | `catalogue` |
| `canaries._generate` | [src/armor/canaries/_generate.py](../../src/armor/canaries/_generate.py) | Install-time canary-value generation per ADR-010 (rewritten); writes the per-installation values file | (leaf) |

## Components — `armor-store` (db layer)

| Component | Source | Responsibility | Depends on |
|-----------|--------|----------------|------------|
| `db.migrations` | [src/armor/db/migrations.py](../../src/armor/db/migrations.py) | Applies `schema.sql` and any future schema bumps idempotently | (leaf) |
| `db.session_store` | [src/armor/db/session_store.py](../../src/armor/db/session_store.py) | Persists per-session risk state, FSM fields (`current_state`, `risk_score`, `last_signal_at`), and the `session_rolling_buffer` table | `migrations`, `types` |
| `db.forensic` | [src/armor/db/forensic.py](../../src/armor/db/forensic.py) | Writes blocked-attack incident records — input, attempted output, `canary_id` (never the value), destination | `migrations`, `types` |
| `db.operator_audit` | [src/armor/db/operator_audit.py](../../src/armor/db/operator_audit.py) | Appends operator audit-log rows when the session-state machine's `clear_blocked()` unblocks a session | `migrations` |
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
