# Architecture — System Structure

**Project:** armor
**Last updated:** 2026-05-24

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
| `pipeline` | [src/armor/pipeline.py](../../src/armor/pipeline.py) | Composes detectors into a single pass; accepts a payload + `SessionContext`, returns the composed `Verdict`. LLM cost-tier gating per ADR-024 lives inside each LLM detector (`detectors/llm_validator`, `detectors/jailbreak_template`), not in the pipeline. | `types`, `detectors/*`, `db/session_store` |
| `types` | [src/armor/types.py](../../src/armor/types.py) | `Verdict`, `SessionContext`, payload types — the shared vocabulary the rest of the system speaks | (leaf) |
| `client` | [src/armor/client.py](../../src/armor/client.py) | Low-level transport — `DaemonClient` that opens a Unix socket to a running daemon and sends a check request | `types` |
| `armor.sdk.client` | [src/armor/sdk/client.py](../../src/armor/sdk/client.py) | Public SDK wrapper — `ArmorClient` class re-exports daemon health and incident queries via the low-level client | `client`, `types` |
| `armor.sdk.async_client` | [src/armor/sdk/async_client.py](../../src/armor/sdk/async_client.py) | Async variant of the public SDK wrapper — `AsyncArmorClient` for async agent integration | `client`, `types` |
| `cli` | [src/armor/cli.py](../../src/armor/cli.py) | Argument parsing and dispatch for `armor daemon` and `armor check` subcommands | `daemon/server`, `client` |

## Components — `armor-daemon`

| Component | Source | Responsibility | Depends on |
|-----------|--------|----------------|------------|
| `daemon.server` | [src/armor/daemon/server.py](../../src/armor/daemon/server.py) | Unix-socket server; reads a check request, invokes `pipeline`, returns the verdict; persists FSM transitions on every check. Loads and injects LLM session into LLM-dependent detectors at boot via post-load loop (mechanism A). Conditionally injects `detectors.output_harmful_content` when `detector.output_harmful_content.enabled=true` and `detectors.cross_boundary_override` when `detector.cross_boundary_override.enabled=true` (default on, per ADR-043 §3). | `pipeline`, `db.migrations`, `db.session_store`, `db.forensic`, `db.quarantine`, `db.sweeper`, `db.operator_audit`, `armor.logging`, `daemon.honeypot_gate`, `session.state_machine`, `llm.session`, `canaries.catalogue`, `canaries.scanner`, `detectors.canary_scanner`, `detectors.destination_extractor`, `detectors.instruction_burial`, `detectors.conversation_hijack`, `detectors.output_harmful_content` (conditional), `detectors.cross_boundary_override` (conditional) |
| `armor.logging` | [src/armor/logging.py](../../src/armor/logging.py) | Structured logging for daemon-side events; substitutes `canary_id` for canary values before persisting | `types` |
| `daemon.honeypot_gate` | [src/armor/daemon/honeypot_gate.py](../../src/armor/daemon/honeypot_gate.py) | Decides when to invoke the honeypot LLM path (gated by session state and per-path budget) | `llm.honeypot`, `session.state_machine` |

## Components — detectors

| Component | Source | Cost tier | Responsibility | Depends on |
|-----------|--------|-----------|----------------|------------|
| `detectors.canary_scanner` | [src/armor/detectors/canary_scanner.py](../../src/armor/detectors/canary_scanner.py) | static | Aho-Corasick scan for canary values in the payload; emits `block` + `canary_id` on any match. The rolling-buffer scan for chunked / paraphrased exfiltration lives in `detectors.canary_paraphrase` (n-gram coverage), not here. | `canaries._generate`, `canaries.catalogue`, `canaries.scanner`, `types` |
| `detectors.canary_paraphrase` | [src/armor/detectors/canary_paraphrase.py](../../src/armor/detectors/canary_paraphrase.py) | static | N-gram coverage detector for paraphrased canary leaks (Approach A per ADR-034); scans rolling buffer for ≥ K distinct n-grams of same canary; emits `advisory` with confidence formula | `canaries.catalogue`, `types`, `session.rolling_buffer` |
| `detectors.canary_chunked` | [src/armor/detectors/canary_chunked.py](../../src/armor/detectors/canary_chunked.py) | static | Chunked-canary block path (B-009c); scans the concatenated rolling buffer for a complete canary value reconstructed across turns and emits `block` + `canary_id` on a full match. Distinct from `detectors.canary_paraphrase`, which matches n-gram fragments. | `canaries.catalogue`, `session.rolling_buffer`, `types` |
| `detectors.regex_authority_impersonation` | [src/armor/detectors/regex_authority_impersonation.py](../../src/armor/detectors/regex_authority_impersonation.py) | static | Regex matches for authority-impersonation injection attacks | `types` |
| `detectors.regex_instruction_override` | [src/armor/detectors/regex_instruction_override.py](../../src/armor/detectors/regex_instruction_override.py) | static | Regex matches for "ignore previous instructions" family attacks | `types` |
| `detectors.regex_roleplay_hijack` | [src/armor/detectors/regex_roleplay_hijack.py](../../src/armor/detectors/regex_roleplay_hijack.py) | static | Regex matches for persona-swap / DAN-style jailbreaks | `types` |
| `detectors.regex_system_prompt_extraction` | [src/armor/detectors/regex_system_prompt_extraction.py](../../src/armor/detectors/regex_system_prompt_extraction.py) | static | Regex matches for system-prompt extraction attempts | `types` |
| `detectors.regex_encoding_request` | [src/armor/detectors/regex_encoding_request.py](../../src/armor/detectors/regex_encoding_request.py) | static | Regex matches for "encode this in base64/hex/rot13" exfiltration-prep requests | `types` |
| `detectors.memory_planting` | [src/armor/detectors/memory_planting.py](../../src/armor/detectors/memory_planting.py) | static | Regex matches for memory-planting injection patterns ("remember this rule", "from now on always", "permanent instruction", etc.) | `types` |
| `detectors.entropy_decode` | [src/armor/detectors/entropy_decode.py](../../src/armor/detectors/entropy_decode.py) | static | Shannon-entropy substring scan + opportunistic decode-and-rescan against single-turn output. Multi-turn coverage of canary fragments is handled by `detectors.canary_paraphrase` (n-gram on the rolling buffer), not here. | `canaries._generate`, `canaries.catalogue`, `canaries.scanner`, `types` |
| `detectors.destination_extractor` | [src/armor/detectors/destination_extractor.py](../../src/armor/detectors/destination_extractor.py) | static | Extracts URLs / IPs / emails from output; flags non-whitelisted destinations | `types` |
| `detectors.instruction_burial` | [src/armor/detectors/instruction_burial.py](../../src/armor/detectors/instruction_burial.py) | static | Detects instruction-override and system-prompt-extraction patterns buried in the tail (last 25%) of long inputs; reuses patterns from `regex.instruction_override` and `regex.system_prompt_extraction` per ADR-037 | `regex_instruction_override.get_compiled_patterns`, `regex_system_prompt_extraction.get_compiled_patterns`, `types` |
| `detectors.cross_boundary_override` | [src/armor/detectors/cross_boundary_override.py](../../src/armor/detectors/cross_boundary_override.py) | static | Scans tool-result / untrusted-span content for boundary-escape attempts: an embedded spotlight sentinel (`sentinel_forgery`) or an instruction-override / system-prompt-extraction / roleplay-hijack / authority-impersonation pattern crossing the trust boundary (per ADR-043 §3–4). Default-on; conditionally injected by `daemon.server`. Emits `block` at confidence ≥ `block_threshold`, `advisory` otherwise. Reuses compiled patterns from the regex detectors (fitness-permitted cross-import per `tests/fitness/test_detector_no_cross_import.py`). | `regex_instruction_override.get_compiled_patterns`, `regex_system_prompt_extraction.get_compiled_patterns`, `regex_roleplay_hijack.get_compiled_patterns`, `regex_authority_impersonation.get_compiled_patterns`, `types` |
| `detectors.cmd_injection_bash` | [src/armor/detectors/cmd_injection_bash.py](../../src/armor/detectors/cmd_injection_bash.py) | static | Denylist scanner for `Bash` tool calls (filesystem destruction, credential reads, container escape) | `types` |
| `detectors.tool_param_schema` | [src/armor/detectors/tool_param_schema.py](../../src/armor/detectors/tool_param_schema.py) | static | Schema-driven parameter-tampering check for tool calls; uses the bundled `tool_schemas.json` per ADR-016 | `types` |
| `detectors.topic_coherence` | [src/armor/detectors/topic_coherence.py](../../src/armor/detectors/topic_coherence.py) | semantic | Cosine-distance against a per-session EMA of MiniLM embeddings; advisory only; soft-fails on budget exceedance per ADR-026 | `embeddings.ema_cache`, `embeddings.onnx_embedder`, `types` |
| `detectors.token_count_anomaly` | [src/armor/detectors/token_count_anomaly.py](../../src/armor/detectors/token_count_anomaly.py) | static | Running mean/std-dev of input lengths per session; advisory on z-score > threshold or absolute-cap exceedance per ADR-037 | `types` |
| `detectors.tool_rate_anomaly` | [src/armor/detectors/tool_rate_anomaly.py](../../src/armor/detectors/tool_rate_anomaly.py) | static | Sliding-window per-tool call-rate tracking per session; advisory when burst detected per ADR-040 | `types` |
| `detectors.tool_chain` | [src/armor/detectors/tool_chain.py](../../src/armor/detectors/tool_chain.py) | static | Detects multi-turn attack chains (e.g., Read .env → WebFetch); per-session history tracking with strict/loose matching per ADR-040 | `types` |
| `detectors.conversation_hijack` | [src/armor/detectors/conversation_hijack.py](../../src/armor/detectors/conversation_hijack.py) | static | Detects claims of prior agreement without corroboration; reads `SessionContext.signal_history` to calibrate confidence per ADR-037 | `types` |
| `detectors.regex_code_injection` | [src/armor/detectors/regex_code_injection.py](../../src/armor/detectors/regex_code_injection.py) | static | Regex matches for Python code injection via `__import__('subprocess')` dynamic import bypass and subprocess/`os.system` calls paired with network exfiltration tools; scans both input text and `code`/`input` tool parameters | `types` |
| `detectors.regex_exfil_chain` | [src/armor/detectors/regex_exfil_chain.py](../../src/armor/detectors/regex_exfil_chain.py) | static | Regex matches for instruction-then-exfiltrate chains (`then`/`and` + send verb + external URL) and URLs with suspicious exfiltration path suffixes (`/collect`, `/exfil`, `/steal`, `/harvest`, etc.) | `types` |
| `detectors.regex_sensitive_file_probe` | [src/armor/detectors/regex_sensitive_file_probe.py](../../src/armor/detectors/regex_sensitive_file_probe.py) | static | Regex matches for sensitive file read-intent probes (`.env`, `id_rsa`, `id_ed25519`, `/etc/shadow`, `.netrc`, `secrets.yaml`), environment-variable enumeration requests, and write-intent to privileged system files (`/etc/crontab`, `/etc/sudoers`, `/etc/hosts`) | `types` |
| `detectors.regex_ssrf_probe` | [src/armor/detectors/regex_ssrf_probe.py](../../src/armor/detectors/regex_ssrf_probe.py) | static | Regex matches for SSRF probe attempts targeting cloud IMDS endpoints (AWS `169.254.169.254`, GCP `metadata.google.internal`, Alibaba `100.100.100.200`) and `file://` URI schemes | `types` |
| `detectors.jailbreak_template` | [src/armor/detectors/jailbreak_template.py](../../src/armor/detectors/jailbreak_template.py) | llm | Static templates (DAN, developer-mode, fictional framing) plus optional validator-LLM judgment. Cost tier reflects highest invocation path. LLM session injected at daemon boot (mechanism A). | `llm.validator`, `types` |
| `detectors.llm_validator` | [src/armor/detectors/llm_validator.py](../../src/armor/detectors/llm_validator.py) | llm | Calls `llm.validator` with a structured-output prompt; emits `advisory` with confidence; gated by `session.state ≥ Watching`. LLM session injected at daemon boot (mechanism A). | `llm.validator`, `types` |
| `detectors.output_harmful_content` | [src/armor/detectors/output_harmful_content.py](../../src/armor/detectors/output_harmful_content.py) | llm | **Opt-in** (disabled by default; enabled via `detector.output_harmful_content.enabled=true`). Two-stage: regex fast-path scans `MODEL_OUTPUT` payloads for runnable attack commands (cloud credential exfil, IMDS probes, privilege escalation chains); stage 2 calls `llm.validator` for confirmation. Emits `block` when LLM confidence ≥ `block_threshold`, `advisory` otherwise. Injected at daemon boot by `daemon.server` when enabled. | `llm.validator`, `types` |

## Components — session

| Component | Source | Responsibility | Depends on |
|-----------|--------|----------------|------------|
| `session.state_machine` | [src/armor/session/state_machine.py](../../src/armor/session/state_machine.py) | Pure `apply_signal(state, score, signal, now) -> (state, score)`; FSM rules per ADR-024 (forward by signal, backward by linear cooldown, Blocked terminal) | `types` |
| `session.rolling_buffer` | [src/armor/session/rolling_buffer.py](../../src/armor/session/rolling_buffer.py) | Per-session bounded output buffer (`capacity_chars` / `capacity_turns`); fed by output checks; consumed by `detectors.canary_paraphrase` (n-gram coverage per B-009b) | (leaf) |

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
| `canaries.activation` | [src/armor/canaries/activation.py](../../src/armor/canaries/activation.py) | Evaluates per-canary activation rules (path/intent context); decides which canaries are active for a given check per ADR-038 | `catalogue`, `types` |

## Components — `armor-store` (db layer)

| Component | Source | Responsibility | Depends on |
|-----------|--------|----------------|------------|
| `db.migrations` | [src/armor/db/migrations.py](../../src/armor/db/migrations.py) | Applies `schema.sql` and any future schema bumps idempotently | (leaf) |
| `db.session_store` | [src/armor/db/session_store.py](../../src/armor/db/session_store.py) | Persists per-session risk state, FSM fields (`current_state`, `risk_score`, `last_signal_at`), and the `session_rolling_buffer` table | `migrations`, `types` |
| `db.forensic` | [src/armor/db/forensic.py](../../src/armor/db/forensic.py) | Writes blocked-attack incident records — input, attempted output, `canary_id` (never the value), destination | `migrations`, `types` |
| `db.operator_audit` | [src/armor/db/operator_audit.py](../../src/armor/db/operator_audit.py) | Appends operator audit-log rows; called from `session.state_machine` when `clear_blocked()` unblocks a session | `migrations` |
| `db.quarantine` | [src/armor/db/quarantine.py](../../src/armor/db/quarantine.py) | Encrypted quarantine of high-risk artifacts; key sourced from `--quarantine-key-path` (or `<db_dir>/.key` fallback) per ADR-011 | `migrations` |
| `db.sweeper` | [src/armor/db/sweeper.py](../../src/armor/db/sweeper.py) | Periodic cleanup — TTL eviction of expired quarantine rows | `quarantine` |

---

## Cross-container edges

The runtime edges that cross container boundaries — these are the integration points and what a hook author needs to know about:

| From | To | Transport | Purpose |
|------|-----|----------|---------|
| Hook (Claude Code) | `armor-daemon` | Unix domain socket (path from `--socket`) | Per-turn `check input` / `check output` request |
| `armor-sdk` (library client) | `armor-daemon` | Unix domain socket (same as above) | Same request shape; lets agent code embed armor without spawning the CLI |
| `armor-cli` (`armor check`) | `armor-daemon` | Unix domain socket | Dev / CI smoke test of a single payload |
| PostToolUse hook (Claude Code) | `armor-daemon` | Unix domain socket | Per-tool-result `check.fetched` request (indirect injection scanning) |
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
