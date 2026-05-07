# Data Model

**Project:** armor
**Last updated:** 2026-05-06

What data exists, how it's structured, where it lives, and what relationships hold between entities.

---

## Persistent state

### Store: SQLite `armor.db`

**Purpose:** Session state, forensic incident log, quarantined raw payloads, canary catalogue snapshot.
**Owner:** Daemon (single writer). Held open with WAL mode for concurrent readers.
**Backup / retention:** Forensic records: indefinite by default. Quarantined raw payloads: TTL governed by `quarantine_ttl_hours` (default 168 = 7 days). Session state: deleted 24h after `Stop` hook fires for the session.

#### Entity: `Session`

```
field            type           notes
─────────────────────────────────────────────────────
session_id       text           PK; format: "<host>-<pid>-<uuid8>" or "anon-<uuid>"
created_at       timestamp      UTC, set by daemon
last_seen_at     timestamp      UTC, updated on every check
current_state    text           one of: Normal | Watching | Elevated | High | Blocked
risk_score       real           non-negative float, current operational risk level (decays over time via cooldown)
turn_count       integer        increments on each input check
signal_history   blob (json)    rolling window of last 50 signals: [{ts, kind, signal_id, severity}]
last_signal_at   real           Unix timestamp of the last signal (used for cooldown decay calculation)
```

- **Identity:** `session_id`. The hook generates and sends it; if absent the daemon mints `anon-<uuid>`.
- **Lifecycle:** Created on first check in a session. Updated on every check. Deleted 24h after the `Stop` hook fires (or never, if no `Stop` hook).
- **State semantics:** Session FSM state (see B-004 in behaviors.md). Drives cost-tier gating in the pipeline (LLM detectors run iff state ≥ Watching).
- **Risk score:** Aggregated detector signal scores (advisory confidence × weight). Accumulates forward on advisories, decays backward via cooldown over wall-clock time. Not monotonic (can decrease). Current operational risk level, not a risk history ledger.
- **Cooldown:** Computed per-check using `current_score - (cooldown_decay_per_min * (now - last_signal_at_minutes))`. Decay is applied before the new signal contributes.

#### Entity: `Incident` (forensic log)

```
field             type        notes
──────────────────────────────────────────────────────
id                integer     PK autoinc
ts                timestamp   UTC
session_id        text        FK Session.session_id (nullable for boot-time errors)
attack_category   text        e.g. "direct_injection", "exfiltration", "tool_abuse"
signal_id         text        which detector + which rule fired (e.g. "regex.instruction_override:override-001", "cmd_injection.bash:fs-rm-rf-root")
input_hash        text        sha256 of input
output_hash       text        sha256 of output (nullable for input-side blocks)
triggered_canary  text        canary_id if applicable (NEVER the canary value itself)
destinations      blob (json) extracted URLs/IPs/emails (sanitized: hostnames only)
encoding_flag     boolean     true if the block was triggered by the `entropy.decode_rescan` detector (encoded exfiltration)
risk_score        integer     session risk score at time of block
action            text        "blocked" | "advisory_only" | "passed_with_warning"
quarantine_id    integer     FK QuarantinedPayload.id (nullable)
```

- **Lifecycle:** Append-only. Never updated. Never deleted.
- **Indexes:** `(session_id, ts)`, `(attack_category, ts)`.
- **Destinations note:** The `destinations` field is populated by the `extractor.destinations` detector (task 011) for exfiltration category checks. It stores hostnames only (no paths, queries, fragments, ports, or email local-parts). Always included in forensic records for audit trail, even if the verdict is `pass` (all whitelisted) or `advisory`.

#### Entity: `QuarantinedPayload`

```
field          type       notes
──────────────────────────────────────────────────────
id             integer    PK autoinc
ts             timestamp  UTC
input_text     text       raw input (encrypted at rest with daemon-local key)
output_text    text       raw output, if applicable
expires_at     timestamp  UTC; row purged when now > expires_at
```

- **Lifecycle:** Written on `block`. Auto-deleted by background sweeper after `expires_at`.

#### Entity: `OperatorAuditLog`

```
field          type       notes
──────────────────────────────────────────────────────
id             integer    PK autoinc
ts             timestamp  UTC; when the operator action occurred
actor          text       operator identifier (host user or auth principal)
action         text       e.g. "session.unblock", "session.clear"
session_id     text       session targeted by the action
reason         text       free-form text from `--reason` flag (required for `unblock`)
```

- **Lifecycle:** Append-only. Written by `armor sessions unblock` and any future operator-clear actions.
- **Invariant:** Never deleted; this is the audit trail for manual state changes.

#### Entity: `SessionRollingBuffer` (rolling multi-turn output aggregation)

```
field          type       notes
──────────────────────────────────────────────────────
id             integer    PK autoinc
session_id     text       FK Session.session_id
turn_id        text       unique identifier for this turn within the session
text           text       the turn's output text
created_at     timestamp  UTC; used for ordering
```

- **Purpose:** Append-only log of output texts per session. Used to reconstruct the rolling-buffer state for multi-turn exfiltration detection (behavior B-009a). On every output check, the current output is appended; the rolling buffer (in-memory, bounded by both chars and turns) loads all historical entries and evicts oldest entries as needed.
- **Lifecycle:** Appended on every output check. Rows are not deleted by the current daemon; per-session bounding is enforced at read time (the loader rehydrates the buffer with `capacity_chars` / `capacity_turns` limits, evicting oldest entries beyond the bound). A periodic sweeper to purge rows for ended sessions is tracked separately as a deferred hygiene task.
- **Indexes:** `(session_id, created_at)` for fast lookups of a session's rolling buffer.
- **Data invariants:** Text is never encrypted or hashed (raw output stored). Text is never logged verbatim to forensic records — chunked-canary blocks reference `turn_ids` and `canary_id` only.
- **Cleanup:** No automatic deletion in the current daemon. Operators can reclaim space by deleting rows for ended sessions out of band; a periodic sweeper is tracked as a deferred hygiene task.

#### Entity: `CanaryCatalogue` (in-memory snapshot)

**Source:** Merged from schema (bundled, `src/armor/canaries/default_catalogue.json`) + values (runtime-injected, path specified by `daemon.canary_values_path` or `ARMOR_CANARY_VALUES_PATH`).

```
field          type      notes
─────────────────────────────────────
canary_id      text      PK; e.g. "aws-key-001", "github-pat-002"
kind           text      "credential" | "url" | "path" | "hostname" | "wallet" | ...
service        text      "aws" | "github" | "stripe" | ...
value          text      the actual canary string (never committed to repo; loaded at boot)
marker_rule    text      how to deterministically identify this value (regex or algorithmic)
created_at     timestamp UTC
active         boolean
```

**Schema vs. Values split (v0.2+):**
- **Schema** (bundled): `src/armor/canaries/default_catalogue.json` contains the metadata (canary_id, kind, service, marker_rule, active, created_at). The `value` field is never present in this file.
- **Values** (runtime): A values file (generated by `armor canary generate` at install time) contains the full merged catalogue, including the actual canary values. This file is loaded from `daemon.canary_values_path` or `ARMOR_CANARY_VALUES_PATH` at daemon boot.
- **Merge:** At daemon boot, schema + values are merged using `canary_id` as the join key. Active set is frozen for the daemon's lifetime.

**Data invariants:**
- Per-installation isolation: Each deployment generates its own values; no value is shared across installations.
- Immutability: The active set is fixed at daemon boot and does not change during the daemon's lifetime.
- Forensic safety: Forensic log references `canary_id`, never `value`. The values file itself is never logged or transmitted outside the daemon process.
- Value isolation: Canary values are read only by the honeypot path (`src/armor/llm/honeypot.py`). The validator LLM (`src/armor/llm/validator.py`) never accesses `catalogue.values()` or reads the `value` field (enforced by fitness function `tests/fitness/validator_no_value_access.py`).
- Value transit: Canary values flow from the in-memory catalogue → honeypot.py → prompt substitution → LLM context window (volatile). Values never appear in prompt template files (only placeholders like `{{canary:id}}`), never in forensic logs, never in the validator path.
- Identity:** `canary_id`. Stable across catalogue rotations and installations.
- **Lifecycle:** Values generated at install time by `armor canary generate`. Schema bundled with the package. Catalogue merged at daemon boot and frozen for the daemon's lifetime.

#### Entity: `ToolSchemas` (in-memory registry, frozen at boot)

**Source:** Bundled in repo at `src/armor/detectors/tool_schemas.json`.

```
field          type      notes
───────────────────────────────────────────
tool_name      text      e.g. "Bash", "Read", "Write", "Edit", "Glob", "Grep", "NotebookEdit"
params_schema  object    JSON schema defining required/optional params and their types
risk_rules     array     List of rule objects; each has id, description, type, patterns
```

**Structure of a tool schema entry:**
```json
{
  "Bash": {
    "params_schema": {
      "command": {"type": "string", "required": true}
    },
    "risk_rules": []
  },
  "Read": {
    "params_schema": {
      "file_path": {"type": "string", "required": true},
      "offset": {"type": "integer", "required": false},
      "limit": {"type": "integer", "required": false}
    },
    "risk_rules": [
      {
        "id": "dangerous-file",
        "description": "Block reads of sensitive files",
        "type": "path_pattern",
        "patterns": ["/etc/shadow", "~/.ssh/id_*", ...]
      }
    ]
  }
}
```

**Data invariants:**
- Loaded once at detector init (detector instantiation time, not daemon boot).
- Frozen for the detector's lifetime; no re-read or hot-reload.
- Unknown tool names in incoming requests → return `pass` with `details["unknown_tool"]=true` (observable, not blocked).
- Read-only tools (Glob, Grep) have empty risk_rules arrays (safe operations, no blocking rules).
- Risk rule type determines matching logic: `path_pattern` (literal + wildcard matching), `path_pattern_with_replace_all` (path + boolean condition), `command_pattern` (literal string search).
- **Lifecycle:** Bundled with the package. Loaded at detector init. Frozen for the daemon's lifetime.

---

## In-memory state

### State: `DetectorRegistry`

- **Shape:** `dict[str, Detector]` keyed by detector ID. Held by the daemon process.
- **Owner:** Daemon main thread. Read-only after boot.
- **Lifetime:** Daemon lifetime. Reload requires daemon restart (no hot-reload in v1).
- **Concurrency rules:** Read-only after boot — safe for unsynchronized concurrent reads. New detectors registered only at boot.

### State: `SessionCache`

- **Shape:** `dict[str, SessionRow]` — write-through cache over the SQLite Session table.
- **Owner:** Daemon. Bounded LRU, default 1024 sessions.
- **Concurrency rules:** Per-session lock acquired in cache; SQLite write happens under that lock to keep state monotonic.
- **Bounds:** LRU evicts least-recently-touched session; evicted state remains in SQLite.

### State: `LLMSession` (the validator + honeypot model)

- **Shape:** A single `llama_cpp.Llama` instance held by the daemon, plus two prompt templates (validator system prompt, honeypot system prompt).
- **Owner:** Daemon. Single-threaded inference; calls serialized through a queue.
- **Lifetime:** Loaded at daemon start. Reload requires daemon restart.

---

## Wire / interchange formats

### Format: Daemon IPC (newline-delimited JSON over Unix socket)

- **Producer:** Hook clients, Python SDK
- **Consumer:** armor daemon

**Request:**
```json
{
  "v": 1,
  "op": "check.input" | "check.output" | "check.tool" | "session.close" |
        "canary.list" |
        "incidents.list" | "incidents.show" | "incidents.tail" | "incident.get" |
        "sessions.list" | "sessions.show" | "sessions.unblock" |
        "health.full",
  "session_id": "claude-code-12345-abc",
  "payload": { ... }
}
```

**Response (check / session.close):**
```json
{
  "v": 1,
  "verdict": "pass" | "block" | "advisory" | "try_later" | "error",
  "signal_id": "regex:override-001",
  "message": "Input blocked: instruction-override pattern matched.",
  "incident_id": 42
}
```

**Operator-UX op payloads and response shapes:**

| Op | Request payload | Response (success) |
|----|----------------|-------------------|
| `canary.list` | `{}` | `{ "verdict": "pass", "canaries": [{canary_id, kind, service, active}, ...] }` |
| `incidents.list` / `incidents.tail` | `{ "limit"?: 50, "session_id"?: str, "category"?: glob, "since_id"?: int }` | `{ "verdict": "pass", "incidents": [<incident row>...] }` |
| `incidents.show` | `{ "incident_id": int|str }` | `{ "verdict": "pass", "incident": <row>|null }` |
| `incident.get` | `{ "id": int|str }` | `{ "verdict": "pass", "incident": <row>|null }` (SDK form) |
| `sessions.list` | `{ "state"?: str }` | `{ "verdict": "pass", "sessions": [<session row>...] }` |
| `sessions.show` | `{ "session_id": str }` | `{ "verdict": "pass", "session": <row>|null }` |
| `sessions.unblock` | `{ "session_id": str, "reason": str (non-empty), "actor"?: str }` | `{ "verdict": "pass", "new_state": "Watching" }` or `{ "verdict": "error", "message": "..." }` if not Blocked or `reason` missing |
| `health.full` | `{}` | `{ "verdict": "pass", "health": {socket_reachable, db_reachable, model_loaded, uptime_seconds, ...} }` |

- **Versioning:** Top-level `v` integer. Daemon supports the current version + the previous one.

### Format: Forensic incident NDJSON (export)

- **Producer:** `armor incidents export` CLI
- **Consumer:** Operator tooling, SIEM ingestion

```json
{"ts":"2026-05-05T18:30:01Z","session_id":"claude-code-12345-abc","attack_category":"exfiltration.canary_leak","signal_id":"canary:aws-key-001","input_hash":"...","output_hash":"...","triggered_canary":"aws-key-001","destinations":["webhook.site"],"encoding_flag":false,"risk_score":85,"action":"blocked"}
```

---

## Validator output format

When detector `llm.validator` runs (triggered by advisory or elevated session state), it returns a structured advisory verdict with:

```
Verdict {
  decision: "advisory",
  signal_id: "llm.validator:safe" | "llm.validator:risky",
  severity: "low" (safe) | "high" (risky),
  message: "LLM validator: safe" or "LLM validator: risky",
  details: {
    "confidence": <float 0.0..1.0>,
    "validator_response": "safe" | "risky"
  }
}
```

The confidence score is used in session risk scoring (per ADR-024 — fed to `apply_signal` weighted by `pipeline.llm_validator_weight`). Parse failures (malformed JSON) return `confidence: 0.0`.

---

## Derived data

| Derived | Source | Recompute trigger | Staleness tolerance |
|---------|--------|-------------------|---------------------|
| Session `state` | `signal_history` + transition rules | Every check | Computed live; no caching |
| Session `risk_score` | `signal_history` weighted sum + validator confidence | Every check | Computed live |
| Aho-Corasick automaton | `CanaryCatalogue` active rows | Daemon boot only | Frozen for daemon lifetime |

---

## Data invariants

- For every `Incident` row, either `quarantine_id IS NULL` OR `QuarantinedPayload.id = quarantine_id` exists (FK enforced).
- `Session.risk_score` is the session's current operational risk: non-negative, increased by advisory signals (weighted by detector and confidence), and decayed linearly over wall-clock time at `session.cooldown_decay_per_min` (per ADR-024). It is **not** monotonic.
- No `Incident.triggered_canary` value ever equals an actual canary string — it is always the `canary_id`. Enforced by the canary scanner code path; spot-checked in tests.
- Active `CanaryCatalogue` rows are immutable for the daemon's lifetime. (Inactive rows can be added/removed; the active set is snapshotted at boot.)
