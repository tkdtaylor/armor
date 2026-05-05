# Data Model

**Project:** armor
**Last updated:** 2026-05-05

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
state            text           one of: Normal | Watching | Elevated | High | Blocked
risk_score       integer        0..100, monotonically non-decreasing per session
turn_count       integer        increments on each input check
signal_history   blob (json)    rolling window of last 50 signals: [{ts, kind, signal_id, severity}]
```

- **Identity:** `session_id`. The hook generates and sends it; if absent the daemon mints `anon-<uuid>`.
- **Lifecycle:** Created on first check in a session. Updated on every check. Deleted 24h after the `Stop` hook fires (or never, if no `Stop` hook).

#### Entity: `Incident` (forensic log)

```
field             type        notes
──────────────────────────────────────────────────────
id                integer     PK autoinc
ts                timestamp   UTC
session_id        text        FK Session.session_id (nullable for boot-time errors)
attack_category   text        e.g. "direct_injection.instruction_override", "exfiltration.canary_leak"
signal_id         text        which detector + which rule fired (e.g. "regex:override-001")
input_hash        text        sha256 of input
output_hash       text        sha256 of output (nullable for input-side blocks)
triggered_canary  text        canary_id if applicable (NEVER the canary value itself)
destinations      blob (json) extracted URLs/IPs/emails (sanitized: hostnames only)
encoding_flag     boolean
risk_score        integer     session risk score at time of block
action            text        "blocked" | "advisory_only" | "passed_with_warning"
quarantine_id    integer     FK QuarantinedPayload.id (nullable)
```

- **Lifecycle:** Append-only. Never updated. Never deleted.
- **Indexes:** `(session_id, ts)`, `(attack_category, ts)`.

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

#### Entity: `CanaryCatalogue` (snapshot)

```
field          type      notes
─────────────────────────────────────
canary_id      text      PK; e.g. "aws-key-001", "github-pat-002"
kind           text      "credential" | "url" | "path" | "hostname" | "wallet" | ...
service        text      "aws" | "github" | "stripe" | ...
value          text      the actual canary string (encrypted at rest)
marker_rule    text      how to deterministically identify this value (regex or algorithmic)
created_at     timestamp UTC
active         boolean
```

- **Identity:** `canary_id`. Stable across catalogue rotations.
- **Lifecycle:** Generated at container build (or on `armor canary regenerate`). Within a running daemon, the active set is fixed — no mid-session rotation.

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
  "op": "check.input" | "check.output" | "check.tool" | "session.close",
  "session_id": "claude-code-12345-abc",
  "payload": { "text": "...", "tool": "...", "params": {} }
}
```

**Response:**
```json
{
  "v": 1,
  "verdict": "pass" | "block" | "advisory" | "try_later" | "error",
  "signal_id": "regex:override-001",
  "message": "Input blocked: instruction-override pattern matched.",
  "incident_id": 42
}
```

- **Versioning:** Top-level `v` integer. Daemon supports the current version + the previous one.

### Format: Forensic incident NDJSON (export)

- **Producer:** `armor incidents export` CLI
- **Consumer:** Operator tooling, SIEM ingestion

```json
{"ts":"2026-05-05T18:30:01Z","session_id":"claude-code-12345-abc","attack_category":"exfiltration.canary_leak","signal_id":"canary:aws-key-001","input_hash":"...","output_hash":"...","triggered_canary":"aws-key-001","destinations":["webhook.site"],"encoding_flag":false,"risk_score":85,"action":"blocked"}
```

---

## Derived data

| Derived | Source | Recompute trigger | Staleness tolerance |
|---------|--------|-------------------|---------------------|
| Session `state` | `signal_history` + transition rules | Every check | Computed live; no caching |
| Session `risk_score` | `signal_history` weighted sum | Every check | Computed live |
| Aho-Corasick automaton | `CanaryCatalogue` active rows | Daemon boot only | Frozen for daemon lifetime |

---

## Data invariants

- For every `Incident` row, either `quarantine_id IS NULL` OR `QuarantinedPayload.id = quarantine_id` exists (FK enforced).
- `Session.risk_score` is monotonically non-decreasing within a session (enforced by the daemon, not the DB).
- No `Incident.triggered_canary` value ever equals an actual canary string — it is always the `canary_id`. Enforced by the canary scanner code path; spot-checked in tests.
- Active `CanaryCatalogue` rows are immutable for the daemon's lifetime. (Inactive rows can be added/removed; the active set is snapshotted at boot.)
