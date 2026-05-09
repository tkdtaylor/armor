# ADR 029: Structured-Log Schema

**Status:** Accepted

**Date:** 2026-05-06

---

## Context

The daemon currently logs via the Python `logging` module with a JSON formatter (`src/armor/logging.py`). As the operator-facing surface matures (task 028 — Operator UX), we need a stable, machine-parseable log schema that allows operators to:

1. Filter and tail logs programmatically
2. Export to SIEM / observability systems
3. Correlate logs with operator actions (e.g., manual unblock via `armor sessions unblock`)
4. Audit changes to session state

The current JSON formatter in `armor/logging.py` produces output with `timestamp`, `level`, `message`, and `logger` fields, but lacks the domain-specific fields needed for operator visibility (session_id, request_id, decision, latency, etc.).

## Decision

**Structured logs are JSON objects, one per line (NDJSON format).** Every line conforms to this schema:

| Field | Type | Presence | Notes |
|-------|------|----------|-------|
| `ts` | ISO 8601 string | Required | UTC timestamp in ISO format (e.g., `2026-05-06T14:23:45.123456Z`) |
| `level` | string | Required | One of: `debug`, `info`, `warning`, `error` |
| `event` | string | Required | Event type (e.g., `check.input.started`, `session.unblock`, `daemon.boot`) |
| `session_id` | string | Optional | Session identifier; required for any check-related event |
| `request_id` | string | Optional | Unique request identifier; required for any check-related event |
| `detector_id` | string | Optional | Name of the detector (e.g., `regex_instruction_override`); only present if a detector ran |
| `decision` | string | Optional | Detector output (`pass`, `block`, `advisory`); only present if a detector ran |
| `latency_ms` | number | Optional | Round-trip latency in milliseconds; only present for check operations |
| `message` | string | Optional | Human-readable log message |
| `exception` | string | Optional | Exception traceback; only present if an error occurred |

### Examples

**Input check started (all required fields):**
```json
{
  "ts": "2026-05-06T14:23:45.123456Z",
  "level": "info",
  "event": "check.input.started",
  "session_id": "localhost-12345-abc123",
  "request_id": "req-001",
  "message": "Starting input check"
}
```

**Detector ran (with decision and detector_id):**
```json
{
  "ts": "2026-05-06T14:23:45.234567Z",
  "level": "info",
  "event": "check.detector.run",
  "session_id": "localhost-12345-abc123",
  "request_id": "req-001",
  "detector_id": "regex_instruction_override",
  "decision": "block",
  "latency_ms": 12
}
```

**Check completed (with overall latency):**
```json
{
  "ts": "2026-05-06T14:23:45.345678Z",
  "level": "info",
  "event": "check.input.completed",
  "session_id": "localhost-12345-abc123",
  "request_id": "req-001",
  "decision": "block",
  "latency_ms": 123
}
```

**Operator unblock action (audit event):**
```json
{
  "ts": "2026-05-06T14:25:00.000000Z",
  "level": "info",
  "event": "session.unblock",
  "session_id": "localhost-12345-abc123",
  "message": "Session manually unblocked by operator",
  "reason": "manual review cleared"
}
```

**Daemon boot (no session context):**
```json
{
  "ts": "2026-05-06T14:00:00.000000Z",
  "level": "info",
  "event": "daemon.boot",
  "message": "armor daemon started, listening on /var/run/armor.sock"
}
```

### Field semantics

- **`ts`:** Always ISO 8601 UTC, with microseconds. Example: `2026-05-06T14:23:45.123456Z`.
- **`level`:** Matches Python logging levels: `debug`, `info`, `warning`, `error`.
- **`event`:** Hierarchical dot-separated string (e.g., `check.input.completed`, `session.unblock`). Allows filtering by event family (`check.*`, `session.*`).
- **`session_id`:** Required for any check operation (input, output, tool) and any session-management operation (unblock, close). Absent for daemon-level events (boot, shutdown).
- **`request_id`:** Unique identifier for a single check request. Allows correlation across multiple detector runs within one check. Format: `req-<uuid>` or similar.
- **`detector_id`:** Name of the detector that produced the decision. Omitted if no detector ran or the decision came from the pipeline (e.g., a sentinel decision before any detector ran).
- **`decision`:** One of `pass`, `block`, `advisory`. Only present if a decision was made (i.e., a detector or gating rule returned a verdict).
- **`latency_ms`:** Wall-clock elapsed time in milliseconds. For `check.*.completed`, it's end-to-end latency. For `check.detector.run`, it's the detector's own latency. Never negative.
- **`message`:** Human-readable explanation. Optional; may duplicate information in structured fields (for readability in text-only contexts, e.g., tailing logs via `tail -f`).
- **`exception`:** Full traceback if an exception occurred. Implies `level` ≥ `error`. Useful for debugging crashes.

## Consequences

1. **Operator observability:** Operators can now filter logs by event, session, or decision, and integrate with SIEM systems via JSON parsing.
2. **Backward compatibility:** The JSON formatter is new; existing Python code (test harnesses, evaluations) continues to work. If the daemon's logging behavior changes, old clients parsing the old format will continue to work (they just won't see the new fields).
3. **Schema versioning:** If the schema evolves, new fields are added as optional; existing fields are never deleted or renamed. Clients should tolerate unknown fields.
4. **Audit trail:** Operator actions (unblock, clear) are logged with the same schema, enabling full audit trails.
5. **No secrets in logs:** The schema never includes raw payload, canary values, or user-controlled input. Only IDs, hashes, and sanitized metadata appear in logs.

## Trade-offs

- **Field verbosity:** Some events require multiple fields. This is intentional — machine-parseable logs should be complete enough to stand alone without external context.
- **No request context in non-check events:** Non-check events (e.g., daemon boot) have no request_id. This is correct — they are not tied to a specific client request.
- **Timestamp precision:** Microseconds are included to support millisecond-latency operations. This adds a few bytes per line but is negligible in NDJSON volume.

## Related

- Task 028 — Operator UX
- ADR 028 — SDK surface stability
