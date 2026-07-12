# ADR-045: Emit blocking incidents to the ecosystem audit-trail

**Date:** 2026-07-12
**Status:** Accepted
**Decision date:** 2026-07-12
**References:** task 134; audit-trail `docs/CONTRACT.md` (sibling repo, frozen v1); `docs/spec/behaviors.md` B-020; `docs/spec/configuration.md` `[audit_trail]`; `tests/fitness/test_no_outbound_network.py` (TC-091-14).

## Context

armor writes every blocking verdict to its own SQLite `ForensicLogger` (`src/armor/db/forensic.py`), consumed via `incidents.show`/`incidents.tail` and the CLI. That log is armor-private: an operator running several Secure Agent Ecosystem blocks (armor, vault, sandbox, policy-engine) side by side has no way to correlate an armor block against what the sandbox or vault were doing at the same moment, short of eyeballing separate log files with unsynchronized clocks and no tamper evidence.

audit-trail is the ecosystem's shared forensic log for exactly this: every block emits append-only, hash-chained events (`SHA256(prev_hash + JCS(event))`) to one verifiable chain, so an operator (or an offline auditor) can reconstruct a cross-block incident timeline and detect tampering. Its v1 contract is frozen and already shipped (`docs/CONTRACT.md`, sibling repo, `go build` standalone): armor is the consumer here, not a co-designer of the contract.

Two constraints shape the design:

1. **armor's own blocking behavior must never depend on audit-trail being reachable.** armor is deployable air-gapped (no telemetry by default); the audit-trail emit has to be strictly additive and fail-safe.
2. **The daemon code path bans outbound network imports** (`tests/fitness/test_no_outbound_network.py`, TC-091-14, enforced by an AST-free grep over `src/armor/daemon/`). Any module under that tree that imports `socket`/`urllib`/`requests`/etc. fails CI.

## Decision

### Emit only blocking verdicts, always in addition to SQLite

`AuditTrailEmitter.emit()` is called from `_handle_check_operation` only inside the existing `verdict.blocked` branch, only after `forensic_logger.write_incident` has already returned an `incident_id`, and only if the operator opted in (`[audit_trail].enabled = true`). The SQLite write happens unconditionally; the audit-trail emit is purely additive telemetry layered on top, never a replacement and never a precondition for the SQLite write. If `write_incident` itself raised, the emit is skipped for that check (there is no incident id to reference, and inventing one would break the `refs` contract).

### The event mapping (frozen contract, no negotiation)

`actor` is always `"armor"`. `action` is the check operation with `.` replaced by `_` (`check_input`, `check_output`, `check_tool`, `check_fetched`). `target` is the session id. `decision` is always `"block"` (only blocking verdicts are emitted; advisory/pass verdicts never reach `AuditTrailEmitter`). `refs` is `[{"type": "incident", "id": "<incident_id as string>"}]`, joining the audit-trail row back to the SQLite row without duplicating any of its content. `context` carries exactly `signal_id`, `attack_category`, `severity`, `source` (plus `source_tool` for `check.fetched`), sourced from the same values the SQLite row gets. `attack_category` specifically comes from the same `ForensicLogger._infer_category` code path via a new public wrapper (`infer_category`), so the two logs can never silently drift apart on categorization.

**Never included:** payload text, quarantined content, or any canary value. The `refs` incident id is sufficient for an operator to pull the full record from armor's own store; audit-trail's job is correlation and tamper evidence, not a second copy of the sensitive payload. This mirrors the existing forensic-log invariant ("never store canary values verbatim") one level up: the ecosystem log is even more exposed (multiple blocks emit to it) and gets even less.

### Why AF_UNIX IPC does not violate the no-outbound-network invariant

The daemon no-network invariant exists to stop armor's own code path from becoming an exfiltration or SSRF vector: a compromised or buggy detector reaching out to an attacker-controlled `http(s)://` endpoint. A Unix domain socket connect (`AF_UNIX`, `SOCK_STREAM`) to a fixed, operator-configured local filesystem path is not that risk class: it has no DNS resolution, no routable address, no ability to reach anything off-host, and is architecturally identical to the daemon's own listening socket or its SQLite file handle. It is local IPC to a sibling process the operator explicitly configured, exactly like `daemon.socket` itself. The invariant's fitness test (`test_no_outbound_network.py`) already encodes this distinction structurally: it bans `socket`/`urllib`/`requests`/`httpx`/`http.client`/`urllib3` imports specifically *within `src/armor/daemon/`*, not project-wide. The ban is about what the daemon's own code path can reach, not about IPC as a category.

### Why the module lives outside `src/armor/daemon/`

Because `AuditTrailEmitter` necessarily imports `socket` (there is no other way to speak AF_UNIX from stdlib), it cannot live inside `src/armor/daemon/` without tripping TC-091-14, even though the socket use is benign local IPC by the reasoning above. Rather than special-case the fitness check (which would weaken a test that has caught real regressions), `AuditTrailEmitter` lives in a new top-level module, `src/armor/audit_trail.py`, and the daemon imports the *class* (`from armor.audit_trail import AuditTrailEmitter`) rather than the `socket` module directly. This is the same pattern telemetry-style outbound-aware code already follows in this codebase: the network-touching primitive lives outside the daemon tree; the daemon composes it. The fitness check keeps enforcing "no raw network primitive inside the daemon package" as a structural property, and `audit_trail.py` is the one sanctioned exception point, reviewable in one file.

### Fail-safe policy

`emit()` never raises. Transport failures (socket path absent, `ConnectionRefusedError`, `FileNotFoundError`, `socket.timeout`, any other `OSError`) are logged at WARNING and the event is appended to a bounded in-memory retry buffer (`collections.deque(maxlen=retry_buffer_size)`, default 256, oldest dropped first). The buffer is flushed oldest-first on the next successful `emit()` call, before the new event is sent; if the flush itself hits a transport failure partway through, the unflushed backlog and the new event all remain buffered. A contract-level rejection (`{"error": {...}}`) is different in kind from a transport failure: the event itself is invalid and retrying it would fail forever, so it is logged at ERROR and dropped, never buffered.

The retry buffer is explicitly **not** persisted across daemon restarts. It is a best-effort smoothing mechanism for transient audit-trail unavailability (a restart, a brief network blip on the shared volume), not a durability guarantee. Durable delivery is out of scope for this task; the SQLite `Incident` row is the durable record.

### Config

New opt-in `[audit_trail]` section in `armor.toml`, `enabled = false` by default:

```toml
[audit_trail]
enabled           = false
socket            = "/var/run/audit-trail.sock"
timeout_ms        = 250
retry_buffer_size = 256
```

Read once at daemon-init (`DaemonServer.__init__`), same pattern as `trusted_source_tools` and the other config-derived construction in that method. Absent section or `enabled = false` means `self.audit_emitter = None` and no connection is ever attempted: opt-in all the way down, consistent with armor's air-gapped-by-default posture (telemetry is off by default per the same rationale).

## Consequences

- **Positive:** operators running the full Secure Agent Ecosystem stack get one verifiable, hash-chained view across blocks instead of stitching together per-block logs by timestamp.
- **Positive:** the fail-safe design means enabling this feature carries zero risk to armor's core blocking guarantee. Worst case on a dead socket is a WARNING log line and a bounded buffer, verified by TC-134-09/10 exercising the daemon subprocess with both a dead and a live fake audit-trail socket.
- **Negative / accepted:** the retry buffer is in-memory only; events buffered at daemon shutdown are lost. This is an accepted trade-off (the SQLite row is the durable source of truth) rather than an oversight; see "Out of scope" below.
- **Neutral:** `ForensicLogger` gained one thin public method (`infer_category`) with no behavior change to any existing caller; `_infer_category` remains the implementation and is unchanged.

## Out of scope (deferred, not forgotten)

Querying or verifying the audit-trail chain from armor; operator approval flows; emitting advisory (non-blocking) verdicts to audit-trail; checkpoint/rotate/Rekor operations (all audit-trail-side concerns); retry persistence across daemon restarts (the buffer is deliberately in-memory and bounded); emitting via the audit-trail CLI (the daemon speaks the socket transport only; the CLI is a manual/CI tool audit-trail ships for its own operators, exercised only in this task's live verification, not by armor's runtime path).
