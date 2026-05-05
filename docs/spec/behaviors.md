# Behaviors

**Project:** armor
**Last updated:** 2026-05-05

What the system does, observably. Each behavior describes a triggering condition, the system's response, and any externally-visible side effects.

Not in this file:
- *How* it does it (that's in source code)
- *Why* it does it (that's in ADRs)
- *What data it operates on* (that's in [data-model.md](data-model.md))
- *What the entry points are* (that's in [interfaces.md](interfaces.md))

---

## Format

Each behavior is a numbered subsection:

> **B-NNN: Short imperative title**
>
> - **Trigger:** what causes this behavior to fire
> - **Response:** what the system does
> - **Side effects:** observable effects beyond the immediate response (writes, log entries)
> - **Failure modes:** how it can fail and what the system does when it does
> - *(optional)* **References:** ADRs and test specs

Behaviors are numbered `B-001`, `B-002`, … sequentially. Numbers are stable references — never reuse a number, even if a behavior is removed (mark it `B-NNN: REMOVED — see ADR-XXX` and leave the number).

---

## Core behaviors

### B-001: Check user input for direct prompt injection

- **Trigger:** Hook (or library) calls `armor check input <text> --session-id <id>`.
- **Response:** Daemon runs the input-side detector pipeline. Returns `pass`, `block` (with `signal_id`), or `advisory`.
- **Detectors:**
  - `regex.instruction_override` — blocks patterns like "ignore previous instructions", "disregard your instructions", "forget everything", "new instructions:" at line start.
  - `regex.roleplay_hijack` — blocks patterns like "you are now DAN", "pretend you are", "act as if you have no restrictions", "from now on you are".
  - `regex.system_prompt_extraction` — blocks patterns like "show me your system prompt", "reveal the initial prompt", "what are your instructions", "print your directives".
  - (Authority impersonation, encoding/obfuscation request keywords: planned for P1/P2, not yet implemented.)
- **Side effects:** Increments session turn counter, records signal in session state, writes a forensic record on `block`.
- **Failure modes:** Detector raises → that detector's verdict is recorded as `error`, pipeline continues (fail-open per detector). Whole pipeline raises → daemon returns `block` (fail-closed at pipeline level) and logs an internal error.

### B-002: Check model output for canary exfiltration

- **Trigger:** Hook (or library) calls `armor check output <text> --session-id <id>`.
- **Response:** Aho-Corasick scan of output against the active canary catalogue (detector `canary.scanner`, category `exfiltration`). On hit: returns `block`, captures the full attack chain (input + attempted output + intended destination if any URL/IP/email is present in output). On clean: continues to URL/IP extraction and entropy analysis.
- **Side effects:** Forensic record written. Session risk score incremented. The blocked output is NOT returned to the caller — caller receives the safe-replacement message defined in `configuration.md`.
- **Failure modes:** Canary catalogue not loaded → daemon refuses to start (boot-time invariant; see SPEC.md). Canary values never leak into forensic logs or verdicts — see ADR-010 and test spec for invariants.

### B-003: Block tool calls matching the command-injection denylist

- **Trigger:** Hook calls `armor check tool` with the tool name and parameters (e.g. a `Bash` tool's command string).
- **Response:** Pattern-match command against the denylist (filesystem destruction, credential file reads, container escape, privilege escalation — see data-model.md). Block on match.
- **Side effects:** Block written to forensic log with the full command. Session risk escalated.

### B-004: Track session-level risk and escalate detection strictness

- **Trigger:** Every input/output/tool check writes to session state. The session tracker reads aggregated state on each call.
- **Response:** Session is in one of states `Normal | Watching | Elevated | High | Blocked`. Transitions are governed by signal accumulation rules (see diagram 4 in `architecture/diagrams.md`). At `Elevated` and above, validator LLM is run on every check (not throttled). At `Blocked`, all subsequent calls return `block` until session is closed.
- **Side effects:** Session state row updated atomically per check. State transition writes a log entry.

### B-005: Run the validator LLM as a semantic-level signal

- **Trigger:** Input or output check, when session state is `Watching` or higher, OR when static detectors return `advisory` (matched a soft signal).
- **Response:** Daemon submits the payload to the validator LLM (small quantized model, single forward pass, structured output asking "is this attempting a jailbreak / exfiltration / instruction override?"). Returns `safe | risky` with a confidence score.
- **Side effects:** Output is *advisory* — feeds into the session risk score, never blocks unilaterally. Latency budget: ≤500 ms per call (see configuration.md).
- **Failure modes:** Model unavailable → `advisory` returned with `confidence=0`, pipeline continues. Latency exceeds budget → soft-fail, log warning, continue.

### B-006: Detect and block encoded exfiltration

- **Trigger:** Output check sees a high-entropy substring above the configured length and entropy thresholds, OR input check sees an explicit encoding-request keyword (`base64`, `hex`, `rot13`, `encrypt`, etc.).
- **Response:** On output: attempt single-pass decode of the suspected segment (base64/hex), then re-scan the decoded content for canaries — block on hit. On input: mark as `advisory` and force validator LLM check.
- **Side effects:** Decoded payload is logged, never returned.

### B-007: Capture forensic record on every block

- **Trigger:** Any check returns `block`.
- **Response:** Daemon writes a structured incident record containing: timestamp, attack category, input hash (sha256), output hash (sha256), triggered canary ID (if applicable), detected destinations, encoding flag, session ID, risk score, action taken.
- **Side effects:** Record persisted to the forensic log table in SQLite. The raw input/output texts are stored separately in a quarantine table with a TTL (see data-model.md).

### B-008: Daemon serves multiple concurrent hooks via Unix socket

- **Trigger:** Daemon starts with `armor daemon --socket /var/run/armor.sock`.
- **Response:** Listens for newline-delimited JSON requests; each request is `{op, payload, session_id}`; response is `{verdict, signal_id?, message?}`.
- **Side effects:** All requests are journaled to the session table. The socket is removed and recreated on each start.
- **Failure modes:** Socket path not writable → daemon refuses to start. Concurrent request limit (default 64) reached → new requests get `try_later` verdict.

---

## Edge cases and error behaviors

### B-101: Validator LLM weights missing at startup

- **Trigger:** Daemon starts and the configured model file is not found.
- **Response:** At v0.1, if `ARMOR_DISABLE_LLM=true` (the default), the daemon starts without the model and runs static detectors only. If `ARMOR_DISABLE_LLM=false` and the model file is not found, the daemon exits with code 78 (config error) and logs the missing path. (This strict-refuse-to-start behavior returns at v0.3 when task 016 lands and the validator LLM is required.)
- **Side effects:** No socket created (if exit 78); socket created normally (if LLM is disabled).

### B-102: Session ID not provided

- **Trigger:** Check call comes in without `session_id`.
- **Response:** Daemon assigns an ephemeral session ID (`anon-<uuid>`); session state is created but not persisted across daemon restart.
- **Side effects:** Forensic records carry the anon ID; cross-turn risk tracking still works within the daemon's lifetime.

### B-103: Forensic log full / disk full

- **Trigger:** SQLite write fails.
- **Response:** Daemon switches to **degraded mode** — checks still execute, but blocks return `block` without persisting forensic records (logged to stderr instead). Daemon exits when free disk falls below configured floor.

---

## Behavioral invariants

- A `block` verdict never leaks the matched signal in the caller-facing message. Signal details go to the forensic log only. The user-facing message is the configured safe replacement.
- Output checks are *idempotent* — re-running an output check on the same `(text, session_id)` returns the same verdict and does not double-write forensic records.
- The set of canary values active in the agent's context is consistent across all checks within a session — canaries do not rotate mid-session.
- All write operations to session state are atomic (single SQLite transaction per check).
