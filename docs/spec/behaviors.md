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
- **Failure modes:** Canary catalogue not loaded at boot → daemon exits with code 78 (config error). Canary values file (path specified by `daemon.canary_values_path` or `ARMOR_CANARY_VALUES_PATH`) is missing, malformed, or contains values that don't match their `marker_rule` patterns → daemon exits 78 at startup. Canary values never leak into forensic logs or verdicts — see ADR-010 for invariants and testing requirements.

### B-003: Block tool calls matching the command-injection denylist

- **Trigger:** Hook calls `armor check tool` with the tool name and parameters (e.g. a `Bash` tool's command string).
- **Response:** Detector `cmd_injection.bash` (id `cmd_injection.bash`, category `tool_abuse`, cost tier `static`) pattern-matches the command string against the denylist in `src/armor/detectors/cmd_injection_patterns.yaml`. Blocks on first match. Returns pass for non-Bash tools or empty/missing commands.
- **Pattern families:** The denylist is organized into four families:
  - **Filesystem destruction:** Patterns matching `rm -rf /`, `rm -rf ~`, `rm -rf $HOME`, `dd if=/dev/zero of=/dev/sd*`, `mkfs`, fork bombs (`:(){:|:&};:`), `shred` on system dirs.
  - **Credential reads:** Patterns matching `/etc/shadow`, `/etc/sudoers`, `~/.ssh/id_*` (private keys), `~/.aws/credentials`, `~/.git-credentials`, `/etc/passwd`.
  - **Container escape:** Patterns matching `mount -t cgroup`, `nsenter`, `unshare`, Docker socket writes, `/proc/self/exe` access.
  - **Privilege escalation:** Patterns matching `sudo -i` with stdin redirect, `chmod u+s /bin/*`, `setcap cap_sys_admin`, `setcap cap_net_admin`.
- **Pattern format:** Regex strings stored in YAML, compiled at detector init with `re.MULTILINE | re.IGNORECASE` flags. Anchors and word boundaries prevent false positives (e.g., `rm -rf node_modules` passes; only `rm -rf /` or `~` blocks).
- **Side effects:** Block written to forensic log with the full command and matched pattern ID. Session risk escalated.
- **References:** Task 012, pattern file at `src/armor/detectors/cmd_injection_patterns.yaml`, corpus at `tests/eval/corpus/tool_abuse.yaml`

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

- **Trigger:** Output check sees a high-entropy substring via detector `entropy.decode_rescan`, OR input check sees an explicit encoding-request keyword via detector `regex.encoding_request` (`base64`, `hex`, `rot13`, `encrypt`, etc.).
- **Response:** On output (detector `entropy.decode_rescan`): scan for substrings with Shannon entropy ≥ `entropy.threshold` (default 4.5 bits/char) and length ≥ `entropy.min_length` (default 40 chars); attempt single-pass decode (base64, then hex); re-scan the decoded plaintext for canaries using the existing canary scanner automaton — block on hit with `signal_id = entropy.decode_rescan:<canary_id>`. On input: detector `regex.encoding_request` returns `advisory` for standard requests (feeds session risk score) or `block` for high-confidence attack patterns (e.g., "encode … as base64 and put in URL"), and validator LLM is run if advisories are present.
- **Side effects:** On block: forensic record written with `encoding_flag=true`. Decoded plaintext never leaked in forensic records or verdict details — always reference `canary_id` only.
- **Failure modes:** Decode + re-scan would exceed `pipeline.per_detector_budget_ms` → detector returns `error` (fail-open per detector). Recursion not supported (v0.2 limitation; deferred to v0.3 pending corpus evidence).

### B-007: Capture forensic record on every block

- **Trigger:** Any check returns `block`.
- **Response:** Daemon writes a structured incident record containing: timestamp, attack category, input hash (sha256), output hash (sha256), triggered canary ID (if applicable), detected destinations, encoding flag, session ID, risk score, action taken.
- **Side effects:** Record persisted to the forensic log table in SQLite. The raw input/output texts are stored separately in a quarantine table with a TTL (see data-model.md).

### B-008: Daemon serves multiple concurrent hooks via Unix socket

- **Trigger:** Daemon starts with `armor daemon --socket /var/run/armor.sock`.
- **Response:** Listens for newline-delimited JSON requests; each request is `{op, payload, session_id}`; response is `{verdict, signal_id?, message?}`.
- **Side effects:** All requests are journaled to the session table. The socket is removed and recreated on each start.
- **Failure modes:** Socket path not writable → daemon refuses to start. Concurrent request limit (default 64) reached → new requests get `try_later` verdict.

### B-010: Validate tool-call parameters against per-tool schema and risk rules

- **Trigger:** Hook calls `armor check tool` with the tool name and parameters (e.g., a tool-call with `tool="Read", params={"file_path": "/etc/shadow"}`).
- **Response:** Detector `tool_param.schema` (id `tool_param.schema`, category `tool_abuse`, cost tier `static`) performs two-stage validation:
  1. **Shape validation**: Checks that params have the correct keys, types, and required/optional status per the per-tool schema in `src/armor/detectors/tool_schemas.json`.
  2. **Risk rule validation**: Applies per-tool risk rules (content-based checks) such as blocking reads of `/etc/shadow`, `/proc/self/environ`, `~/.aws/credentials`, `~/.ssh/id_*`; writes to `/etc/*`, `/usr/local/bin/*`, `~/.ssh/authorized_keys`, `~/.bashrc`; and edits with `replace_all=true` on paths under `~/.ssh/` or `/etc/`.
- **Schemas and risk rules**: Hand-curated JSON file bundled in the repo; loaded once at detector init and frozen for the daemon's lifetime. See `src/armor/detectors/tool_schemas.json` and ADR-016.
- **Supported tools**: Bash, Read, Write, Edit, Glob, Grep, NotebookEdit. Unknown tools return `pass` with `details["unknown_tool"]=true` (observable for operator audits). Read-only tools (Glob, Grep) have no risk rules (allowed by spec as safe operations).
- **Signal ID format**: `tool_param.schema:<tool>:<rule_id>`, where rule_id is "shape" for shape violations or the risk rule ID (e.g., "dangerous-file").
- **Side effects:** Block written to forensic log with the detected violation and tool name. Session risk escalated.
- **Failure modes:** If schema file is missing or malformed at boot, detector logs an error and returns `error` verdicts for all checks. All subsequent shape checks pass (fail-open per detector). If a tool has no schema, unknown tool pass is returned.
- **References:** Task 013, ADR-016, schema file at `src/armor/detectors/tool_schemas.json`, corpus at `tests/eval/corpus/tool_abuse.yaml`

### B-009: Extract and whitelist-check exfiltration destinations

- **Trigger:** Output check runs detector `extractor.destinations` (always enabled by default).
- **Response:** Extracts URLs (http/https/ftp), IPv4 addresses, IPv6 addresses, and email addresses from the output text. Normalizes to hostnames only (no paths, queries, fragments, or email local-parts). Deduplicates. Compares each destination against the configured whitelist (`destination_whitelist` key in `armor.toml`, default empty list `[]`). Returns `pass` if no destinations found or all destinations are whitelisted; returns `advisory` if any destination is not whitelisted. Regardless of verdict, `Verdict.details["destinations"]` is always populated with the full extracted list (for forensic audit trail).
- **Side effects:** Forensic record written on `advisory` verdict includes the extracted destinations. Session risk score incremented based on advisory severity. Whitelist is read once at daemon boot and frozen for the daemon's lifetime (no re-read per check).
- **Failure modes:** Whitelist configured but corrupted (not a list) → whitelist falls back to empty (all destinations advisory). Regex-based extraction cannot fail (timeout or excessive memory); malformed URLs/IPs are simply not matched (extraction is best-effort, no errors).
- **References:** ADR-015, data-model.md Incident.destinations, configuration.md destination_whitelist key

---

## Edge cases and error behaviors

### B-101: Daemon boot fails if canary values are misconfigured

- **Trigger:** Daemon starts with `armor daemon` or `armor daemon --canary-values <path>`.
- **Response:** Daemon loads the bundled canary schema and attempts to merge with values from `daemon.canary_values_path` (TOML) or `ARMOR_CANARY_VALUES_PATH` (env var, overrides TOML). On any of the following: values file missing, values file malformed JSON, any active canary's value does not match its `marker_rule` regex — daemon logs the error and exits with code 78 (config error).
- **Side effects:** No socket created. Error is logged clearly to stderr indicating the specific failure (missing file, validation mismatch, etc.).

### B-102: Validator LLM weights missing at startup

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
