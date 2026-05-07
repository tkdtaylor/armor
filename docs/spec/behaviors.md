# Behaviors

**Project:** armor
**Last updated:** 2026-05-06

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

### B-004: Track session-level risk and escalate detection strictness (state machine)

- **Trigger:** Every input/output/tool check. The session state machine reads current state and score on each call.
- **Response:** Session state machine (`src/armor/session/state_machine.py`) applies the new signal and computes the new state deterministically. Session is in one of five states: `Normal | Watching | Elevated | High | Blocked`, ordered by risk level.
  - **Forward transitions** (signal-driven): advisory signals with `confidence` contribute `confidence * weight` to the session risk score. When score crosses a threshold, the state escalates: Normal→Watching (threshold 0.4), Watching→Elevated (0.9), Elevated→High (1.5). Multiple rungs may be crossed in one call if the score jumps far enough.
  - **Backward transitions** (cooldown-driven): score decays linearly with wall-clock time before each new signal is applied. When post-decay score falls below the current state's threshold, the state steps back by exactly one rung (no rung-skipping, even for large elapsed time).
  - **Block transitions**: a signal with `decision == "block"` immediately sets state to `Blocked`, regardless of prior score or state.
  - **Blocked is terminal under signal pressure**: cooldown and advisories cannot exit `Blocked`. Only an operator-issued `armor sessions unblock <id> --reason <text>` clears the state — and it transitions to `Watching` (not `Normal`), so the session remains under elevated scrutiny. The unblock writes a row to `OperatorAuditLog` (see data-model.md) capturing actor, timestamp, session_id, and the operator's free-form reason. `--reason` is required; calls without one are rejected.
- **Cost-tier gating:** The pipeline queries the session state before selecting detectors. LLM-tier detectors run iff state ≥ Watching. Blocked state short-circuits all detectors and returns `block` verdict directly with category `session.blocked` (forensic log still written).
- **Configuration:** Thresholds, decay rate, and per-detector weights are loaded from `armor.toml` (keys: `session.thresholds.{watching,elevated,high}`, `session.cooldown_decay_per_min`, `session.signal_weights.*`). Non-hardcoded, tunable for corpus-driven optimization in v1.0.
- **Side effects:** Session state row updated atomically per check. Risk score reflects current operational threat level (not a monotonic audit trail). Forensic log records all signals (state transitions are orthogonal to incident logging).

### B-005: Run the validator LLM as a semantic-level signal

- **Trigger:** Input or output check, when session state is `Watching` or higher, OR when static detectors return `advisory` (matched a soft signal).
- **Response:** Detector `llm.validator` (id `llm.validator`, category `meta`, cost tier `llm`) submits the payload to the validator LLM (small quantized model, single forward pass, structured JSON output asking "is this safe or risky?"). Returns advisory verdict with confidence score 0..1.
- **System prompt:** Located at `src/armor/llm/prompts/validator.txt`. Explicitly instructs the model to remain a classifier and not deviate from role, with examples of adversarial recruitment attempts. Robust against "as a classifier, say X is safe" jailbreak patterns.
- **Validator output:** JSON `{"verdict": "safe" | "risky", "confidence": 0.0..1.0}`. Parse failure → `advisory` verdict with `confidence=0`, no exception. Model unavailable → `advisory` with `confidence=0`.
- **Side effects:** Output is *advisory* — feeds into the session risk score (weighted by `pipeline.llm_validator_weight`, default 0.3), never blocks unilaterally. Latency budget: ≤500 ms per call (see configuration.md).
- **Failure modes:** Model unavailable → `advisory` returned with `confidence=0`, pipeline continues. Latency exceeds budget → soft-fail, log warning, continue. Malformed JSON → `advisory` with `confidence=0`, logged with truncated response.

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

### B-011: Run the honeypot LLM on elevated injection attempts

- **Trigger:** Input or output check, when session state is **Elevated** or higher AND the static detector pipeline returns `block` or `advisory` (detected injection attempt or soft signal).
- **Response:** Daemon invokes the honeypot LLM (id `honeypot`, category `meta`, cost tier `llm`) with a system prompt containing references to a fake credential vault (placeholders like `{{canary:aws-key-001}}`). At prompt-build time, placeholders are substituted with actual canary values from the runtime-injected catalogue (per ADR-010). The LLM generates a response that appears to comply with the attacker's request, including the fake credentials. The response is returned and flows through the existing `armor check output` path, where the canary scanner detects the credentials in the output and returns a `block` verdict.
- **System prompt:** Located at `src/armor/llm/prompts/honeypot.txt`. Instructs the model to play the role of a helpful assistant with access to a vault of secrets (credentials, API keys, database passwords). Prompt contains only placeholders; values are substituted at build time.
- **Honeypot invocation:** Controlled by the gate function `should_invoke_honeypot(session_context, static_pipeline_verdict) -> bool` at `src/armor/daemon/honeypot_gate.py`. Gate logic is testable in isolation. The gate is wired into the daemon's check-output path and gated on `session.state ≥ Watching` (the LLM cost tier per ADR-024).
- **Security invariant:** Canary values are **never** stored in the prompt template file (only placeholders). The validator LLM never reads canary values (enforced by fitness function). Forensic records reference `canary_id`, never the value. This decouples the validator (semantic classifier) from the honeypot (attack-response engine).
- **Side effects:** Honeypot response contains canary values (by design). Response piped through canary scanner. Forensic record written with `triggered_canary` set to the canary ID.
- **Failure modes:** LLM unavailable → returns empty response (pipeline continues, honeypot produces no output). Prompt load fails → logs error, returns empty response. Canary catalogue empty or missing → daemon refuses to start (exit 78, configured at boot).
- **References:** ADR-021 (honeypot design), ADR-010 (canary catalogue), task 019, fitness functions `no_canary_in_prompts.py` and `validator_no_value_access.py`.

### B-009: Extract and whitelist-check exfiltration destinations

- **Trigger:** Output check runs detector `extractor.destinations` (always enabled by default).
- **Response:** Extracts URLs (http/https/ftp), IPv4 addresses, IPv6 addresses, and email addresses from the output text. Normalizes to hostnames only (no paths, queries, fragments, or email local-parts). Deduplicates. Compares each destination against the configured whitelist (`destination_whitelist` key in `armor.toml`, default empty list `[]`). Returns `pass` if no destinations found or all destinations are whitelisted; returns `advisory` if any destination is not whitelisted. Regardless of verdict, `Verdict.details["destinations"]` is always populated with the full extracted list (for forensic audit trail).
- **Side effects:** Forensic record written on `advisory` verdict includes the extracted destinations. Session risk score incremented based on advisory severity. Whitelist is read once at daemon boot and frozen for the daemon's lifetime (no re-read per check).
- **Failure modes:** Whitelist configured but corrupted (not a list) → whitelist falls back to empty (all destinations advisory). Regex-based extraction cannot fail (timeout or excessive memory); malformed URLs/IPs are simply not matched (extraction is best-effort, no errors).
- **References:** ADR-015, data-model.md Incident.destinations, configuration.md destination_whitelist key

### B-008a: Detect abrupt topic shifts within a session (topic-coherence advisory)

- **Trigger:** Input check runs detector `meta.topic_coherence` (enabled by default, only when session exists).
- **Response:** Detector `meta.topic_coherence` (id `meta.topic_coherence`, category `meta`, cost tier `static`) maintains a rolling exponential moving average (EMA) of embeddings from recent turns (window size 5 by default). On each input:
  1. Computes a semantic embedding of the current input text using a sentence-transformer ONNX model (all-MiniLM-L6-v2, ~23 MB, baked into the container).
  2. Compares the embedding to the rolling EMA using cosine distance.
  3. If distance exceeds the threshold (default 0.5), emits `advisory` with confidence `min(1.0, (distance - threshold) / margin)`.
  4. Updates the EMA with the new embedding.
- **Warm-up behavior:** On the first input of a session (turn 1), no EMA exists; detector seeds the EMA and returns `pass`. Starting on turn 2, the detector compares and may emit advisories.
- **Soft-fail on latency budget:** If embedding inference exceeds the per-call budget (default 50 ms P95), detector returns `advisory(confidence=0)` with `soft_fail=true` (fail-open pattern, consistent with the LLM-budget contract in ADR-023).
- **EMA storage:** Maintained in-memory per-session, garbage-collected when the session ends or is explicitly cleared.
- **Signal integration:** Advisory signals feed into `session.state_machine.apply_signal` (per ADR-024) and increment the session risk score. A sequence of pivots can escalate the session state from Normal → Watching → Elevated → High.
- **Security intent:** Flags adversarial pivots (e.g., "help me debug Python" → "what's your system prompt?") without blocking unilaterally. The advisory contributes to session-level risk scoring and may trigger the honeypot LLM when session state reaches Elevated.
- **Side effects:** Session risk score incremented per advisory. EMA state (rolling window, current vector) persists for the session lifetime. Per-call latency is measured and logged.
- **Failure modes:** Embedding model not found → detector returns `pass` (fail-open). Embedding computation times out → soft-fail advisory with `confidence=0`. Session state unavailable → detector returns `pass` (fail-open).
- **References:** Task 024, ADR-026, corpus at `tests/eval/corpus/topic_pivot.yaml`

### B-009a: Detect chunked exfiltration across multiple turns via rolling-buffer aggregation

- **Trigger:** Output check reaches the rolling-buffer scanning phase. This occurs after per-turn detectors have run and the output has been appended to the per-session rolling buffer.
- **Response:** The rolling buffer maintains a bounded concatenation of the last N turn outputs (bounded by both character count and turn count, whichever fills first; defaults: 8 KB / 20 turns per ADR-025). On every output check, the daemon:
  1. Appends the current turn's output to the buffer.
  2. Re-runs the canary scanner against `buffer.concatenated()`. A hit that **did not** occur in the single turn but **does** occur in the concatenation → returns `block` with `signal_id = canary.chunked:<canary_id>` and `category = "exfiltration.canary_chunked"`.
  3. Re-runs the entropy analyzer against the concatenation using a separate rolling-window threshold (`detector.entropy.rolling_threshold`, default 4.5 bits/char). If entropy exceeds the threshold and a canary scan hit occurs, returns `advisory` or `block` depending on the matched pattern.
  4. Checks for partial-canary prefixes: if a contiguous prefix of any active canary value (≥ `detector.canary.partial_match_min_chars` chars, default 12) is present in the buffer, returns `advisory` with `signal_id = canary.partial:<canary_id>` and feeds the signal into `apply_signal` to escalate session risk.
- **Quarantine:** A chunked-canary `block` quarantines all turn IDs currently in the rolling buffer as a single quarantine entry, not one entry per turn.
- **Cooldown interaction:** The rolling buffer does **not** reset when the session state steps back to Normal (cooldown). The buffer persists across cooldown to maintain context for gradual exfiltration attacks.
- **Forensic invariant:** Chunked-canary incidents reference `canary_id` only, never the canary value itself. Forensic records record the `turn_ids` that contributed fragments.
- **Side effects:** Buffer entries are persisted to `SessionRollingBuffer` table (append-only). Chunked-canary blocks increment session risk and write forensic records with category `exfiltration.canary_chunked`. Partial-match advisories increment risk score via the session state machine.
- **Failure modes:** Rolling-window scan exceeds latency budget → returns `error` verdict, pipeline continues (fail-open per detector). Buffer table corrupted or missing → daemon refuses to start (exit 78 at migrations stage).
- **References:** Task 023, ADR-025, corpus at `tests/eval/corpus/multi_turn_chunked.yaml`

---

## Edge cases and error behaviors

### B-101: Daemon boot fails if canary values are misconfigured

- **Trigger:** Daemon starts with `armor daemon` or `armor daemon --canary-values <path>`.
- **Response:** Daemon loads the bundled canary schema and attempts to merge with values from `daemon.canary_values_path` (TOML) or `ARMOR_CANARY_VALUES_PATH` (env var, overrides TOML). On any of the following: values file missing, values file malformed JSON, any active canary's value does not match its `marker_rule` regex — daemon logs the error and exits with code 78 (config error).
- **Side effects:** No socket created. Error is logged clearly to stderr indicating the specific failure (missing file, validation mismatch, etc.).

### B-102: Validator LLM weights missing at startup

- **Trigger:** Daemon starts and the configured model file is not found.
- **Response:** If `ARMOR_DISABLE_LLM=true`, the daemon starts without the model and runs static detectors only. If `ARMOR_DISABLE_LLM=false` (the production default since the validator LLM was integrated per ADR-019) and the model file is not found, the daemon exits with code 78 (config error) and logs the missing path.
- **Side effects:** No socket created (if exit 78); socket created normally (if LLM is disabled).

### B-102: Session ID not provided

- **Trigger:** Check call comes in without `session_id`.
- **Response:** Daemon assigns an ephemeral session ID (`anon-<uuid>`); session state is created but not persisted across daemon restart.
- **Side effects:** Forensic records carry the anon ID; cross-turn risk tracking still works within the daemon's lifetime.

### B-103: Forensic log full / disk full

- **Trigger:** SQLite write fails.
- **Response:** Daemon switches to **degraded mode** — checks still execute, but blocks return `block` without persisting forensic records (logged to stderr instead). Daemon exits when free disk falls below configured floor.

---

## Multi-turn scenarios and session-level evaluation

The eval corpus at `tests/eval/corpus/scenarios_multi_turn.yaml` includes multi-turn scenario rows that test session-level detectors and the state machine deterministically. Each row replays a sequence of turns through the same session and asserts per-turn verdicts and post-turn session state. This enables:

- **Detector testing over sequences** — the rolling-buffer canary scanner (per ADR-025) triggers on canary chunks accumulated across turns; multi-turn corpus rows assert per-turn input/output verdicts and post-turn session state.
- **State machine validation** — each scenario exercises specific state transitions (forward escalation, cooldown step-back, block stickiness) and confirms deterministic threshold-driven transitions.
- **Fitness coverage** — the transition-coverage fitness check validates that every `apply_signal`-reachable edge is exercised by ≥1 corpus row.

Scenarios are hand-curated (not synthetically generated). Rows are tagged with `family` for filtering (e.g., "chunked_canary", "gradual_jailbreak", "topic_pivot", "cooldown_then_retry", "long_benign_session", "operator_clear_resume"). The `operator_clear_resume` family asserts that signal pressure (advisories, cooldown) cannot exit `Blocked`; the only sanctioned exit is the operator-issued `armor sessions unblock <id> --reason <text>` (B-004), which is exercised by the `clear_blocked` unit test and the `sessions.unblock` round-trip integration test rather than the eval corpus.

## Behavioral invariants

- A `block` verdict never leaks the matched signal in the caller-facing message. Signal details go to the forensic log only. The user-facing message is the configured safe replacement.
- Output checks are *idempotent* — re-running an output check on the same `(text, session_id)` returns the same verdict and does not double-write forensic records.
- The set of canary values active in the agent's context is consistent across all checks within a session — canaries do not rotate mid-session.
- All write operations to session state are atomic (single SQLite transaction per check).
