# Behaviors

**Project:** armor
**Last updated:** 2026-05-23

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
  - `regex.authority_impersonation` — blocks patterns like "as your administrator", "I am your developer", "by order of compliance"; advisory on softer patterns like "this is for a security audit", "authorized by legal".
  - `regex.encoding_request` — flags exfiltration-prep encoding requests; verdict semantics described under B-006.
  - `regex.ssrf_probe` — blocks SSRF probe attempts targeting cloud IMDS endpoints (AWS `169.254.169.254`, GCP `metadata.google.internal`, Alibaba `100.100.100.200`) and `file://` URI schemes.
  - `regex.sensitive_file_probe` — blocks read-intent probes targeting sensitive files (`.env`, `id_rsa`, `id_ed25519`, `/etc/shadow`, `.netrc`, `secrets.yaml`), environment-variable enumeration requests, and write-intent to privileged system files (`/etc/crontab`, `/etc/sudoers`, `/etc/hosts`).
  - `regex.code_injection` — blocks Python code injection patterns targeting agent code execution tools; catches `__import__('subprocess')` dynamic import bypass and subprocess/`os.system` calls paired with network exfiltration tools; scans both input text and `code`/`input` tool parameters.
  - `regex.exfil_chain` — blocks instruction-then-exfiltrate chains (e.g., "search X, then send to http://evil.io/collect") and URLs with suspicious exfiltration path suffixes (`/collect`, `/exfil`, `/steal`, `/harvest`).
- **Side effects:** Increments session turn counter, records signal in session state, writes a forensic record on `block`.
- **Failure modes:** Detector raises → that detector's verdict is recorded as `error`, pipeline continues (fail-open per detector). Whole pipeline raises → daemon returns `block` (fail-closed at pipeline level) and logs an internal error.

### B-002: Check model output for canary exfiltration

- **Trigger:** Hook (or library) calls `armor check output <text> --session-id <id>`.
- **Response:** Aho-Corasick scan of output against the **active canary subset** (detector `canary.scanner`, category `exfiltration`). Per ADR-038, the active subset is computed per-check by evaluating each canary's activation rule against the session context. Catalogue covers 24 services across 12 kinds: AWS/GitHub/Stripe/OpenAI/Anthropic/Cohere/HuggingFace/GitLab/Slack/Discord/Twilio/SendGrid/Google/Firebase/GCP/Azure credentials, JWT, SSH keys, TLS certificates, Kubernetes configs, database connection strings, webhook URLs, cryptocurrency wallets (Bitcoin WIF, Ethereum, Solana, BIP39 seeds, MetaMask vaults), and PII identity records (fake name, email, date of birth, SIN — seeded via `armor canary pii-context`). On hit: returns `block`, captures the full attack chain (input + attempted output + intended destination if any URL/IP/email is present in output). On clean: continues to URL/IP extraction and entropy analysis.
- **Side effects:** Forensic record written. Session risk score incremented. The blocked output is NOT returned to the caller — caller receives the safe-replacement message defined in `configuration.md`. When a high-risk kind (LLM-provider keys) triggers a block, `Verdict.details["false_positive_risk"]` is set to `"high"` to support operator workflow tuning.
- **Activation rules (per ADR-038):** The active subset varies per-check based on:
  - `always` (default): canary is active in every check.
  - `tool_used`: canary is active iff the named tool was used at least once in the session (counts blocked attempts).
  - `fsm_state_at_least`: canary is active iff the session has reached the named state (sticky: stays active even after cooldown).
  - `time_window`: canary is active iff (day_of_year + hash(canary_id)) mod period_days == 0 (wall-clock anchor, survives daemon restart).
  - `session_turn_min`: canary is active iff session turn count >= min_turns.
- **Performance:** Per-check `active_for` evaluation ≤ 1 ms mean. Aho-Corasick automaton rebuilds only when active subset changes (cached by subset hash).
- **Failure modes:** Canary catalogue not loaded at boot → daemon exits with code 78 (config error). Canary values file (path specified by `daemon.canary_values_path` or `ARMOR_CANARY_VALUES_PATH`) is missing, malformed, or contains values that don't match their `marker_rule` patterns → daemon exits 78 at startup. Canary values never leak into forensic logs or verdicts — see ADR-010 and ADR-038 for invariants and testing requirements.

### B-003: Block tool calls matching the command-injection denylist

- **Trigger:** Hook calls `armor check tool` with the tool name and parameters (e.g. a `Bash` tool's command string).
- **Response:** Detector `cmd_injection.bash` (id `cmd_injection.bash`, category `tool_abuse`, cost tier `static`) pattern-matches the command string against the denylist in `src/armor/detectors/cmd_injection_patterns.yaml`. Blocks on first match. Returns pass for non-Bash tools or empty/missing commands.
- **Pattern families:** The denylist is organized into five families:
  - **Filesystem destruction:** Patterns matching `rm -rf /`, `rm -rf ~`, `rm -rf $HOME`, `dd if=/dev/zero of=/dev/sd*`, `mkfs`, fork bombs (`:(){:|:&};:`), `shred` on system dirs.
  - **Credential reads:** Patterns matching `/etc/shadow`, `/etc/sudoers`, `~/.ssh/id_*` (private keys), `~/.aws/credentials`, `~/.git-credentials`, `/etc/passwd`.
  - **Container escape:** Patterns matching `mount -t cgroup`, `nsenter`, `unshare`, Docker socket writes, `/proc/self/exe` access, `systemctl stop/disable/mask docker`, `mount --bind` host directories.
  - **Privilege escalation:** Patterns matching `sudo -i` with stdin redirect, `chmod u+s /bin/*`, `chmod 777`, `chmod a+rwx`, `setcap cap_sys_admin`, `setcap cap_net_admin`.
  - **Persistence:** Patterns matching `chown root`, `passwd root`, `crontab -e` / crontab write, scheduled task modifications.
- **Pattern format:** Regex strings stored in YAML, compiled at detector init with `re.MULTILINE | re.IGNORECASE` flags. Anchors and word boundaries prevent false positives (e.g., `rm -rf node_modules` passes; only `rm -rf /` or `~` blocks).
- **Side effects:** Block written to forensic log with the full command and matched pattern ID. Session risk escalated.
- **References:** pattern file at `src/armor/detectors/cmd_injection_patterns.yaml`, corpus at `tests/eval/corpus/tool_abuse.yaml`

### B-004: Track session-level risk and escalate detection strictness (state machine)

- **Trigger:** Every input/output/tool check. The session state machine reads current state and score on each call.
- **Response:** Session state machine (`src/armor/session/state_machine.py`) applies the new signal and computes the new state deterministically. Session is in one of five states: `Normal | Watching | Elevated | High | Blocked`, ordered by risk level.
  - **Forward transitions** (signal-driven): advisory signals with `confidence` contribute `confidence * weight` to the session risk score. When score crosses a threshold, the state escalates: Normal→Watching (threshold 0.4), Watching→Elevated (0.9), Elevated→High (1.5). Multiple rungs may be crossed in one call if the score jumps far enough.
  - **Backward transitions** (cooldown-driven): score decays linearly with wall-clock time before each new signal is applied. When post-decay score falls below the current state's threshold, the state steps back by exactly one rung (no rung-skipping, even for large elapsed time).
  - **Block transitions**: a signal with `decision == "block"` immediately sets state to `Blocked`, regardless of prior score or state.
  - **Blocked is terminal under signal pressure**: cooldown and advisories cannot exit `Blocked`. Only an operator-issued `armor sessions unblock <id> --reason <text>` clears the state — and it transitions to `Watching` (not `Normal`), so the session remains under elevated scrutiny. The unblock writes a row to `OperatorAuditLog` (see data-model.md) capturing actor, timestamp, session_id, and the operator's free-form reason. `--reason` is required; calls without one are rejected.
- **Cost-tier gating:** The pipeline queries the session state before selecting detectors. LLM-tier detectors run iff state ≥ Watching. Blocked state short-circuits all detectors and returns `block` verdict directly with category `session.blocked` (forensic log still written).
- **Configuration:** Thresholds, decay rate, and per-detector weights are loaded from `armor.toml` (keys: `session.thresholds.{watching,elevated,high}`, `session.cooldown_decay_per_min`, `session.signal_weights.*`). Non-hardcoded, tunable for corpus-driven optimization.
- **Side effects:** Session state row updated atomically per check. Risk score reflects current operational threat level (not a monotonic audit trail). Forensic log records all signals (state transitions are orthogonal to incident logging).

### B-005: Run the validator LLM as a semantic-level signal

- **Trigger:** Input or output check, when session state is `Watching` or higher (FSM-gated).
- **Response:** Detector `llm.validator` (id `llm.validator`, category `meta`, cost tier `llm`) submits the payload to the validator LLM (small quantized model, single forward pass, structured JSON output asking "is this safe or risky?"). Returns advisory verdict with confidence score 0..1.
- **System prompt:** Located at `src/armor/llm/prompts/validator.txt`. Explicitly instructs the model to remain a classifier and not deviate from role, with examples of adversarial recruitment attempts. Robust against "as a classifier, say X is safe" jailbreak patterns.
- **Validator output:** JSON `{"verdict": "safe" | "risky", "confidence": 0.0..1.0}`. Parse failure → `advisory` verdict with `confidence=0`, no exception. Model unavailable → `advisory` with `confidence=0`.
- **Side effects:** Output is *advisory* — feeds into the session risk score (weighted by `pipeline.llm_validator_weight`, default 0.3), never blocks unilaterally. Latency budget: ≤500 ms per call (see configuration.md).
- **Failure modes:** Model unavailable → `advisory` returned with `confidence=0`, pipeline continues. Latency exceeds budget → soft-fail with `signal_id="llm.validator:soft_fail"`, returns `advisory(confidence=0)`, log warning, continue (per ADR-023; not operator-tunable). Malformed JSON → `advisory` with `confidence=0`, logged with truncated response.

### B-006: Detect and block encoded exfiltration

- **Trigger:** Output check sees a high-entropy substring via detector `entropy.decode_rescan`, OR input check sees an explicit encoding-request keyword via detector `regex.encoding_request` (`base64`, `hex`, `rot13`, `encrypt`, etc.).
- **Response:** On output (detector `entropy.decode_rescan`): scan for substrings with Shannon entropy ≥ `entropy.threshold` (default 4.5 bits/char) and length ≥ `entropy.min_length` (default 40 chars); attempt **bounded-depth recursive decode** (default max depth 3) trying each codec (base64, hex, URL-encode) at each level; re-scan decoded plaintext for canaries using the existing canary scanner automaton — block on hit with `signal_id = entropy.decode_rescan:<chain>:<canary_id>` where `<chain>` is the codec sequence (e.g., `b64.hex`). Recursion terminates on: depth cap reached, no-progress (decoded entropy < input entropy − margin, default 0.5 bits/char), per-detector budget consumed, or successful canary match. On input: detector `regex.encoding_request` returns `advisory` for standard requests (feeds session risk score) or `block` for high-confidence attack patterns (e.g., "encode … as base64 and put in URL"), and validator LLM is run if advisories are present.
- **Side effects:** On block: forensic record written with `encoding_flag=true`, `decode_chain` (codec sequence), and `decode_depth` (chain length). Decoded plaintext never leaked in forensic records or verdict details — always reference `canary_id` only.
- **Failure modes:** Decode + re-scan would exceed `pipeline.per_detector_budget_ms` → detector returns `error` (fail-open per detector).

### B-007: Capture forensic record on every block

- **Trigger:** Any check returns `block`.
- **Response:** Daemon writes a structured incident record containing: timestamp, attack category, input hash (sha256), output hash (sha256), triggered canary ID (if applicable), detected destinations, encoding flag, session ID, risk score, action taken.
- **Side effects:** Record persisted to the forensic log table in SQLite. The raw input/output texts are stored separately in a quarantine table with a TTL (see data-model.md).

### B-008: Daemon serves multiple concurrent hooks via Unix socket

- **Trigger:** Daemon starts with `armor daemon --socket /var/run/armor.sock`.
- **Response:** Listens for newline-delimited JSON requests; each request is `{op, payload, session_id}`; response is `{verdict, signal_id?, message?}`.
- **Side effects:** All requests are journaled to the session table. The socket is removed and recreated on each start.
- **Failure modes:** Socket path not writable → daemon refuses to start. Concurrency cap (`asyncio.Semaphore(max_concurrent)`, default 64) reached → new connections wait their turn; the daemon does not return a back-pressure verdict — callers see the response when their request reaches the head of the queue.

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
- **References:** ADR-016, schema file at `src/armor/detectors/tool_schemas.json`, corpus at `tests/eval/corpus/tool_abuse.yaml`

### B-011: Run the honeypot LLM on elevated injection attempts

- **Trigger:** Output check (`check.output`), when session state is **Watching or higher** AND the static detector pipeline returns `block` or `advisory` (detected injection attempt or soft signal).
- **Response:** Daemon invokes the honeypot LLM (id `honeypot`, category `meta`, cost tier `llm`) with a system prompt containing references to a fake credential vault (placeholders like `{{canary:aws-key-001}}`). Per ADR-038, the prompt is **per-check** and contains only currently-active canaries. At prompt-build time, placeholders are substituted with actual canary values from the runtime-injected catalogue; inactive canaries are omitted (per ADR-010). The LLM generates a response that appears to comply with the attacker's request, including the fake credentials. The response is piped through the canary scanner detector, which detects the credentials in the output and returns a `block` verdict.
- **System prompt:** Located at `src/armor/llm/prompts/honeypot.txt`. Instructs the model to play the role of a helpful assistant with access to a vault of secrets (credentials, API keys, database passwords). Prompt contains only placeholders; values are substituted at build time with the active subset.
- **Honeypot invocation:** Controlled by the gate function `should_invoke_honeypot(session_context, static_pipeline_verdict) -> bool` at `src/armor/daemon/honeypot_gate.py`. Gate logic is testable in isolation. The gate is wired into the daemon's check-output path and gated on `session.state ≥ Watching` (the LLM cost tier per ADR-024).
- **Per-check active subset:** The honeypot prompt references only canaries in the active subset for the current session context (per ADR-038 B-002 activation rules). This varies per-check based on tool usage, FSM state, time window, or turn count.
- **Security invariant:** Canary values are **never** stored in the prompt template file (only placeholders). The validator LLM never reads canary values (enforced by fitness function). Forensic records reference `canary_id`, never the value. This decouples the validator (semantic classifier) from the honeypot (attack-response engine).
- **Side effects:** Honeypot response contains canary values from the active subset (by design). Response piped through canary scanner. Forensic record written with `triggered_canary` set to the canary ID.
- **Failure modes:** LLM unavailable → returns empty response (pipeline continues, honeypot produces no output). Prompt load fails → logs error, returns empty response. Canary catalogue empty or missing → daemon refuses to start (exit 78, configured at boot).
- **References:** ADR-021 (honeypot design), ADR-010 (canary catalogue), ADR-038 (activation rules), task 019, task 073, fitness functions `no_canary_in_prompts.py` and `validator_no_value_access.py`.

### B-012: Detect memory-planting injection attempts

- **Trigger:** Input check runs detector `meta.memory_planting` (enabled by default).
- **Response:** Detector `meta.memory_planting` (id `meta.memory_planting`, category `meta`, cost tier `static`) pattern-matches against eight regex families that flag attempts to plant persistent instructions in the model's memory across turns:
  - "Remember this rule/fact/instruction/directive"
  - "From now on, always/you will/you should/you must"
  - "For the rest of this/the conversation/session"
  - "Whenever I/you/we [action], always/you will/you must"
  - "Permanent instruction/rule/directive"
  - "Default to always/never"
  - "Moving forward, always/never/you should/must/will"
  - "Henceforth, always/never/you should/must/will"
  - All patterns are case-insensitive and return `advisory` with `severity="medium"` and `confidence=0.4`.
  - Patterns are designed with selectivity to avoid false positives on benign uses like "remember to always use 4-space indents" or "from now on this code should compile".
- **Pattern selectivity:** Patterns require specific directive keywords or instruction verbs to avoid triggering on bare temporal phrases. For example, "remember this rule" requires the "rule|fact|instruction|directive" qualifier; bare "remember to" does not match.
- **Side effects:** Advisory signals feed into `session.state_machine.apply_signal` (per ADR-024) and increment the session risk score. A single memory-planting advisory keeps the session at Watching; repeated attempts across turns escalate to Elevated or higher.
- **Session integration:** Each advisory from this detector contributes `confidence * weight` to the session risk score (default weight 0.4 per `session.signal_weights."meta.memory_planting"` in `armor.toml`).
- **Failure modes:** Regex compilation fails → detector returns `error` verdict, pipeline continues (fail-open per detector).
- **References:** ADR-037 (detector 3, memory manipulation category), task 071. Pattern coverage is exercised by unit tests and `tests/eval/corpus/context_window.yaml` (family: "memory_planting").

### B-013: Detect instruction-override patterns buried in long inputs

- **Trigger:** Input check runs detector `meta.instruction_burial` (enabled by default).
- **Response:** Detector `meta.instruction_burial` (id `meta.instruction_burial`, category `meta`, cost tier `static`) detects a positioning anomaly specific to long inputs: instruction-override or system-prompt-extraction patterns appearing **only in the last 25%** (configurable via `detector.instruction_burial.tail_fraction`) of the input, **not** in the first 75% (head region).
  - Only activates on inputs ≥ `detector.instruction_burial.min_length_bytes` (default 4096). Shorter inputs skip the check and return `pass`.
  - Splits input into head (first 75%) and tail (last 25%) regions.
  - Reuses the compiled regex patterns from `regex.instruction_override` and `regex.system_prompt_extraction` (no duplication).
  - For each pattern family (override, extraction): scans head and tail independently.
  - Returns `advisory` with `severity="high"`, `confidence=0.8`, and signal_id `meta.instruction_burial:override-NNN` or `meta.instruction_burial:extraction-NNN` **only if** (match in tail) AND NOT (match in head).
  - If a pattern matches in the head region (regardless of tail), returns `pass` — the base regex detector (`regex.instruction_override` or `regex.system_prompt_extraction`) will block separately; this detector only signals the positional anomaly.
- **Positioning anomaly rationale:** Long-context-window attacks exploit diminishing attention by burying directives late in a prompt. This detector flags the attack pattern itself (instruction override or extraction request) when it exhibits this specific spatial characteristic.
- **Configuration keys:** `detector.instruction_burial.min_length_bytes` (int, default 4096) and `detector.instruction_burial.tail_fraction` (float, default 0.25).
- **Failure modes:** Regex pattern reuse fails (entry point misconfigured) → detector returns `error` verdict, pipeline continues (fail-open per detector). Pattern match raises exception → caught, error verdict returned.
- **References:** ADR-037 (detector 2, instruction burial category), task 070. Pattern coverage is exercised by unit tests and `tests/eval/corpus/context_window.yaml` (family: "instruction_burial").

### B-009: Extract and whitelist-check exfiltration destinations

- **Trigger:** Output check runs detector `extractor.destinations` (always enabled by default).
- **Response:** Extracts URLs (http/https/ftp), IPv4 addresses, IPv6 addresses, and email addresses from the output text. Normalizes to hostnames only (no paths, queries, fragments, or email local-parts). Deduplicates. Compares each destination against the configured whitelist (`destination_whitelist` key in `armor.toml`, default empty list `[]`). Returns `pass` if no destinations found or all destinations are whitelisted; returns `advisory` if any destination is not whitelisted. Regardless of verdict, `Verdict.details["destinations"]` is always populated with the full extracted list (for forensic audit trail).
- **Side effects:** Extracted destinations are surfaced via `Verdict.details["destinations"]` for downstream consumers. Forensic records are written only on `block` (per B-007); advisory verdicts do not produce forensic rows. Session risk score incremented based on advisory severity. Whitelist is read once at daemon boot and frozen for the daemon's lifetime (no re-read per check).
- **Failure modes:** Whitelist configured but corrupted (not a list) → whitelist falls back to empty (all destinations advisory). Regex-based extraction cannot fail (timeout or excessive memory); malformed URLs/IPs are simply not matched (extraction is best-effort, no errors).
- **References:** ADR-015, data-model.md Incident.destinations, configuration.md destination_whitelist key

### B-008a: Detect abrupt topic shifts within a session (topic-coherence advisory)

- **Trigger:** Input check runs detector `meta.topic_coherence` (enabled by default, only when session exists).
- **Response:** Detector `meta.topic_coherence` (id `meta.topic_coherence`, category `meta`, cost tier `semantic`) maintains a rolling exponential moving average (EMA) of embeddings from recent turns (window size 5 by default). On each input:
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
- **References:** ADR-026, corpus at `tests/eval/corpus/scenarios_multi_turn.yaml` (family: "topic_pivot")

### B-008b: Detect anomalous input lengths within a session (token-count advisory)

- **Trigger:** Input check runs detector `meta.token_count_anomaly` (enabled by default, only when session exists).
- **Response:** Detector `meta.token_count_anomaly` (id `meta.token_count_anomaly`, category `meta`, cost tier `static`) maintains a running mean and sample standard deviation of input lengths per session using Welford's online algorithm. On each input:
  1. Computes the input length in bytes (UTF-8 encoded).
  2. If length exceeds absolute cap (default 32768 bytes), emits `advisory` regardless of session history.
  3. Otherwise, if session has fewer than `min_history_turns` (default 3) prior turns, seeds the statistics and returns `pass`.
  4. Once baseline is established (≥3 turns), computes z-score = (length − mean) / std_dev. If z-score > sigma_threshold (default 3.0), emits `advisory` with confidence `min(1.0, z_score / sigma_threshold)`.
  5. Updates the running statistics and returns `pass` or `advisory`.
- **Warm-up behavior:** First `min_history_turns` turns always return `pass`, establishing the per-session baseline of typical input lengths.
- **Confidence formula:** Advisory confidence = `min(1.0, z_score / sigma_threshold)`. Higher z-scores (larger deviations) produce higher confidence. Absolute-cap violations scale confidence by `length_bytes / cap_bytes`.
- **Storage:** Running statistics (count, mean, running variance) maintained in-memory per-session, garbage-collected when the session ends or the daemon restarts (per ADR-037).
- **Signal integration:** Advisory signals feed into `session.state_machine.apply_signal` (per ADR-024) and increment the session risk score. Repeated oversized inputs can escalate the session state from Normal → Watching → Elevated → High.
- **Security intent:** Flags context-overflow and token-budget-exploitation attempts (e.g., submitting 100 KB of padding to exhaust token limits) without blocking unilaterally. The advisory contributes to session-level risk scoring.
- **Side effects:** Session risk score incremented per advisory. Per-session running statistics persist for the session lifetime.
- **Failure modes:** Session unavailable → detector returns `pass` (fail-open). Encoding errors on UTF-8 calculation → exception caught, returns `error` verdict, pipeline continues.
- **References:** ADR-037. Statistic-based detection is exercised by unit tests and `tests/eval/corpus/context_window.yaml` (family: "context_overflow").

### B-009a: Maintain a per-session rolling buffer for multi-turn detection

- **Trigger:** Output check. After per-turn detectors run, the current turn's output is appended to the per-session rolling buffer.
- **Response:** The rolling buffer maintains a bounded concatenation of the last N turn outputs (bounded by both character count and turn count, whichever fills first; defaults: 8 KB / 20 turns per ADR-025). The buffer itself is the substrate for multi-turn detection — the active multi-turn detector that consumes it is `canary.paraphrase` (per B-009b), which scans the concatenation for fragmented canary leaks via n-gram matching.
- **Cooldown interaction:** The rolling buffer does **not** reset when the session state steps back to Normal (cooldown). The buffer persists across cooldown to maintain context for gradual exfiltration attacks.
- **Forensic invariant:** Multi-turn incidents reference `canary_id` only, never the canary value itself. Forensic records record the `turn_ids` that contributed fragments.
- **Side effects:** Buffer entries are persisted to the `SessionRollingBuffer` table (append-only).
- **Failure modes:** Buffer table corrupted or missing → daemon refuses to start (exit 78 at migrations stage). Per-detector latency budget overruns are handled at each consumer detector (currently `canary.paraphrase`), not here.
- **References:** ADR-025, corpus at `tests/eval/corpus/multi_turn_chunked.yaml`. The chunked-canary `block` path described in earlier drafts (signal_id `canary.chunked:<canary_id>`, category `exfiltration.canary_chunked`) and the entropy rolling-buffer scan (`entropy.rolling_threshold` config key) are not currently wired in `src/`; multi-turn coverage is presently provided exclusively by `canary.paraphrase` (B-009b). A dedicated chunked-canary block path remains a candidate for future work.

### B-009b: Detect paraphrased canary leaks via n-gram matching in rolling buffer

- **Trigger:** Output check reaches the rolling-buffer scanning phase (same as B-009a). Detector `canary.paraphrase` runs on the rolling buffer after the chunked-canary scan.
- **Response:** The paraphrase detector builds an Aho-Corasick automaton of all contiguous n-grams of length [`detector.canary_paraphrase.ngram_min`, `detector.canary_paraphrase.ngram_max`] from active canary values (defaults: 6–11 chars, below the 12-char partial-match threshold from B-009a). On every output check, it:
  1. Scans the rolling buffer concatenation for n-gram matches.
  2. Tracks distinct n-grams matched per canary_id.
  3. If count ≥ `detector.canary_paraphrase.k_threshold` (default 3) for any canary, returns `advisory` with `signal_id = canary.paraphrase:<canary_id>:ngram`, `severity = high`, and `confidence = min(1.0, K_observed / K_threshold * 0.5)`.
  4. Otherwise returns `pass`.
- **Use case:** Catches fragmented leaks like *"the secret starts with `wJalrXUt`, then has `EMI/K7MD`, and ends with `DENG/bPxRf`"* where none of the fragments individually reach the 12-char threshold of B-009a.
- **Forensic invariant:** Advisory details reference `canary_id`, `ngram_count`, `k_threshold`, and `confidence` only — never the matched n-gram bytes themselves.
- **Configuration:**
  - `detector.canary_paraphrase.ngram_min` (int, default 6): minimum n-gram length.
  - `detector.canary_paraphrase.ngram_max` (int, default 11): maximum n-gram length.
  - `detector.canary_paraphrase.k_threshold` (int, default 3): distinct n-grams required to fire advisory.
  - `detector.canary_paraphrase.advisory_weight` (float, default 0.5): signal weight consumed by session FSM via `session.signal_weights."canary.paraphrase"`.
- **Relationship to B-009a:** Both detectors share the rolling buffer and operate on the same concatenation. B-009a fires on contiguous 12+ char prefixes (higher confidence, block-eligible). B-009b fires on sub-12-char n-gram fragments (lower confidence, advisory only). They emit distinct `signal_id`s (`canary.partial` vs `canary.paraphrase`) and feed separate signals into the FSM.
- **Failure modes:** Latency budget exceeded (timeout) → returns `error` verdict, pipeline continues. Automaton construction fails → falls back to pass verdict and logs warning.
- **References:** ADR-034, unit tests at `tests/unit/detectors/test_canary_paraphrase.py`, corpus at `tests/eval/corpus/exfiltration.yaml` (family `paraphrase_exfil`)

### B-014: Detect tool-call rate anomalies within a session

- **Trigger:** Tool check runs detector `meta.tool_rate_anomaly` (enabled by default, only when session exists).
- **Response:** Detector `meta.tool_rate_anomaly` (id `meta.tool_rate_anomaly`, category `meta`, cost tier `static`) maintains a sliding window per (session_id, tool_name) of recent tool-call timestamps. On each tool check:
  1. Records the current timestamp in the per-tool window.
  2. Trims entries older than `detector.tool_rate.window_seconds` (default 60 seconds).
  3. Counts the number of calls for the current tool within the window.
  4. If count exceeds the threshold for that tool, emits `advisory` with confidence `min(1.0, observed / threshold - 1.0)`.
  5. Otherwise returns `pass`.
- **Per-tool thresholds:** Defaults configured per tool (WebFetch=10, Read=30, Bash=20, Write=15, Grep=60 calls per 60-second window) with a fallback default of 30 for unlisted tools. All thresholds are tunable via `detector.tool_rate.thresholds.*` in `armor.toml`.
- **Window duration:** Configurable via `detector.tool_rate.window_seconds` (default 60 seconds). Window expiry is computed at check time (no background cleanup).
- **Sliding-window state:** Maintained in-memory per-session, per-tool as a deque of (timestamp, tool_name) tuples. State is evicted when the session ends.
- **Signal integration:** Advisory signals feed into `session.state_machine.apply_signal` (per ADR-024) and increment the session risk score. Bursty tool calls (e.g., rapid-fire WebFetch in an attempt to exfiltrate via parallel requests) accumulate risk and may escalate the session state from Normal → Watching → Elevated → High.
- **Failure modes:** Timer unavailable or now_fn fails → detector falls back to `time.time()` and continues. Window maintenance is O(k) where k is the number of expired entries (bounded by window width and tool call rate).
- **References:** ADR-040, unit tests at `tests/unit/detectors/test_tool_rate_anomaly.py`

### B-015: Detect conversation hijacking attempts

- **Trigger:** Input check runs detector `meta.conversation_hijack` (enabled by default).
- **Response:** Detector `meta.conversation_hijack` (id `meta.conversation_hijack`, category `meta`, cost tier `static`) scans the input for claim patterns asserting prior agreement or discussion:
  1. `"as we/you agreed/discussed/said/established earlier/before/previously/already"`
  2. `"per/following our/the previous/prior/earlier conversation/discussion/exchange"`
  3. `"recall that I/you am/told you/asked/established"`
  4. `"based on/in light of our/the earlier agreement/discussion/conversation"`
- **Confidence calibration:** On pattern match:
  - If turn count (inferred from `SessionContext.signal_history` length) is 0 or 1 → emit `advisory` with `confidence = detector.conversation_hijack.unsupported_confidence` (default 0.7, high confidence).
  - If turn count ≥ 2 (prior discussion exists) → emit `advisory` with `confidence = detector.conversation_hijack.supported_confidence` (default 0.3, low confidence, since claim might be legitimate).
- **Signal details:** Advisory includes matched family, offset, pattern match length, and `prior_discussion_detected` boolean.
- **Failure modes:** `SessionContext.signal_history` not accessible → detector assumes no prior discussion and applies high confidence. Pattern match exception → returns `error` verdict, pipeline continues.
- **Configuration:** `detector.conversation_hijack.unsupported_confidence` (float, default 0.7) and `detector.conversation_hijack.supported_confidence` (float, default 0.3).
- **References:** ADR-037, unit tests at `tests/unit/detectors/test_conversation_hijack.py`, and `tests/eval/corpus/context_window.yaml` (family: "conversation_hijack")

### B-016: Detect tool-call attack chains (cross-service exfiltration)

- **Trigger:** Tool check runs detector `meta.tool_chain` (enabled by default, only when session exists).
- **Response:** Detector `meta.tool_chain` (id `meta.tool_chain`, category `meta`, cost tier `static`) maintains a per-session history of recent tool calls (last `detector.tool_chain.history_depth` calls, default 20). On each tool check:
  1. Checks if the current call extends any partial chain match in the session's chain state.
  2. For each chain template in the catalogue (`src/armor/detectors/tool_chains.yaml` plus any user-provided chains), evaluates whether the current call matches the next expected step.
  3. Strictness validation: "strict" chains require all prior steps to match consecutively (no unrelated calls in between). "Loose" chains allow unrelated calls within `detector.tool_chain.window_turns` (default 5 turns) between consecutive steps.
  4. If a complete chain matches, returns the chain's verdict (`block` or `advisory`) with `signal_id = meta.tool_chain:<chain_id>` and `details["chain_steps"]` populated with matched call sequence.
  5. Otherwise returns `pass`.
- **Bundled chain catalogue:** Five seed chains targeting cross-service exfiltration and credential theft:
  - `read-env-then-fetch`: Read `.env` → WebFetch external host. Verdict: block.
  - `read-aws-then-any`: Read `~/.aws/credentials` → any tool with credential content in params. Verdict: block.
  - `read-ssh-then-out`: Read `~/.ssh/id_*` → Bash output containing PEM header. Verdict: block.
  - `passwd-sweep`: Read `/etc/passwd` → `/etc/shadow` → `/etc/sudoers`. Verdict: advisory.
  - `git-cred-sweep`: Bash `git config user.email` → `git config user.password`. Verdict: advisory.
- **Blocked calls excluded:** Tool calls blocked by other detectors do NOT advance chain matches (per ADR-040 Q5). The detector records all calls unconditionally for forensic completeness, but only "pass" verdicts participate in chain-state advancement. When a prior tool call was blocked, the chain state doesn't advance even if the current call matches the next step.
- **Operator-extensible:** Config key `detector.tool_chain.user_chains_path` (path; default unset). When set, the detector loads additional chains from that file. Format identical to `tool_chains.yaml`. User chains augment (do not replace) the bundled catalogue.
- **Signal integration:** Both `block` and `advisory` verdicts are recorded in `Verdict`. Block verdicts immediately short-circuit the pipeline and are persisted to the forensic log. Advisory verdicts feed into `session.state_machine.apply_signal` (per ADR-024) and increment the session risk score. Repeated chain detections (different chains or same chain in different sessions) accumulate risk across turns.
- **State reset:** Once a chain completes and fires, that chain's state is reset (partial-match index set to 0). Subsequent calls that would match the same chain from the start are tracked independently.
- **Per-session state:** Tool-call history and chain state are maintained in-memory per `session_id`. State is evicted when the session ends or the daemon restarts.
- **Forensic invariant:** `details["chain_steps"]` is populated with step information (tool name, matched parameter keys), not parameter values. Full command strings and URLs are not included in forensic details (only in the raw-payload quarantine for high-risk incidents).
- **Failure modes:** Chain catalogue file missing or malformed at startup → detector logs error but returns `pass` for all checks (fail-open per detector). User chain file missing or malformed → logged as warning, bundled chains remain active, detector continues. Regex pattern compilation error → detector returns `error` verdict, pipeline continues.
- **Configuration keys:**
  - `detector.tool_chain.history_depth` (int, default 20): max recent tool calls to retain per session.
  - `detector.tool_chain.window_turns` (int, default 5): max turns between consecutive steps in loose mode.
  - `detector.tool_chain.user_chains_path` (path, default unset): optional user-provided chains file.
- **References:** ADR-040, unit tests at `tests/unit/detectors/test_tool_chain.py`, bundled chains at `src/armor/detectors/tool_chains.yaml`

### B-017: Detect indirect injection in tool-call results

- **Trigger:** PostToolUse hook (Claude Code integration) calls `armor check fetched <result_text> --source-tool <tool_name> --session-id <id>` for a tool result, OR library client calls the IPC op `check.fetched`.
- **Response:** Daemon runs the input-side detector pipeline against the tool-call result. Returns `pass`, `block` (with `signal_id`), or `advisory`. The `Payload.source` field is set to `Source.TOOL_RESULT_UNTRUSTED` by default. If the `source_tool` matches an entry in the operator-configured `[pipeline.fetched] trusted_source_tools` allowlist (per task 080, ADR-041), the payload is classified as `TOOL_RESULT_TRUSTED` and the indirect-injection regex detector subset is skipped (instruction_override, roleplay_hijack, system_prompt_extraction, authority_impersonation, encoding_request). Other detectors (canary scanner, entropy, encoding) still run — trust applies to origin, not content. The per-source multiplier (default 1.5× for untrusted results, 0.5× for trusted results) scales detector confidence before verdicts materialize.
- **Detectors:** Same as B-001 (instruction-override, roleplay-hijack, system-prompt-extraction, authority-impersonation, etc.) applied to the fetched content.
- **4 KB chunking (ADR-033):** Payloads ≤ 4096 bytes run the pipeline once (no chunking). Payloads > 4096 bytes are split into tiled (non-overlapping) 4 KB windows. The pipeline runs on each chunk in order until the first non-pass verdict, which wins and is returned. Hard cap: 16 chunks (~64 KB max processed per request); chunks beyond this cap are recorded as unprocessed. Detailed chunking metadata is persisted to the forensic incident for operator analysis.
- **Chunking metadata:** When chunking activates (payload > 4 KB), the winning verdict's `details["additional_chunks"]` is populated with a list of chunk indices that were either: (1) skipped due to early termination after the first hit, or (2) checked but returned pass. If the hard cap of 16 chunks is reached, `details["chunks_skipped"]` contains the indices of chunks that were not processed. This metadata is persisted to the `Incident.chunk_metadata` JSON column.
- **Side effects:** Increments session turn counter, records signal in session state, writes a forensic record on `block` with `attack_category="indirect_injection.<vector>"` where `<vector>` ∈ {`instruction_override`, `system_prompt_extraction`, `roleplay_hijack`, `encoding_request`, `authority_impersonation`, `memory_planting`} (derived from the regex detector family). Forensic record includes: `source_tool` (tool name), `chunk_index` (0-based index of the winning chunk; NULL if no chunking), and `chunk_metadata` (JSON dict with `additional_chunks` and optionally `chunks_skipped`). Canary leaks via check.fetched remain categorized as `exfiltration.canary_leak` regardless of source.
- **Hook integration:** PostToolUse hook (registered in `.claude/settings.json` for read-side tools: `Read`, `WebFetch`, `Grep`, `Glob`, MCP `read_*` patterns) first checks `pipeline.exempt.read_paths` (for Read/Grep file paths) and `pipeline.exempt.webfetch_domains` (for WebFetch URLs) against the incoming payload's path/domain. On exemption match, the hook skips the daemon call entirely (no incident logged). On non-exemption, the hook calls `armor check fetched`, and on `block` verdict, the hook replaces the tool result with a sanitized stub: `[armor: tool result blocked — incident <incident_id>]`. On `pass` or `advisory`, the original tool result is returned unmodified.
- **Exemption mechanism:** Bundled defaults in `armor.toml` under `[pipeline.exempt]` cover research materials (`tests/eval/corpus/**`, `archive/**`, `docs/architecture/decisions/**`, `docs/spec/**`, `discussion.md`, `**/regex_*.py`) and trusted security-research domains (`owasp.org`, `huggingface.co/papers/**`, `arxiv.org/**`, `github.com/anthropic-ai/**`). A fresh install does the right thing for security-research workflows out of the box.
- **Configuration:** The chunk size is configurable via `[pipeline.fetched]` section in `armor.toml` with key `chunk_size_bytes` (default 4096). The hard cap of 16 chunks is fixed (unadjustable).
- **Failure modes:** Detector raises → that detector's verdict is recorded as `error`, pipeline continues (fail-open per detector). Whole pipeline raises → daemon returns `block` (fail-closed at pipeline level) and logs an internal error.
- **References:** ADR-033, ADR-041

### B-018: Detect harmful commands in model output (opt-in)

- **Trigger:** Output check runs detector `output.harmful_content` when `detector.output_harmful_content.enabled = true` in `armor.toml` (disabled by default). Only fires on payloads with `source == MODEL_OUTPUT`.
- **Response:** Two-stage detection:
  1. **Stage 1 — regex fast path:** Scans the output for runnable attack commands in four families:
     - **Cloud credential exfil:** `aws s3 cp … credentials`, `gsutil cp … credentials`, `az storage blob upload`.
     - **Credential file access:** `cat ~/.aws/credentials`, `cat /etc/shadow`, `cat ~/.netrc`, `cat ~/.ssh/id_rsa`, `find / -name *.aws`, `find / -name credentials`.
     - **IMDS / metadata endpoints:** `169.254.169.254`, `metadata.google.internal`, `100.100.100.200`.
     - **Privilege escalation chains:** `aws ssm get-parameter --with-decryption`, `aws iam pass-role`, `aws iam attach-role-policy`.
     If no pattern fires, returns `pass` immediately.
  2. **Stage 2 — LLM confirmation:** If a pattern fires and the LLM session is available, the output is sent to the validator LLM with a dedicated prompt (`src/armor/llm/prompts/output_harmful_content.txt`). Returns `block` with `signal_id = output.harmful_content:confirmed` if the LLM returns `risky` with `confidence ≥ block_threshold` (default 0.6). Returns `advisory` with `signal_id = output.harmful_content:pattern_match` if the LLM returns `risky` below threshold, or if the LLM is unavailable.
- **Configuration:** Controlled by `detector.output_harmful_content.enabled` (bool, default `false`) and `detector.output_harmful_content.block_threshold` (float, default 0.6). See `docs/spec/configuration.md`.
- **Side effects:** On `block`: forensic record written with `attack_category = "output_harmful_content"`, severity `critical`. On `advisory`: session risk score incremented.
- **Failure modes:** Stage 1 pattern raises → `error` verdict returned, pipeline continues (fail-open per detector). LLM unavailable → soft-fail to `advisory` with `signal_id = output.harmful_content:pattern_match`. LLM exception → soft-fail to `advisory` with error details in `details["error"]`.
- **References:** task 112, corpus at `tests/eval/corpus/scenarios_multi_turn.yaml` (family: "authority_pedagogy_framing"), configuration keys at `docs/spec/configuration.md`.

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

### B-104: Session ID not provided

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
