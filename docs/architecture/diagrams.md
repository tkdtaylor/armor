# Architecture Diagrams

**Project:** armor
**Last updated:** 2026-06-19 (v2.3 — drift fix: documented canary.chunked block path (B-009c) and cross_boundary_override in §1 and §3)

Mermaid diagrams for the overall system and key runtime flows. See [overview.md](overview.md) for prose context and [decisions/](decisions/) for the ADRs referenced here.

These diagrams are part of the **authoritative spec** for this project. Code changes that contradict a diagram either invalidate the change or invalidate the diagram; one must be updated to match the other in the same commit.

---

## Capability overview — armor protecting an agent

The 30-second mental model. armor sits as a guard layer between the user, the agent's LLM loop, and the tools the agent calls. It enforces three intercept points (input, tool, output) and runs a canary-trap path: a honeypot LLM seeds fake credentials into suspicious sessions, and if any of those credentials reappear in a later output the request is blocked and a forensic incident is written — with the `canary_id` only, never the value.

![armor architecture concept: protected LLM agent flow through input, output, and tool-call guard layers](../../artifacts/armor-architecture.png)

```mermaid
flowchart LR
    User(["User"])

    subgraph Armor["armor daemon (guard layer)"]
        direction TB
        I["check input<br/>injection, jailbreak, encoding"]
        TC["check tool<br/>param schemas, dangerous bash"]
        O["check output<br/>canary scan, rolling buffer, entropy, destinations"]
        H["Honeypot LLM<br/>seeds canary credentials<br/>when injection is suspected"]
        F[("Forensic log<br/>canary_id only<br/>value is never stored")]
    end

    Agent["Agent (your LLM loop)"]
    Tools["Tools (shell, APIs, retrieval)"]

    User -->|"1 prompt"| I
    I -->|pass| Agent
    I -.block.-> F
    Agent -->|"2 tool call"| TC
    TC -->|pass| Tools
    TC -.block.-> F
    Tools -->|result| Agent
    Agent -->|"3 response"| O
    O -->|pass| User
    O -.canary leak.-> F
    H -. seeds canaries .-> Agent
```

**Reading the diagram**

- **Solid arrows** are the happy path (the request flows through). **Dotted arrows** are the unhappy path (a check fired, the request is blocked, the incident is written to the forensic log).
- **Three intercept points** map to the three `armor check` subcommands. They are wired through four Claude Code lifecycle hooks (`UserPromptSubmit`, `PreToolUse`, `PostToolUse`, `Stop` — see §6 for the deployment topology). Every detector runs at exactly one point — there's no shared mutable state between them.
- **The canary trap** is the loop on the right: the honeypot LLM (same model weights as the validator, different system prompt) seeds canary credentials into the agent's context when a session reaches `Watching` and an injection signal fires. Any later output containing one of those values trips the canary scanner at the output check. The honeypot is not a detector — it's a bait generator that makes exfiltration *visible* downstream.
- **Forensic log discipline.** The forensic log records `canary_id` (e.g. `aws-key-042`) and not the canary value. Two reasons: (1) the log itself must not become an exfiltration channel if an attacker ever gains read access to it, and (2) canary values are expected to be regenerated and rotated; pinning a value into the audit history would couple the audit trail to a transient secret. See ADR-010 for the storage contract and the unit test that enforces it.

The eight diagrams below zoom into individual aspects of this overview: §1 component layout, §2 input flow, §3 output / canary-trip flow, §4 multi-turn risk escalation, §5 operator-clear path, §6 Claude Code deployment topology, §7 tool-call validation flow, §8 canary value generation and runtime use.

---

## 1. System components

```mermaid
flowchart TB
    subgraph Host["Host (user's machine)"]
        CC["Claude Code (or other agent)"]
        Hook["Tiny shell hook<br/>UserPromptSubmit / PreToolUse /<br/>PostToolUse / Stop"]
        Lib["armor Python library<br/>(ArmorClient / AsyncArmorClient — ADR-028)"]
        Spotlight["armor.spotlight annotator<br/>(agent-side transform — ADR-043)<br/>Span[] → (marked_text, boundary_instruction)<br/>No daemon call; pure library function"]
    end

    subgraph Container["armor container"]
        Daemon["armor daemon<br/>(long-lived Python process)"]

        PipelineOrch["Pipeline orchestrator<br/>(runs detectors, aggregates verdicts)"]

        subgraph Detectors["Detector pipeline"]
            Static["Static detectors<br/>(regex, Aho-Corasick, entropy)<br/>incl. ssrf_probe, sensitive_file_probe,<br/>code_injection, exfil_chain,<br/>cross_boundary_override (default-on)"]
            Validator["Validator LLM<br/>(Qwen3-0.6B-Q4_K_M)"]
            Topic["Topic-coherence detector<br/>(MiniLM ONNX embedding, per-session EMA)"]
            CmdGuard["Command-injection guard<br/>(shell denylist, tool params)"]
            Rolling["canary.paraphrase n-gram scan (advisory)<br/>+ canary.chunked full-value scan (block)<br/>(rolling buffer, 8 KB / 20 turns)"]
            ToolAbuse["Tool-abuse detectors<br/>(param schema, rate anomaly, chain)"]
            OutputOpt["Output detectors (opt-in)<br/>(output.harmful_content — regex + LLM, MODEL_OUTPUT only)"]
        end

        HoneypotGate["HoneypotGate<br/>(state ≥ Watching ∧ block/advisory → honeypot)"]

        FSM["Session state machine<br/>(Normal → Watching → Elevated → High → Blocked)"]
        Session["Session tracker<br/>(SQLite — sessions + rolling buffer)"]
        Forensic["Forensic logger<br/>(blocked-attack records, canary_id only)"]
        Honeypot["Honeypot LLM<br/>(shared model session, canary-bearing prompt per ADR-038)"]
        Logger["Structured logger (armor.logging)<br/>(event sink, ADR-029)"]
    end

    CC --> Hook
    CC -.annotate context.-> Spotlight
    Hook -->|Unix socket| Daemon
    Lib -->|Unix socket| Daemon
    Daemon --> PipelineOrch
    PipelineOrch --> Static
    PipelineOrch --> Validator
    PipelineOrch --> Topic
    PipelineOrch --> CmdGuard
    PipelineOrch --> Rolling
    PipelineOrch --> ToolAbuse
    PipelineOrch --> OutputOpt
    HoneypotGate -.invokes.-> Honeypot
    Topic -.advisory feeds.-> FSM
    Static -.advisory/block feeds.-> FSM
    Rolling -.advisory feeds.-> FSM
    FSM -.gates LLM tier.-> HoneypotGate
    Daemon --> Session
    Daemon --> Forensic
    Daemon --> Logger
    PipelineOrch -.feeds verdicts.-> FSM
```

**Key contracts**
- The daemon is the single entry point; hooks and the library (armor.sdk, armor.canaries) never invoke detectors directly. Keeps detector discovery, ordering, and config centralized.
- The pipeline orchestrator (`armor.pipeline.Pipeline`) is the composition engine: it runs detectors in sequence, enforces per-detector timeouts, and aggregates verdicts (first block short-circuits, otherwise highest-severity advisory propagates).
- Every detector implements `Detector.check(payload, context) -> Verdict`. New detectors plug in via a registry; no detector touches another's internals.
- The HoneypotGate (`armor.daemon.honeypot_gate.should_invoke_honeypot`) gates the honeypot path: invoked only when session state ≥ `Watching` AND the static pipeline returns `block` or `advisory` (per B-011).
- The validator LLM and the honeypot share one model weight; they differ only by system prompt. Loaded once at daemon start.
- The topic-coherence embedder (`armor.embeddings.onnx_embedder.Embedder`) loads `all-MiniLM-L6-v2` ONNX once at daemon start; the detector maintains a rolling EMA via `armor.embeddings.ema_cache.EMACache`. The detector emits `advisory` only — never `block` on its own — and feeds the session state machine (ADR-026). Input checks run the topic-coherence detector per B-008a.
- The session state machine sits between the pipeline and per-detector cost decisions: it gates the LLM cost tier (skipped at `Normal`, run at ≥ `Watching`), accumulates risk from advisory verdicts, and short-circuits all detectors at `Blocked` while still writing the forensic incident (ADR-024).
- The rolling buffer (per-session concatenation, 8 KB / 20 turns per ADR-025) is consumed by two detectors: `detectors.canary_paraphrase` scans for ≥ K distinct n-grams of any active canary and emits an `advisory` (per B-009a / B-009b), and `detectors.canary_chunked` scans the concatenated buffer for a complete canary value reconstructed across turns and emits `block` on a full match (per B-009c).
- The canaries module (`armor.canaries.catalogue.Catalogue`, `armor.canaries._generate.write_values_file`) manages the injected credential catalogue — placeholders are substituted at honeypot LLM prompt-build time.
- The structured logger (`armor.logging`) is the event sink for all daemon operations: verdicts, state transitions, honeypot invocations, and forensic incidents. Event schema is defined in ADR-029.
- The SDK (`armor.sdk.client.ArmorClient`, `armor.sdk.async_client.AsyncArmorClient`) provides importable clients for third-party integrations; daemon communication is via Unix socket, never in-process.
- Session state is process-local (SQLite file in a mounted volume). A daemon restart preserves session history, FSM fields (`current_state`, `risk_score`, `last_signal_at`), and the rolling buffer.
- The `armor.spotlight` annotator (`armor.spotlight.annotate`) is a pure library transform that runs in the **agent process**, not inside the daemon container. It accepts a list of `Span` objects (each tagged with a `Source` provenance label) and returns `(marked_text, boundary_instruction)`. The agent prepends `boundary_instruction` to its system prompt and passes `marked_text` as context to the downstream LLM. This transform has no daemon call, no network call, and does not touch the detector pipeline — it is a standalone ADR-028 stable SDK surface (ADR-043 §2). Detection of sentinel forgery in untrusted spans is the annotator's secondary role: if an untrusted span's text contains the sentinel base string, the annotator neutralizes it and raises `SentinelForgeryError` so the agent can log the boundary-escape attempt.

---

## 2. Primary runtime flow — input check

```mermaid
sequenceDiagram
    autonumber
    participant U as User
    participant CC as Claude Code
    participant H as Hook (UserPromptSubmit)
    participant D as armor daemon
    participant SD as Static detectors
    participant TC as Topic-coherence
    participant V as Validator LLM
    participant HG as HoneypotGate
    participant S as Session tracker

    U->>CC: types prompt
    CC->>H: fire UserPromptSubmit
    H->>D: check input (prompt, session_id)
    D->>SD: run static filters
    D->>TC: compute topic coherence (B-008a)
    alt static block
        SD-->>D: block (matched signal)
        alt state ≥ Watching ∧ injection detected
            D->>HG: should_invoke_honeypot?
            HG-->>D: yes (B-011)
            D->>V: honeypot LLM check
            V-->>D: verdict (with fake credentials)
        else state < Watching OR no injection
            D-->>D: skip honeypot
        end
        D->>S: record block + risk++
        D-->>H: BLOCK
        H-->>CC: stderr + exit 2
        CC-->>U: shows blocked notice
    else static pass
        SD-->>D: pass
        TC-->>D: advisory (topic shift) or pass
        D->>V: semantic check (optional, when Watching+)
        V-->>D: verdict
        D->>S: record pass / advisory
        D-->>H: PASS
        H-->>CC: exit 0
        CC->>U: continues normally
    end
```

---

## 3. Output / exfiltration check (canary trip)

```mermaid
sequenceDiagram
    autonumber
    participant CC as Claude Code
    participant H as Hook (PostToolUse / Stop)
    participant D as armor daemon
    participant CS as Canary scanner
    participant DS as Destination scanner
    participant ES as Entropy analyzer
    participant RB as Rolling buffer scan
    participant HG as HoneypotGate
    participant V as Validator LLM
    participant FL as Forensic logger

    CC->>H: model output ready
    H->>D: check output (text, session_id)
    D->>CS: scan for canary tokens (per-turn)
    D->>DS: extract URLs / IPs / emails
    D->>ES: high-entropy substring scan
    D->>RB: canary.paraphrase n-gram scan over rolling buffer (B-009b)
    D->>RB: canary.chunked full-value scan over rolling buffer (B-009c)
    alt canary tripped (per-turn full match)
        CS-->>D: HIT (canary_id, position)
        alt state ≥ Watching ∧ block detected
            D->>HG: should_invoke_honeypot?
            HG-->>D: yes (B-011)
            D->>V: honeypot LLM confirmation
            V-->>D: verdict
        end
        D->>FL: write incident<br/>(input + attempted output + destination)
        D-->>H: BLOCK
        H-->>CC: replace output with safe message
    else chunked canary reconstructed (B-009c)
        RB-->>D: HIT (canary_id, full value across turns)
        D->>FL: write incident<br/>(input + attempted output + destination)
        D-->>H: BLOCK
        H-->>CC: replace output with safe message
    else multi-turn paraphrase advisory (B-009b)
        RB-->>D: ADVISORY (canary_id, ngram_count)
        D->>FL: feed advisory into FSM and increase risk score
    else clean
        CS-->>D: clean
        RB-->>D: clean
        DS-->>D: destinations OK / on whitelist
        ES-->>D: entropy OK
        D-->>H: PASS
    end
```

---

## 4. Multi-turn risk escalation

```mermaid
stateDiagram-v2
    [*] --> Normal
    Normal --> Watching: risk_score ≥ 0.4
    Watching --> Elevated: risk_score ≥ 0.9
    Elevated --> High: risk_score ≥ 1.5
    High --> Blocked: any block verdict
    Normal --> Blocked: any block verdict
    Watching --> Blocked: any block verdict
    Elevated --> Blocked: any block verdict
    Watching --> Normal: cooldown drops score below 0.4
    Elevated --> Watching: cooldown drops score below 0.9
    High --> Elevated: cooldown drops score below 1.5
    Blocked --> Watching: clear_blocked / sessions.unblock --reason
    Blocked --> Blocked: signal pressure (advisories / cooldown cannot exit)

    note right of Normal
        LLM cost-tier detectors are skipped.
    end note

    note right of Watching
        Static detectors plus the LLM
        cost tier (validator + honeypot).
    end note

    note right of High
        One step from Blocked. Cooldown
        is the only escape.
    end note

    note right of Blocked
        All detectors short-circuit, and the
        forensic incident is still written.
    end note
```

Forward transitions are signal-driven: each `advisory` verdict adds `confidence × per-detector weight` to `risk_score`; any `block` verdict jumps directly to `Blocked` from any rung. Backward transitions are cooldown-driven: `risk_score` decays linearly at `session.cooldown_decay_per_min` against wall-clock time (default 0.1 / minute), and the state steps back exactly one rung when the score falls below the current rung's threshold. The operator-clear contract is `Blocked` → `Watching` via `armor sessions unblock <id> --reason <text>`; the daemon couples the state mutation with an `OperatorAuditLog` write in a single SQLite transaction (see §5 below). Thresholds and weights live in `armor.toml` (see [`docs/spec/configuration.md`](../spec/configuration.md)).

---

## 5. Operator-clear flow (sessions.unblock)

```mermaid
sequenceDiagram
    autonumber
    participant Op as Operator
    participant CLI as armor sessions unblock
    participant D as armor daemon
    participant FSM as state_machine.clear_blocked
    participant DB as SQLite (Session + OperatorAuditLog)
    participant Log as Structured logger

    Op->>CLI: armor sessions unblock SB --reason "manual review cleared"
    CLI->>D: IPC sessions.unblock (session_id, reason, actor)
    D->>FSM: clear_blocked(session_id, actor, reason, db_path)
    FSM->>DB: BEGIN, UPDATE Session SET current_state=Watching, INSERT OperatorAuditLog, COMMIT
    alt session not Blocked
        FSM-->>D: raise InvalidStateTransition
        D->>Log: emit sessions.unblock error event
        D-->>CLI: error verdict with message
    else success
        FSM-->>D: SessionState.WATCHING
        D->>Log: emit sessions.unblock pass event
        D-->>CLI: pass verdict with new state Watching
    end
```

This flow is the only exit from `Blocked`. The state mutation and the
audit-log row are written under a single SQLite transaction; if either
fails the session remains `Blocked` and no audit row is written
(enforced by the unit test in `tests/unit/test_clear_blocked.py`).

---

## 6. Deployment topology — Claude Code hook integration

The most common public deployment shape: a Claude Code project on the host calls `armor check <kind>` from each lifecycle hook; the daemon runs in the same host (uv) or in a container.

```mermaid
flowchart LR
    subgraph Host["Host machine"]
        CC["Claude Code session"]
        SH["host shell<br/>(.claude/settings.json hooks)"]
        SOCK["/tmp/armor.sock<br/>(Unix socket, 0600)"]
        DB["armor.db<br/>(SQLite)"]
        subgraph Daemon["armor daemon (uv or container)"]
            CLI["armor CLI"]
            PIPE["detector pipeline"]
            LLM["validator + honeypot LLM"]
        end
    end

    CC -->|"UserPromptSubmit"| SH
    CC -->|"PreToolUse"| SH
    CC -->|"PostToolUse"| SH
    CC -->|"Stop"| SH
    SH -->|"armor check input/tool/output"| CLI
    CLI -->|"Unix socket request"| SOCK
    SOCK --> Daemon
    Daemon --> PIPE
    PIPE --> LLM
    Daemon -->|"forensic incident<br/>(canary_id, never value)"| DB
    Daemon -->|"verdict (exit 0 / 2)"| SH
    SH -->|"halt at lifecycle event<br/>if exit 2"| CC
```

Wire-up reference: [examples/claude_code/settings.json](../../examples/claude_code/settings.json) is the drop-in `.claude/settings.json` that establishes this topology. The Python SDK path (`examples/anthropic_sdk.py`, `examples/openai_sdk.py`, `examples/langchain.py`, `examples/custom_agent.py`) bypasses the hook layer and calls the daemon directly via `ArmorClient`; the topology is otherwise the same.

The four lifecycle hooks map to four armor check kinds plus session bookkeeping. `PostToolUse` is wired twice with different tool-name matchers — read-style tools (Read/WebFetch/Grep/Glob/MCP-readers) feed `check fetched` for indirect-injection scanning, all other tool results feed `check output` for canary-leak detection:

| Lifecycle event | Tool matcher | armor command | Defends against |
|---|---|---|---|
| `UserPromptSubmit` | (any) | `armor check input` | direct injection, jailbreak templates, encoding-request patterns |
| `PreToolUse` | (any) | `armor check tool` | parameter tampering, dangerous bash, schema violations |
| `PostToolUse` | `Read\|WebFetch\|Grep\|Glob\|mcp__.*__read.*` | `armor check fetched` | indirect injection in retrieved content (B-017) |
| `PostToolUse` | (any) | `armor check output` | canary exfiltration, encoded payloads, partial-canary aggregation |
| `Stop` | — | `armor session close` | per-session state flush (rolling buffer, risk score) |

---

## 7. Tool-call validation flow

The `armor check tool` path (PreToolUse hook). Two static detectors compose: `tool_param_schema.ToolParamSchema` always runs (looks the tool up in `tool_schemas.json`, validates parameter shape, then runs each declared `risk_rule`); `cmd_injection_bash.CmdInjectionBash` runs only when `payload.tool == "Bash"` and matches the bash command string against the patterns in `cmd_injection_patterns.yaml`. The pipeline short-circuits on the first `block`.

```mermaid
sequenceDiagram
    autonumber
    participant CC as Claude Code
    participant H as Hook (PreToolUse)
    participant D as armor daemon
    participant TPS as ToolParamSchema
    participant CIB as CmdInjectionBash
    participant FL as Forensic logger

    CC->>H: about to call tool (name, params)
    H->>D: check tool (name, params, session_id)
    D->>TPS: validate against tool_schemas.json
    alt schema mismatch or risk-rule hit
        TPS-->>D: block (signal_id tool_param.schema:tool:rule_or_shape)
        D->>FL: incident (tool, rule_id, params)
        D-->>H: BLOCK (exit 2 — tool call halted)
    else pass (or unknown tool — continues)
        TPS-->>D: pass
        alt payload.tool == Bash
            D->>CIB: regex-scan command vs cmd_injection_patterns.yaml
            alt denylist match
                CIB-->>D: block (rm -rf, /etc/shadow read, container escape, sudo escalation, etc.)
                D->>FL: incident (matched pattern_id, family, severity)
                D-->>H: BLOCK
            else clean
                CIB-->>D: pass
                D-->>H: PASS (tool runs)
            end
        else non-Bash tool
            D-->>H: PASS (tool runs)
        end
    end
```

**Key contracts**

- `ToolParamSchema.check` returns `pass` with `details.unknown_tool=true` when the tool name is absent from the registry. The pipeline does not block on unknown tools — it relies on subsequent detectors (today only `CmdInjectionBash` for Bash) to decide.
- A schema mismatch (missing required param, wrong type) emits `signal_id = tool_param.schema:<tool>:shape`. A `risk_rule` match emits `signal_id = tool_param.schema:<tool>:<rule.id>`. Both are `severity: "high"` and short-circuit the pipeline.
- `CmdInjectionBash._patterns` is loaded once per process (class-level cache). Patterns are categorized by `family` (`filesystem_destruction`, `credential_read`, `container_escape`, `privilege_escalation`); the family becomes part of the forensic incident category.
- The detector for tool calls runs the same orchestration shape as input/output checks — see §1's `Pipeline orchestrator` and the `_handle_check_operation` dispatch in `armor/daemon/server.py`. The only difference is the payload constructor (`Payload(text=f"{tool} {params}", tool=tool, params=params)`).

---

## 8. Canary value generation and runtime use

How a canary value gets from "regex pattern in the bundled schema" to "Aho-Corasick automaton + substituted honeypot prompt" without ever touching the GGUF model file. Three phases: install, boot, runtime.

```mermaid
flowchart TB
    subgraph Install["Install-time (operator runs once per environment)"]
        S1["default_catalogue.json<br/>(bundled schema:<br/>canary_id, kind, marker_rule, active — no values)"]
        S2["armor canary generate<br/>(reads schema, generates a fresh value per<br/>active marker_rule, merges schema + values)"]
        S3[("values JSON file<br/>(0o600, owner-only —<br/>schema fields plus the freshly random value)")]
        S4["armor canary honeypot<br/>(writes fake-credential .env<br/>with generated values)"]
        S5["armor canary pii-context<br/>(writes system-prompt snippet<br/>with fake PII identity records:<br/>name, email, DOB, SIN)"]
        S1 --> S2 --> S3
        S3 --> S4
        S3 --> S5
    end

    subgraph Boot["Daemon boot-time"]
        B1["daemon --canary-values-path"]
        B2["Catalogue.load(values file)"]
        B3["In-memory catalogue<br/>(canary_id, value, kind, marker_rule)"]
        S3 --> B1 --> B2 --> B3
    end

    subgraph Consumers["Two runtime consumers (B-002 + B-011, ADR-021)"]
        C1["CanaryScanner<br/>(builds Aho-Corasick automaton<br/>from the value strings —<br/>O(n) substring scan)"]
        C2["honeypot.respond()<br/>(substitutes canary placeholders<br/>in honeypot.txt template at<br/>inference time only)"]
        B3 --> C1
        B3 --> C2
    end

    subgraph Detect["Detection path"]
        D1["Every output check<br/>(per-turn payload +<br/>rolling buffer concatenation)"]
        D2["Honeypot LLM response<br/>(substituted prompt fed to model)"]
        D3[("Forensic log<br/>writes canary_id only —<br/>never the value")]
        C1 -.scans.-> D1
        C2 -.invokes.-> D2
        D2 -.routes back through.-> D1
        D1 -.match block.-> D3
    end
```

**Key contracts**

- The bundled `default_catalogue.json` ships in the wheel and the Docker image but contains **no values** — only `canary_id`, `kind`, `service`, `marker_rule`, `active`. Anyone reading the public source learns the *shape* of the canaries, not any deployment's specific values.
- Two honeypot output paths are available after `armor canary generate`: `armor canary honeypot` writes a fake-credential `.env` file (credentials surface) and `armor canary pii-context` writes a system-prompt snippet with fake PII identity records (name, email, date of birth, SIN). Both output files contain real canary values registered in the daemon; any output containing these values triggers a block via the Aho-Corasick scanner — regardless of how the attacker phrased their request.
- `_generate_value_for_pattern(marker_rule)` in `armor/canaries/_generate.py` knows the recognized regex shapes (AWS keys, GitHub PATs, Stripe keys, fake URLs/paths/hostnames/emails, fake wallet addresses) and emits a fresh random string conforming to each. Unknown patterns raise `ValueError` rather than silently producing garbage.
- `write_values_file()` writes the merged schema + values atomically with mode `0o600` via `os.open(O_CREAT|O_WRONLY|O_TRUNC, 0o600)` — readable only by the owning user. Each install therefore has a different value set; cloning a public dump tells an attacker nothing about a target deployment.
- The `Catalogue` object is daemon-process-local. There is no network read; the values file path is operator-controlled and lives outside the Docker image (per ADR-010).
- `CanaryScanner` builds its automaton once at daemon start from the in-memory values. Substring matching is O(n) in the input length regardless of catalogue size, which keeps the per-output cost flat.
- `armor.llm.honeypot.respond` is the *only* code path that reads `Catalogue.value`. The validator path never touches values — enforced by the `tests/fitness/test_validator_no_value_access.py` fitness function that AST-scans `validator.py` for any `catalogue.values()` call or `.value` field access (per ADR-021).
- The forensic log records `triggered_canary = canary_id` (e.g. `aws-key-042`), not the value. Test `test_triggered_canary_id_not_value` in `tests/unit/db/test_forensic.py` asserts the substitution at write time; the log itself can never become an exfiltration channel.
- A successful injection that causes the honeypot LLM to emit its substituted prompt content routes back through the same output-check path (because every honeypot response is itself an output) — closing the loop deterministically: prompt-injection → honeypot bait → canary value in output → Aho-Corasick match → block + forensic incident.

---

## Adding more diagrams

Reserved for future expansion. The current open candidate is:

- Container-only topology (defer until the GHCR image is published — same shape as §6 with `Daemon` running in its own container reachable via shared-volume socket)

If a new component lands or an existing flow gains a non-obvious branch, add it as the next numbered section. One concept per diagram. If a diagram tries to show both a component layout and a runtime sequence, split it.

---

## Maintaining these diagrams

- **Trigger to update:** any time a new detector class lands, the daemon's IPC surface changes, or session-state semantics change.
- **Edit existing over adding new.** Duplicates rot independently.
- **Update the date at the top** when you change anything substantive.
