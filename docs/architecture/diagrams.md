# Architecture Diagrams

**Project:** armor
**Last updated:** 2026-05-07 (v1.1 — added HoneypotGate, pipeline orchestrator, logging sink, rolling buffer in §3)

Mermaid diagrams for the overall system and key runtime flows. See [overview.md](overview.md) for prose context and [decisions/](decisions/) for the ADRs referenced here.

These diagrams are part of the **authoritative spec** for this project. Code changes that contradict a diagram either invalidate the change or invalidate the diagram; one must be updated to match the other in the same commit.

---

## 1. System components

```mermaid
flowchart TB
    subgraph Host["Host (user's machine)"]
        CC["Claude Code (or other agent)"]
        Hook["Tiny shell hook<br/>UserPromptSubmit / PreToolUse /<br/>PostToolUse / Stop"]
        Lib["armor Python library<br/>(ArmorClient / AsyncArmorClient — ADR-028)"]
    end

    subgraph Container["armor container"]
        Daemon["armor daemon<br/>(long-lived Python process)"]

        PipelineOrch["Pipeline orchestrator<br/>(runs detectors, aggregates verdicts)"]

        subgraph Detectors["Detector pipeline"]
            Static["Static detectors<br/>(regex, Aho-Corasick, entropy)"]
            Validator["Validator LLM<br/>(Qwen3-0.6B-Q4_K_M)"]
            Topic["Topic-coherence detector<br/>(MiniLM ONNX embedding, per-session EMA)"]
            CmdGuard["Command-injection guard<br/>(shell denylist, tool params)"]
            Rolling["Rolling-buffer scan<br/>(per-session, 8 KB / 20 turns)"]
        end

        HoneypotGate["HoneypotGate<br/>(state ≥ Watching ∧ block/advisory → honeypot)"]

        FSM["Session state machine<br/>(Normal → Watching → Elevated → High → Blocked)"]
        Session["Session tracker<br/>(SQLite — sessions + rolling buffer)"]
        Forensic["Forensic logger<br/>(blocked-attack records, canary_id only)"]
        Honeypot["Honeypot context<br/>(canary credentials, URLs, paths)"]
        Logger["Structured logger (armor.logging)<br/>(event sink, ADR-029)"]
    end

    CC --> Hook
    Hook -->|Unix socket| Daemon
    Lib -->|HTTP / Unix socket| Daemon
    Daemon --> PipelineOrch
    PipelineOrch --> Static
    PipelineOrch --> Validator
    PipelineOrch --> Topic
    PipelineOrch --> CmdGuard
    PipelineOrch --> Rolling
    Validator -.uses.-> Honeypot
    HoneypotGate -.invokes.-> Validator
    Topic -.advisory feeds.-> FSM
    Static -.advisory/block feeds.-> FSM
    Rolling -.advisory/block feeds.-> FSM
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
- The rolling-buffer scan re-runs the canary scanner (from `armor.canaries.scanner.CanaryScanner`) and entropy analyzer against the per-session concatenation on every output check; a chunked match that did not trip on a single turn produces `exfiltration.canary_chunked` with all turns currently in the buffer quarantined together (per B-009a, ADR-025).
- The canaries module (`armor.canaries.catalogue.Catalogue`, `armor.canaries._generate.write_values_file`) manages the injected credential catalogue — placeholders are substituted at honeypot LLM prompt-build time.
- The structured logger (`armor.logging`) is the event sink for all daemon operations: verdicts, state transitions, honeypot invocations, and forensic incidents. Event schema is defined in ADR-029.
- The SDK (`armor.sdk.client.ArmorClient`, `armor.sdk.async_client.AsyncArmorClient`) provides importable clients for third-party integrations; daemon communication is via HTTP/Unix socket, never in-process.
- Session state is process-local (SQLite file in a mounted volume). A daemon restart preserves session history, FSM fields (`current_state`, `risk_score`, `last_signal_at`), and the rolling buffer.

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
    D->>RB: scan rolling buffer (B-009a)
    alt canary tripped (per-turn or chunked)
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
    else rolling buffer hit (chunked exfiltration)
        RB-->>D: HIT (canary_id, chunked match)
        D->>FL: write incident (chunked, all turns in buffer)
        D-->>H: BLOCK
        H-->>CC: replace output with safe message
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
        All detectors short-circuit; the
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
    FSM->>DB: BEGIN; UPDATE Session SET current_state='Watching'; INSERT OperatorAuditLog; COMMIT
    alt session not Blocked
        FSM-->>D: raise InvalidStateTransition
        D->>Log: emit { event: "sessions.unblock", decision: "error" }
        D-->>CLI: { verdict: "error", message }
    else success
        FSM-->>D: SessionState.WATCHING
        D->>Log: emit { event: "sessions.unblock", decision: "pass", session_id }
        D-->>CLI: { verdict: "pass", new_state: "Watching" }
    end
```

This flow is the only exit from `Blocked`. The state mutation and the
audit-log row are written under a single SQLite transaction; if either
fails the session remains `Blocked` and no audit row is written
(enforced by the unit test in `tests/unit/test_clear_blocked.py`).

---

## Adding more diagrams

Add additional numbered sections (5., 6., …) for any of:

- Tool-call validation flow (when the command-injection guard tells more nuanced detail)
- Deployment topology (host hook → container socket → daemon → SQLite volume)
- Canary value generation (how marker patterns get embedded into "valid-looking" credentials)

One concept per diagram. If a diagram tries to show both a component layout and a runtime sequence, split it.

---

## Maintaining these diagrams

- **Trigger to update:** any time a new detector class lands, the daemon's IPC surface changes, or session-state semantics change.
- **Edit existing over adding new.** Duplicates rot independently.
- **Update the date at the top** when you change anything substantive.
