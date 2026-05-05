# Architecture Diagrams

**Project:** armor
**Last updated:** 2026-05-05

Mermaid diagrams for the overall system and key runtime flows. See [overview.md](overview.md) for prose context and [decisions/](decisions/) for the ADRs referenced here.

These diagrams are part of the **authoritative spec** for this project. Code changes that contradict a diagram either invalidate the change or invalidate the diagram; one must be updated to match the other in the same commit.

---

## 1. System components

```mermaid
flowchart TB
    subgraph Host["Host (user's machine)"]
        CC["Claude Code (or other agent)"]
        Hook["Tiny shell hook<br/>UserPromptSubmit / PreToolUse /<br/>PostToolUse / Stop"]
        Lib["armor Python library<br/>(Guard SDK — secondary)"]
    end

    subgraph Container["armor container"]
        Daemon["armor daemon<br/>(long-lived Python process)"]

        subgraph Detectors["Detector pipeline"]
            Static["Static detectors<br/>(regex, Aho-Corasick, entropy)"]
            Validator["Validator LLM<br/>(small quantized — Qwen/Phi/Llama)"]
            CmdGuard["Command-injection guard<br/>(shell denylist, tool params)"]
        end

        Session["Session tracker<br/>(SQLite)"]
        Forensic["Forensic logger<br/>(blocked-attack records)"]
        Honeypot["Honeypot context<br/>(canary credentials, URLs, paths)"]
    end

    CC --> Hook
    Hook -->|Unix socket| Daemon
    Lib -->|HTTP / Unix socket| Daemon
    Daemon --> Static
    Daemon --> Validator
    Daemon --> CmdGuard
    Validator -.uses.-> Honeypot
    Daemon --> Session
    Daemon --> Forensic
```

**Key contracts**
- The daemon is the single entry point; hooks and the library never invoke detectors directly. Keeps detector discovery, ordering, and config centralized.
- Every detector implements `Detector.check(payload, context) -> Verdict`. New detectors plug in via a registry; no detector touches another's internals.
- The validator LLM and the honeypot share one model weight; they differ only by system prompt. Loaded once at daemon start.
- Session state is process-local (SQLite file in a mounted volume). A daemon restart preserves session history.

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
    participant V as Validator LLM
    participant S as Session tracker

    U->>CC: types prompt
    CC->>H: fire UserPromptSubmit
    H->>D: check input (prompt, session_id)
    D->>SD: run static filters
    alt static block
        SD-->>D: block (matched signal)
        D->>S: record block + risk++
        D-->>H: BLOCK
        H-->>CC: stderr + exit 2
        CC-->>U: shows blocked notice
    else static pass
        SD-->>D: pass
        D->>V: semantic check (optional, throttled)
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
    participant FL as Forensic logger

    CC->>H: model output ready
    H->>D: check output (text, session_id)
    D->>CS: scan for canary tokens
    D->>DS: extract URLs / IPs / emails
    D->>ES: high-entropy substring scan
    alt canary tripped
        CS-->>D: HIT (canary_id, position)
        D->>FL: write incident<br/>(input + attempted output + destination)
        D-->>H: BLOCK
        H-->>CC: replace output with safe message
    else clean
        CS-->>D: clean
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
    Normal --> Watching: 1 advisory signal
    Normal --> Elevated: 2+ advisory in window
    Watching --> Normal: 10 turns clean
    Watching --> Elevated: another signal
    Elevated --> High: partial canary match / encoding request
    Elevated --> Watching: 20 turns clean
    High --> Blocked: any further signal
    Blocked --> [*]: session closed (Stop hook)

    note right of Watching
        Static + LLM both run
    end note

    note right of Elevated
        Stricter thresholds, more
        validator LLM passes
    end note

    note right of High
        Block on first hit; require
        manual session reset
    end note
```

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
