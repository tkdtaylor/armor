# Architecture Overview

**Project:** armor
**Last updated:** 2026-05-05

## What this is

`armor` is a defense-in-depth security layer for LLM agents. It detects prompt injection, exfiltration via canary tokens, encoding/obfuscation, jailbreaks, tool/API abuse, and multi-turn session attacks. It runs as a long-lived Python daemon inside a Docker container and is consumed two ways:

1. **As Claude Code hooks** — primary integration, via `UserPromptSubmit`, `PreToolUse`, `PostToolUse`, `Stop`
2. **As an importable Python library** — secondary integration for custom agents wrapping the Anthropic / OpenAI / LangChain SDKs

The full design discussion that motivated this architecture is in [discussion.md](../../discussion.md) at the project root (gitignored, kept locally).

## High-level design

```
┌──────────────────────┐       ┌──────────────────────────────────┐
│  Claude Code (host)  │       │      armor container             │
│   ┌──────────────┐   │       │                                  │
│   │ shell hook   │───┼──────►│  ┌────────────────────────────┐  │
│   │ (tiny client)│   │ unix  │  │   armor daemon (Python)    │  │
│   └──────────────┘   │ socket│  │                            │  │
│                      │       │  │  ┌──────────────────────┐  │  │
│   ┌──────────────┐   │       │  │  │ Static detectors     │  │  │
│   │ python lib   │───┼──────►│  │  │ (regex, A-C, entropy)│  │  │
│   │ (Guard SDK)  │   │ HTTP  │  │  └──────────────────────┘  │  │
│   └──────────────┘   │ /unix │  │  ┌──────────────────────┐  │  │
└──────────────────────┘       │  │  │ Validator LLM        │  │  │
                               │  │  │ (small quantized)    │  │  │
                               │  │  └──────────────────────┘  │  │
                               │  │  ┌──────────────────────┐  │  │
                               │  │  │ Session tracker      │  │  │
                               │  │  │ (SQLite)             │  │  │
                               │  │  └──────────────────────┘  │  │
                               │  │  ┌──────────────────────┐  │  │
                               │  │  │ Forensic logger      │  │  │
                               │  │  └──────────────────────┘  │  │
                               │  └────────────────────────────┘  │
                               └──────────────────────────────────┘
```

The daemon is started once and serves all requests. Hooks are tiny clients; the cost of cold-starting Python is paid once per daemon restart, not once per Claude Code turn.

The validator LLM and the **honeypot** are the same model — one weight set, two system prompts. The honeypot answers as if it has access to a vault of fake credentials, internal hostnames, and webhook URLs that are designed to look real but are statically detectable. If any canary value appears in agent output, it is a deterministic signal that an injection succeeded — converting a fuzzy semantic problem into a string-matching problem.

> See [diagrams.md](diagrams.md) for the full system + runtime sequence diagrams.
> See [`docs/spec/`](../spec/) for the structured spec — what the system *does and is* today.

## Key decisions

| Decision | Choice | ADR |
|----------|--------|-----|
| Primary integration point | Claude Code hooks (`UserPromptSubmit`, `PreToolUse`, `PostToolUse`, `Stop`) | ADR-001 |
| Secondary integration | Importable Python library wrapping SDK calls | ADR-001 |
| Implementation language | Python 3.12, daemon architecture for sub-millisecond per-hook latency | ADR-002 |
| Validator + honeypot model | `lmstudio-community/Qwen3-0.6B-GGUF` (Qwen3-0.6B-Q4_K_M, Apache 2.0) — same weights, two system prompts | ADR-018 |
| Inference runtime | `llama.cpp` via `llama-cpp-python` | ADR-003 |
| Session state store | SQLite, file-backed | ADR-004 |
| Pattern matcher | `pyahocorasick` for multi-pattern canary scanning | ADR-005 |
| Container base | Debian slim multi-stage; target image <2 GB with model baked in | ADR-006 |
| Detection categories in v1 | P0–P3 from the discussion taxonomy (direct injection, exfiltration, encoding, jailbreak, tool abuse, context attacks, multi-turn) | ADR-007 |

## Data flow

1. **Inbound check (input)**: User submits text → hook fires `armor check input` with the prompt → daemon runs static filters (encoding-request keywords, instruction-override regex, jailbreak templates) → if safe, returns `pass`; otherwise returns `block` with the matched signal.
2. **Outbound check (output)**: Model returns text → hook fires `armor check output` → daemon runs canary scan, URL/IP/email exfil extraction, output entropy analysis, and (optionally) the validator LLM → returns `pass` or `block + forensic record`.
3. **Tool-call check**: Agent issues a Bash tool call → hook fires `armor check tool` with the command → daemon checks against the command-injection denylist (rm -rf /, /etc/shadow reads, container escape patterns) → returns `pass` / `block`.
4. **Session-level**: Every check writes to a per-session SQLite row. A session-tracker reads aggregated stats (rolling output entropy, partial canary matches across turns, exfil-destination accumulation) and can escalate a session's risk score, triggering harder blocks.

## External dependencies

| Dependency | Purpose | Notes |
|------------|---------|-------|
| `llama-cpp-python` | Local quantized LLM inference | Pinned; bundled with model weights in the image |
| `pyahocorasick` | Multi-pattern string matching (canaries, keywords) | Pure-Python fallback acceptable for tests |
| SQLite (stdlib) | Session state, forensic log | No external service |
| Anthropic SDK / OpenAI SDK / LangChain | (Optional) library-side adapters when used as a wrap | Not needed for hook-only deployments |

## Design principles

This project follows **Unix philosophy** — small composable detectors over a single monolithic checker. Each detector has a single responsibility (one signal, one pattern family, one heuristic) and exposes a uniform `Detector.check(payload) -> Verdict` interface. The pipeline is just an ordered list of detectors, configurable per check-point.

The full statement (modularity, interface standardization, maintainability, reusability + the working rules) lives in `CLAUDE.md` and is enforced by the `architect` agent during reviews. Two project-specific addenda:

- **Detectors fail open by default; the pipeline fails closed.** A single detector raising on bad input is a bug we want to know about, not a security failure — the pipeline runs the next detector. But if the *whole pipeline* errors out and produces no verdict, the request is blocked. Better a false positive than a silent miss.
- **The validator LLM is on the hot path but never load-bearing.** Static detectors must catch every P0/P1 attack on their own. The LLM exists to add semantic-level signal for P2/P3 attacks (jailbreak framing, gradual escalation) where static rules over-match. Treat its verdict as advisory, weighted into the risk score.

## Constraints and non-goals

- **Not a replacement for model-side safety training.** `armor` is a perimeter; the model still needs to refuse on its own. Defense in depth, not defense in one place.
- **Not a generic content filter.** Profanity, NSFW, copyright, etc. are out of scope. Scope is *security against adversarial prompts and exfiltration*, not safety/policy filtering.
- **Not designed for sub-millisecond hot paths inside a high-QPS API.** The target is a single user's Claude Code session and small-N agent fleets. Throughput optimization beyond that is explicitly v2+.
- **No outbound network calls from the daemon by default.** All inference is local. This is part of the threat model — the guardrail is the last line; it must not itself be a data exfiltration channel.
