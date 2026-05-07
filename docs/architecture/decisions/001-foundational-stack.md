# ADR-001 — Foundational stack and integration model

**Status:** Accepted
**Date:** 2026-05-04 (back-documented 2026-05-06; the decisions were taken at project bootstrap and originally captured only in `discussion.md`)
**Deciders:** armor core team

## Context

armor was bootstrapped from a long discussion captured in `discussion.md` (gitignored, kept locally). That conversation locked in a small set of foundational decisions before the project's task-and-ADR workflow existed. Subsequent ADRs and spec entries reference those choices as if they were ADRs (`ADR-001` … `ADR-007`), but no files with those numbers were ever written. The numbered ADR sequence on disk starts at `008-daemon-concurrency.md`.

This ADR back-documents the bootstrap decisions in one place so the references resolve and future readers can find the rationale without `discussion.md` (which is gitignored and may not be present).

The decisions covered here are not new and have not been re-litigated. Where a later ADR has revised one of them, that ADR is cited explicitly and supersedes this one for that row.

## Decision

The following choices were made at project bootstrap and remain in force. Each row's "current truth" lives in `docs/spec/`; this ADR records the reasoning and the supersession trail.

### Integration model

**Primary integration:** Claude Code hooks (`UserPromptSubmit`, `PreToolUse`, `PostToolUse`, `Stop`).

**Secondary integration:** importable Python library (`armor.Guard`) for custom agents wrapping Anthropic / OpenAI / LangChain SDKs.

**Why hooks first:** Claude Code is the canonical agent surface that motivated the project; hooks are the lowest-friction integration point because they require no SDK changes. The library wrapper is the natural fallback for non–Claude Code agents.

### Implementation language and runtime architecture

**Language:** Python 3.12, managed with `uv`.

**Architecture:** long-lived daemon + tiny client per hook invocation, talking over a Unix domain socket (HTTP fallback for non-local clients).

**Why Python:** every agent framework worth wrapping is Python-first; iteration speed on detector heuristics matters more than raw runtime cost. **Why a daemon:** `python3 -c …` cold-start adds ~50–100 ms per hook, which is unacceptable for the per-turn budget; loading the validator LLM once and keeping it warm amortises the cost.

Concurrency model details (asyncio + `asyncio.to_thread`) were deferred until the daemon implementation itself; see ADR-008.

### Inference runtime (placeholder, superseded by ADR-018/019)

The bootstrap decision was: **a small (~1–2 B parameter) quantized open-weight LLM, loaded locally via `llama.cpp` bindings, no outbound calls, no proprietary models.**

The specific model and binding library were left open at bootstrap: candidates listed were Qwen 2.5, Phi 3.5-mini, Llama 3.2-1B, Gemma 2-2B. The empirical model selection is locked in by **ADR-018 (Qwen3-0.6B-Q4_K_M)**, and the binding library is locked in by **ADR-019 (`llama-cpp-python`)**.

### Session state store

**SQLite (stdlib).** File-backed, no external service, durable across daemon restarts. The schema and access pattern have been extended by later ADRs (ADR-024 FSM fields, ADR-025 rolling-buffer table) but the choice of SQLite as the substrate is unchanged.

### Pattern matcher

**`pyahocorasick`** for multi-pattern canary scanning. Single-pass multi-pattern matching scales linearly in input length regardless of canary set size, which is the dominant hot-path cost for the canary scanner.

### Container base

**Debian slim, multi-stage build.** Target image < 2 GB with the validator weights and the topic-coherence ONNX model baked in. Multi-stage keeps the runtime image free of build tools.

### Detection categories in v1

**P0 → P3 from the threat-model taxonomy in `discussion.md`:** direct injection, exfiltration, encoding/obfuscation, jailbreak templates, tool/API abuse, context attacks, multi-turn / session attacks. The roadmap (`docs/plans/roadmap.md`) maps each priority to a milestone.

## Supersession trail

| Row | Status | Successor |
|-----|--------|-----------|
| Integration model | In force | — |
| Language + daemon architecture | In force | — |
| Inference runtime (placeholder) | Superseded for the model row by ADR-018 | ADR-018 |
| Inference runtime (placeholder) | Superseded for the binding library by ADR-019 | ADR-019 |
| Session store | In force; extended | ADR-024 (FSM fields), ADR-025 (rolling-buffer table) |
| Pattern matcher | In force | — |
| Container base | In force | — |
| Detection taxonomy | In force | Roadmap |

## Consequences

- References in `overview.md`, `tech-stack.md`, `interfaces.md`, completed task files, and earlier ADRs that cite `ADR-001` through `ADR-007` are anchored to this ADR. The granular row each reference was making is preserved in the supersession trail above.
- ADR-018's "Supersedes: ADR-003" line reads as a forward link from ADR-018 back to the placeholder model row in this ADR. ADR-019 follows the same convention for the binding-library row.
- This ADR is **back-documentation, not a re-decision.** Future changes to any row land as a new ADR that supersedes this one for that row only.

## References

- `discussion.md` — original design conversation (gitignored, kept locally)
- `docs/architecture/overview.md` — high-level narrative
- `docs/architecture/tech-stack.md` — table form of these choices
- `docs/plans/roadmap.md` — P0 → P3 milestone mapping
- ADR-008 — daemon concurrency model (deferred from this ADR)
- ADR-018 — validator/honeypot model choice (supersedes the model row)
- ADR-019 — `llama-cpp-python` integration (supersedes the binding-library row)
