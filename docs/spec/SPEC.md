# armor — Authoritative Spec

**Project:** armor
**Last updated:** 2026-05-07

## What this directory is

`docs/spec/` is the **authoritative current-state snapshot** of armor. It answers the question:

> "If the code were deleted tomorrow, what would I need to write down to rebuild it?"

The spec is dual-natured:

- **Output of current sessions** — every completed task that changes externally-observable behavior, the data model, an interface, or configuration must update the relevant spec file in the same commit.
- **Input to future sessions** — used for onboarding, drift audits against the code, and (in the limit) regenerating the codebase from scratch.

The code is one *realization* of this spec. If the spec and code disagree, one of them is wrong — fix the wrong one in that same change.

## Spec vs. ADRs vs. overview

| Doc | Purpose | Lifecycle |
|-----|---------|-----------|
| [`docs/spec/`](.) | What the system **does and is** today | Snapshot — supersede in place, never append |
| [`docs/architecture/decisions/`](../architecture/decisions/) | **Why** decisions were made | Append-only history; ADRs can be superseded by later ADRs |
| [`docs/architecture/overview.md`](../architecture/overview.md) | Narrative tour of the system | Snapshot, but optimized for human reading |
| [`docs/architecture/diagrams.md`](../architecture/diagrams.md) | Visual structure and flows | Snapshot, part of the spec |

When a later ADR supersedes an earlier one (for example, ADR-018 supersedes the model row of ADR-001), the spec just reflects the new choice. The ADRs preserve the reasoning trail; the spec preserves the current truth.

## The spec files

| File | Covers | Read this when |
|------|--------|---------------|
| [behaviors.md](behaviors.md) | What the system does — detection categories, block/pass/forensic-capture semantics, session escalation rules | You need to know what should happen when X |
| [architecture.md](architecture.md) | System structure — containers, components, source paths, cross-container edges (paired with `docs/architecture/diagrams.md`) | You need to know what the deployable units and modules are, or audit drift against the code |
| [data-model.md](data-model.md) | Detector verdicts, session state, canary catalogue, forensic incident records | You need to know what data exists and how it's structured |
| [interfaces.md](interfaces.md) | The `armor` CLI, the daemon IPC protocol, the Python SDK surface, hook contracts | You need to know what calls into or out of the system |
| [configuration.md](configuration.md) | Detector thresholds, hook profile env vars, model selection, container limits | You need to know what's tunable |
| [fitness-functions.md](fitness-functions.md) | Executable architectural invariants — what `make fitness` checks (no network in daemon, no canary leak, layering, complexity, coverage) | You need to know which invariants are mechanically verified, or propose a new one |

## Maintenance rules

1. **Update in the same commit as the code change.** A task that changes behavior is not done until `behaviors.md` reflects it.
2. **Supersede in place. Never append.** When a decision changes, rewrite the spec entry — don't add a "previously this was X" note. The ADR carries that history.
3. **No future tense.** The spec describes what *is*, not what *will be*. Roadmap and per-task planning are operator-private and not part of the public repo.
4. **No implementation rationale.** "We chose X because Y" belongs in an ADR. The spec just says "uses X."

## Project summary

`armor` is a defense-in-depth security layer for LLM agents — Python library + Docker container — that detects prompt injection, exfiltration via canary tokens, encoding/obfuscation, jailbreaks, tool/API abuse, and multi-turn session attacks. It runs as a long-lived daemon and integrates with Claude Code via shell hooks and with custom agents as an importable library.

## Top-level invariants

- **Every check returns a `Verdict` of `pass | block | advisory`.** No detector returns side-channel data; no detector mutates payload. Verdicts compose via the pipeline (defined in `behaviors.md`).
- **The daemon never makes outbound network calls by default.** All inference is local. The validator LLM and the pattern engines must work without internet. (Outbound calls are gated behind an explicit opt-in config flag for telemetry, not default-on.)
- **Hook clients never bypass the daemon.** Detectors are not callable directly from a hook; the hook always speaks to the daemon. Centralization keeps detector ordering, version, and config consistent.
- **Forensic logs never contain the canary value verbatim** — they reference canary IDs. This prevents the forensic log itself from becoming a canary-leak channel if it's ever exposed.
- **Block decisions are deterministic given (input, output, session_state).** No randomness in the verdict path. This makes regressions reproducible from the corpus.

## Non-goals

- Replacing model-side safety training. armor is a perimeter; the model still refuses on its own.
- Generic content filtering (profanity, NSFW, copyright). Out of scope — the scope is *security*, not policy.
- Sub-millisecond hot paths inside a high-QPS API. Target is a single user's Claude Code session and small agent fleets.
- Detection of every theoretical attack. The corpus defines what we claim to catch; new attack classes land as corpus entries + (when needed) new detectors.
