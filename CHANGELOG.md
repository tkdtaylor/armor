# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

### Changed

### Fixed

## [1.0.0] — 2026-05-07

First public release. Adds the operator-facing release surface (CLI export, security disclosure procedure, contributor docs), reconciles configuration with the post-FSM data model, and removes pre-rebrand and pre-rotation literals from the public tree.

### Added

- **`armor incidents export`** CLI subcommand for exporting forensic records to JSONL with operator-supplied filters (session, time window, verdict).
- **SECURITY.md** disclosure policy with a structured reporting procedure, numeric SLA, public-issue guard, and private-channel anchor (Security Advisory + email).
- **Contributor scaffolding**: `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `.github/ISSUE_TEMPLATE/`, `.github/PULL_REQUEST_TEMPLATE.md`, `.github/dependabot.yml`, and the `.github/workflows/release.yml` release workflow.
- **Honeypot P95 latency fitness check** at the post-ADR-023 16,000 ms budget (ADR-023 supersedes the v0.4 12,000 ms placeholder).
- **`scripts/fitness.sh`** wired into CI so the fitness suite runs on every PR.

### Changed

- **Canonical contact emails** moved to `taylorguard.me`: general / security / Code-of-Conduct contact is `tools@taylorguard.me`; commercial-license inquiries go to `licensing@taylorguard.me`.
- **`armor.toml` schema** rewritten for the post-FSM model: session thresholds, cooldown decay, signal weights, validator/honeypot budgets, and rolling-buffer / topic-coherence keys are now first-class.
- **Architecture component table** added to `docs/architecture/overview.md` enumerating every runtime module the daemon ships with.
- **Architecture diagrams** refreshed for v1.0: HoneypotGate, pipeline orchestrator, logging sink, and rolling buffer added to the runtime-flow diagram.
- **Roadmap and per-task planning are operator-private** and no longer part of the public repo. The build-process workflow itself (TDD spec-first, atomic commits, ADR + test-spec + task-completion as separate commits) remains documented in `CONTRIBUTING.md` and `CLAUDE.md`.
- **Public git history** rewritten and squashed to seven milestone commits with a single canonical author identity (the GitHub noreply). Pre-rewrite history preserved on the operator's local disk via a `--mirror` clone; not part of the public repo.

### Fixed

- **Pre-rotation AWS-shape canary literals** removed from the tracked tree. The synthetic shapes that remain inside honeypot bait have a defensive purpose; the AWS-published example `AKIAIOSFODNN7EXAMPLE` is on scanner allowlists by design.
- **Pre-rebrand contact-email literals** purged from every tracked file outside the historical exclusion list.
- **Honeypot p95 latency regression** above the v0.4 placeholder budget — fixed and a new fitness gate set at the ADR-023 budget.
- **Spec drift cluster** across `docs/spec/configuration.md`, `data-model.md`, `behaviors.md`, and `interfaces.md` reconciled in one pass.
- **Fitness pytest discovery** — modules renamed so pytest collects them by default; `structured_logs` test renamed to follow the same convention.

## [0.4.0] — 2026-05-06

Initial v0.4 release: multi-turn session attacks, LLM validator in container.

### Added

- **Session state machine** (ADR-024): Normal → Watching → Elevated → High → Blocked with cooldown rules for multi-turn attack detection.
- **Rolling output entropy tracking** (ADR-027): per-session buffers aggregate partial exfiltration across turns.
- **Topic coherence detector** (ADR-026): sentence-transformer ONNX embedding detects mid-session context shifts as attack signals.
- **Multi-turn scenario support** (ADR-027): eval corpus now includes long-lived session test cases.
- LLM P95 latency fitness check (validator ≤ 500 ms, honeypot ≤ 12,000 ms).
- Daemon cold-start fitness check (socket acceptance ≤ 5 s).

### Changed

### Fixed

## [0.3.0] — 2026-05-06

Initial v0.3 release: validator LLM in the container.

### Added

- **Validator LLM integration** (ADR-018 / ADR-019): Qwen3-0.6B-Q4_K_M selected via empirical benchmark; baked into multi-stage Docker image.
- **Honeypot system prompt** (ADR-019): shares validator weights, answers as if canary credentials were available.
- **Jailbreak template detector** (ADR-022): static + LLM hybrid detects DAN, developer-mode, fictional-framing attacks.
- **LLM call budgeting** (ADR-023): soft-fail on timeout (validator 500ms budget, honeypot 12s budget).

### Changed

### Fixed

## [0.2.0] — 2026-05-05

Initial v0.2 release: encoding, obfuscation, and tool-call protection.

### Added

- **Encoding-request detector** (Task 009): detects base64/hex/rot13/encrypt keywords in user input.
- **Output entropy analyzer** (Task 010): opportunistic decode-and-rescan on high-entropy output.
- **Install-time canary generation** (Task 015, ADR-010 rewritten): per-installation values, runtime injection, no hardcoded values.
- **URL/IP/email extractors** (Task 011): with destination whitelist support.
- **Command-injection denylist** (Task 012): filesystem destruction, credential reads, container escape patterns for Bash.
- **Parameter tampering check** (Task 013): schema-driven tool-call parameter validation.
- **Eval harness** (Task 014): corpus-driven pytest parametrization with CI gate.
- **Daemon subprocess integration tests** (Task 030): replaces pytest-asyncio hangs with subprocess-based per-test isolation.
- **Corpus canary substitution** (Task 031): `{canary:<id>}` template references resolved at load time.

### Changed

### Fixed

## [0.1.0] — 2026-05-05

Initial v0.1 release: foundation and P0 detection.

### Added

- **Project setup** (Task 001): uv, ruff, pytest-cov, pre-commit, Makefile, CI skeleton.
- **Daemon skeleton** (Task 002): Unix socket IPC, request/response loop, structured logging.
- **Detector trait** (Task 003): pipeline runner, Verdict aggregation.
- **Static detectors** (Task 004): instruction-override, role-play hijack, system-prompt extraction.
- **Canary catalogue** (Task 005): Aho-Corasick scanner, generator for common patterns (AWS keys, API tokens, etc.).
- **SQLite session store** (Task 006): forensic incident table, quarantined payload table with AES-256 encryption.
- **armor CLI** (Task 007): daemon control, check commands, Claude Code hook installer.
- **End-to-end demo** (Task 008): proves detection and forensic logging work.

### Changed

### Fixed
