# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

### Changed

### Fixed

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
