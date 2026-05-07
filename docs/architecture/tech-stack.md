# Tech Stack

**Project:** armor
**Last updated:** 2026-05-06

## Core stack

| Layer | Technology | Rationale |
|-------|-----------|-----------|
| Language | Python 3.12 | Library reusability is a primary goal — every agent framework worth wrapping (Anthropic SDK, LangChain, LlamaIndex) is Python-first. Iteration speed on detector heuristics matters more than raw runtime cost. (ADR-001) |
| Packaging | `uv` | Modern, fast, lockfile-driven. Becoming the standard. |
| Runtime architecture | Long-lived daemon + tiny clients (Unix socket) | Avoids the ~50–100 ms per-hook cold-start tax of `python3 -c …` invocations. (ADR-001 / ADR-008) |
| Inference engine | `llama.cpp` via `llama-cpp-python` | CPU-friendly, supports Q4 quantization, broad model coverage. (ADR-019) |
| Validator/honeypot model | `lmstudio-community/Qwen3-0.6B-GGUF` (Q4_K_M, Apache 2.0) | Selected by the dual-corpus benchmark; same weights, two system prompts. (ADR-018) |
| Embedding model (topic coherence) | `all-MiniLM-L6-v2` ONNX (~23 MB), via `onnxruntime` + HF `transformers` tokenizer | Local, deterministic, ~10–30 ms per call; fits the no-outbound-network invariant. (ADR-026) |
| Pattern matcher | `pyahocorasick` | Single-pass multi-pattern matching scales linearly in input length, regardless of canary set size. (ADR-001) |
| Session store | SQLite (stdlib) | File-backed, no external service, durable across daemon restarts. Holds session-state-machine fields (current_state, risk_score, last_signal_at) and the per-session rolling-output buffer. (ADR-001 / ADR-024 / ADR-025) |
| Container | Docker, multi-stage build, Debian slim base | Target image <2 GB with quantized model bundled. (ADR-001) |
| IPC | Unix domain socket (length-prefixed JSON), HTTP fallback for non-local clients | Sub-millisecond per-call overhead for the hook path. |

## Development tooling

| Tool | Purpose |
|------|---------|
| Git | Version control |
| `uv` | Dependency management, virtualenv, scripts |
| `ruff` | Lint + format (replaces flake8, isort, black) |
| `pytest` + `pytest-cov` | Unit tests + coverage |
| `pre-commit` | Pre-commit lint/format hook |
| `mypy` | Static type checking (strict mode) |
| Docker + Docker Compose | Containerized dev + deployment |
| GitHub Actions | CI (lint, test, container build) |

## Testing

| Tool | Scope |
|------|-------|
| `pytest` | Unit tests of individual detectors |
| `pytest` (parametrized over a corpus) | **Red-team eval harness** — a curated YAML/JSONL corpus of attacks (one row per attack) drives a single test that asserts each is blocked. New attacks land as new corpus entries, not new test functions. |
| `pytest` integration tests | Daemon boot + IPC round-trip + multi-turn session flow |
| Manual hook test (Claude Code session) | Smoke test against a live agent — gate before each release |

## Notes

- `llama-cpp-python` ships pre-built wheels for common platforms. If a build is needed, the container is the canonical environment — host builds are best-effort.
- `pyahocorasick` is C-extension; pure-Python fallback exists for environments where the wheel can't install (e.g. edge cases in CI).
- The validator/honeypot weights and the topic-coherence ONNX model are baked into the runtime image at build time. Neither is fetched at daemon start; the daemon code path makes no outbound network calls.
