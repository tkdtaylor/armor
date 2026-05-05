# Tech Stack

**Project:** armor
**Last updated:** 2026-05-05

## Core stack

| Layer | Technology | Rationale |
|-------|-----------|-----------|
| Language | Python 3.12 | Library reusability is a primary goal — every agent framework worth wrapping (Anthropic SDK, LangChain, LlamaIndex) is Python-first. Iteration speed on detector heuristics matters more than raw runtime cost. (ADR-002) |
| Packaging | `uv` | Modern, fast, lockfile-driven. Becoming the standard. |
| Runtime architecture | Long-lived daemon + tiny clients (Unix socket) | Avoids the ~50–100 ms per-hook cold-start tax of `python3 -c …` invocations. (ADR-002) |
| Inference engine | `llama.cpp` via `llama-cpp-python` | CPU-friendly, supports Q4 quantization, broad model coverage. |
| Validator/honeypot model | TBD by benchmark — candidates: Qwen 2.5-1.5B, Phi 3.5-mini, Llama 3.2-1B, Gemma 2-2B | Selection is itself a v1 task with an evaluation harness. (ADR-003) |
| Pattern matcher | `pyahocorasick` | Single-pass multi-pattern matching scales linearly in input length, regardless of canary set size. |
| Session store | SQLite (stdlib) | File-backed, no external service, durable across daemon restarts. (ADR-004) |
| Container | Docker, multi-stage build, Debian slim base | Target image <2 GB with quantized model bundled. (ADR-006) |
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
- Model selection (Qwen / Phi / Llama / Gemma) is gated by the v1 benchmark task — do not lock the choice in the Dockerfile until that task is done.
