# Performance and benchmarks

This document covers the performance characteristics of armor's detector pipeline
and how to measure them in your environment.

## Measured performance (preview, 2026-05-05)

Numbers below are local measurements on x86_64 with Intel Core Ultra 9 185H, 62 GiB RAM,
`llama.cpp` CPU inference, single-threaded. These are preview measurements; treat as
illustrative, not a production guarantee.

| Metric | Value | Source |
|---|---|---|
| Validator true-positive rate (jailbreak corpus) | **96%** (48/50; Wilson 95% CI 86.5%–98.9%) | `tests/bench/llm_selection/run.py` |
| Validator overall accuracy (100-row dual corpus) | **83%** (83/100; Wilson 95% CI 74.5%–89.1%) | `tests/bench/llm_selection/run.py` |
| Honeypot canary-emission rate (any match) | **96.7%** (29/30; Wilson 95% CI 83.3%–99.4%) | `tests/bench/llm_selection/run.py` |
| Honeypot canary-emission rate (strict format) | **66.7%** (20/30; Wilson 95% CI 48.8%–80.8%) | `tests/bench/llm_selection/run.py` |
| Validator P95 latency | **≤ 500 ms** (empirical 486 ms steady-state) | `tests/fitness/test_llm_p95_latency.py`; see [ADR-023](architecture/decisions/023-llm-budget-soft-fail.md) |
| Honeypot P95 latency | **≤ 16,000 ms** (empirical ~11,875–15,500 ms steady-state) | `tests/fitness/test_llm_p95_latency.py`; see [ADR-023](architecture/decisions/023-llm-budget-soft-fail.md) |
| Daemon cold-start | **≤ 5,000 ms** | `tests/fitness/test_cold_start_budget.py` |
| Model size (Qwen3-0.6B Q4_K_M) | **~462 MB** GGUF | [ADR-018](architecture/decisions/018-validator-model-choice.md) |

## Red-team corpus coverage

**Single-shot attack families** (804 total rows across 7 families):
- Direct injection: 106 rows
- Exfiltration: 116 rows
- Indirect injection: 104 rows
- Jailbreak: 149 rows
- Obfuscation: 100 rows
- Tool abuse: 110 rows
- Probe attacks: 119 rows

**Multi-turn scenarios** (42 total rows):
- Chunked exfiltration attacks: 11 rows
- Complex multi-turn scenarios: 31 rows

## Reproduce the benchmark

To measure validator + honeypot accuracy and latency in your environment:

```bash
# Pull the model
uv run hf download lmstudio-community/Qwen3-0.6B-GGUF Qwen3-0.6B-Q4_K_M.gguf

# Run the dual-corpus benchmark
MODEL=$(uv run hf download lmstudio-community/Qwen3-0.6B-GGUF Qwen3-0.6B-Q4_K_M.gguf --quiet)
uv run python -m tests.bench.llm_selection.run \
  --model "$MODEL" --quant Q4_K_M --license Apache-2.0 \
  --output artifacts/bench-results/results.json
```

To compare other quantization levels or model candidates, pass different `--model`
and `--quant` values. The full benchmark supports flags like `--n-threads`,
`--n-gpu-layers`, `--mode`, and `--max-rows`. See `tests/bench/llm_selection/run.py`
for all options.

## Latency measurement methodology

P95 latencies are computed across timed inference rows on the corpus, with the
**first 1–2 rows discarded as warmup** (per task 092). The first inference call into
`llama-cpp` per process incurs one-time costs (KV-cache allocation, page-fault-in on
GGUF weights, allocator initialization) that aren't representative of steady-state.
Both the 100-row full bench and 20-row smoke variant warm up first, so they report
steady-state P95.

See `tests/fitness/_llm_p95_helpers.py` for implementation and
[ADR-023 §Measurement methodology](architecture/decisions/023-llm-budget-soft-fail.md)
for the rationale.

## Fitness checks

Latency budgets are re-checked on every `make fitness` run (or `make fitness-smoke`
for a quick smoke test). These are mechanical assertions on the live codebase:

```bash
make check        # lint + type + test + eval (includes fitness-smoke)
make fitness-full # full fitness suite (can take 5–10 minutes)
```

See [docs/spec/fitness-functions.md](spec/fitness-functions.md) for the complete list
of fitness invariants.
