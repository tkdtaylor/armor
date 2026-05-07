# ADR-019 — llama-cpp Integration & Daemon Cold-Start Instrumentation

**Date:** 2026-05-05
**Status:** Accepted
**Relates to:** ADR-001, ADR-018, Task 017

## Context

armor needs to ship the quantized LLM chosen in ADR-018 (Qwen3-0.6B-Q4_K_M)
bundled with the daemon, running inference locally without outbound network
calls. Task 017 integrates `llama-cpp-python` into the daemon bootstrap path,
measures cold-start latency, and documents deployment expectations.

## Decision

### Inference Runtime: llama-cpp-python

**Choice:** Use the pre-built binary wheel of `llama-cpp-python>=0.2.45` from
PyPI, pinned in `pyproject.toml` as a runtime (not dev-only) dependency.

**Rationale:**
1. **Pre-built wheel availability** — PyPI ships pre-compiled wheels for
   Python 3.12 on Linux x86_64 (the deployment target). No build-time C
   compilation required in the runtime container.
2. **Reduced build time** — Multi-stage Dockerfile: builder stage installs the
   wheel; runtime stage copies only the installed packages and the model.
   No build tools in the final image.
3. **Minimal runtime image** — The wheel is statically compiled; we do not
   vendor BLAS or OpenMP. All dependencies are bundled in the wheel.

**Not chosen:**
- Building from source (C build-time overhead in container, larger image).
- GPU support (`n_gpu_layers > 0` deferred to v0.4; CPU-only is simpler and
  covers the single-user Claude Code session target).

### CPU-Only Inference

**Configuration:** All LLM inference uses `n_threads=1` and `n_gpu_layers=0`.
- `n_threads=1` — Explicit single-threaded binding; matches deployment floor
  (1 CPU, 4 GB RAM). Multi-threaded inference would compete with other daemon
  tasks and exceed the floor's parallelism budget.
- `n_gpu_layers=0` — GPU support is not required for the v0.3 release. If
  added later, it will be opt-in via configuration.

### Cold-Start Instrumentation

**Implementation:** `DaemonServer.__init__()` records a start time, then
`DaemonServer.start()` measures elapsed time after initialization completes.
The elapsed milliseconds are logged to INFO level as:

```
armor daemon cold-start: <NNN> ms
```

**Baseline measurement (2026-05-05, single machine):**

| Configuration | Cold-Start (ms) |
|---|---:|
| No LLM (`ARMOR_DISABLE_LLM=true`) | 36 |
| With Qwen3-0.6B-Q4_K_M loaded | 712 |

The "with LLM" measurement includes:
- Instantiation of `llama_cpp.Llama`
- Self-test forward pass (input: "Say 'ok' in one word.", 10 max tokens)
- Database migrations
- Detector registry initialization
- Session store setup
- Socket binding

All timing is single-threaded, no concurrency.

**SLA implications:** The user-facing latency of the first armor check is
dictated by whether the daemon is already running:
- **Daemon pre-started** — Check latency is milliseconds (socket roundtrip +
  inference).
- **Daemon not pre-started** — Cold-start adds ~700 ms. The hook may choose to
  start the daemon at user session open time (e.g., on Claude Code launch) to
  amortize this cost.

### Multi-Stage Docker Image

**Stages:**

1. **Builder stage** (`FROM python:3.12-slim as builder`)
   - Installs build dependencies (gcc, g++, cmake)
   - Copies source code and runs `pip install --user .`
   - This stage includes the full llama-cpp-python build
   - Total builder size: ~2 GB (includes compiler toolchain)

2. **Runtime stage** (`FROM python:3.12-slim`)
   - Copies only `/root/.local/` from builder (the installed wheels)
   - Copies model file from `docker/model.gguf` → `/models/active.gguf`
   - Creates unprivileged `armor` user (UID 999)
   - Entrypoint: `armor daemon --model /models/active.gguf`

**Image size (measured 2026-05-05):**

| Component | Size |
|---|---:|
| Base `python:3.12-slim` | ~145 MB |
| Installed wheels (llama-cpp-python + deps) | ~150 MB |
| Model (Qwen3-0.6B-Q4_K_M.gguf) | ~462 MB |
| **Total runtime image** | **~757 MB** |

**Target:** <2 GB (target achieved; 757 MB).

### Environment Variable Defaults

`ARMOR_DISABLE_LLM` defaults to `false` (as of task 017). When `false`:
- If `--model <path>` is provided on the CLI, load that file.
- Else if `/models/active.gguf` exists (Docker-only), load it.
- Else skip LLM loading (daemon boots cleanly in static-detector-only mode).

When `ARMOR_DISABLE_LLM=true`:
- Skip LLM loading entirely. Daemon boots in <50 ms.

### No Outbound Network Calls

**Invariant enforced:** The daemon code path (`src/armor/daemon/`) must never
import `requests`, `httpx`, `urllib3`, or similar networking libraries. A
mechanical fitness check (`tests/fitness/no_outbound_network.py`) is part of
the CI gate.

**Rationale:** armor is a security layer. If the daemon ever exfiltrates data
(intentionally or via supply-chain compromise), it defeats the trust model.
All inference is local; all telemetry is opt-in and lives in a separate,
explicitly gated module.

## Implementation Notes

### Self-Test Forward Pass

When the model is loaded, `armor.llm.loader` runs a forward pass with the input
"Say 'ok' in one word." If this fails (model file corrupt, OOM, etc.), the
daemon exits with code 78 (configuration error).

### Prompt Discipline

Qwen3 instruct models emit a `<think>...</think>` reasoning block at the start
of every response. To avoid wasting context and leaking intermediate canary
values:
- **Validator and honeypot prompts** will append `/no_think` to the user turn
  (Qwen3's documented opt-out).
- The response parser will strip residual `<think>` blocks if present.
- This discipline is enforced in the prompt builders (not caller-side).

(Task 018 and 019 will implement the validator and honeypot prompt builders
and call-sites; Task 017 just loads the model and prepares the session.)

### Reproducing the Measurements

```bash
# 1. Download the model (462 MB)
MODEL=$(uv run hf download lmstudio-community/Qwen3-0.6B-GGUF \
  Qwen3-0.6B-Q4_K_M.gguf --print-only | grep "^path=") && echo "${MODEL#path=}"

# 2. Run daemon with explicit model path
ARMOR_DISABLE_LLM=false timeout 10 uv run armor daemon \
  --socket /tmp/test.sock --db /tmp/test.db --model "$MODEL_PATH" \
  2>&1 | grep "cold-start"

# 3. Build and measure Docker image
cp "$MODEL_PATH" docker/model.gguf
docker build -t armor:latest docker/
docker images armor:latest --format "{{.Size}}"
```

## Related Decisions

- **ADR-001** — Foundational stack: Python 3.12, daemon architecture, placeholder for the inference runtime (this ADR locks in `llama-cpp-python` as the binding library and supersedes the placeholder for that row).
- **ADR-018** — Model choice: Qwen3-0.6B-Q4_K_M (this ADR integrates the
  chosen model).
- **Task 017** — Implementation task (this ADR documents the outcome).
- **Task 018** — Validator prompt design (uses the loaded session).
- **Task 019** — Honeypot prompt design (same loaded session, different
  system prompt).

## Deferred / Future Work

| Item | Reason | Target |
|---|---|---|
| GPU inference (`n_gpu_layers > 0`) | Adds CUDA/ROCm dependency; deployment floor doesn't require it | v0.4 |
| Quantization variants (e.g., Q3_K) | Q4_K_M is the sweet spot for accuracy/speed/size | v0.4 |
| Model swap at runtime | Daemon is long-lived; reloading the model cleanly is complex | v0.5 |
| Telemetry (latency histograms, error rates) | Out-of-band via opt-in, separate module; not in daemon critical path | v0.4 |
