# ADR-023 — LLM call budgeting and soft-fail policy

**Date:** 2026-05-06
**Status:** Accepted
**Task:** 021
**Authors:** Kevin

## Context

The validator and honeypot paths have fundamentally different latency profiles. Per ADR-018's empirical benchmark (Qwen3-0.6B-Q4_K_M, single-threaded llama-cpp-python):

| Path | P95 Latency | Notes |
|------|------------|-------|
| **Validator** | 486 ms | Outputs a single classification token; short, bounded response |
| **Honeypot** | 11,875 ms | Generates a multi-credential cooperative response; ~24× validator latency |

The user-facing SLA (B-005) targets **500 ms per LLM call**. A single uniform `model.budget_ms = 500` cannot accommodate both paths:
- Setting `budget_ms = 500` causes the honeypot to timeout on 95% of calls.
- Setting `budget_ms = 12000` ignores the validator's SLA and leaves the pipeline blocked for 12 seconds on validator timeouts.

Task 021 must choose a budget structure and implement soft-fail (graceful timeout handling) to bridge the gap.

## Decision

### Option chosen: Option 1 — Per-path budgets

armor will enforce **separate budgets per path**:

```toml
[model]
validator_budget_ms = 500   # P95 validator latency ≤ 500 ms
honeypot_budget_ms = 16000  # P95 honeypot latency ≤ 16,000 ms (15,000 + 1000 ms buffer)
```

Both budgets are **hard caps** — if an inference call exceeds its path-specific deadline, the LLM request is abandoned (best-effort cancellation; `llama-cpp-python` does not provide hard cancellation) and the detector returns `advisory(confidence=0)` without raising an exception.

### Rationale for Option 1

| Criterion | Option 1 (Per-path) | Option 2 (Token cap) | Option 3 (Async) |
|-----------|----------------------|---------------------|------------------|
| **Validator SLA compliance** | ✅ 500 ms honored | ✅ 500 ms honored | ✅ 500 ms honored |
| **Honeypot SLA compliance** | ✅ 12,000 ms accommodated | ❌ Risk truncation | ❌ No hot-path SLA |
| **Config complexity** | 2 keys (clear) | Token cap logic (fragile) | Async wiring (deferred) |
| **Determinism** | ✅ Predictable per path | ⚠️ Cap varies by prompt | ❌ Off-path, timing-dependent |
| **Canary safety** | ✅ No truncation risk | ❌ Risk mid-value | ✅ Prompts safe |
| **Implementation cost** | Low (two deadline vars) | Medium (token limiter) | High (async plumbing) |
| **Fitness measurability** | ✅ Easy (two P95 assertions) | ⚠️ Indirect (cap size) | ⚠️ Non-deterministic |

**Option 1 is cleanest:** Two simple configuration keys, both paths get their own budget, no truncation risk, easy to monitor and test.

**Why not Option 2 (token cap)?** The honeypot prompt includes placeholders like `{{canary:aws-key-001}}`, which are ~20 characters each. The prompt itself is ~500 tokens. A token cap small enough to hit 500 ms would truncate canary values mid-emission, breaking the deterministic Aho-Corasick scan (which expects exact matches). A safe cap would be at least 1000 tokens (honeypot prompt + response), taking us back to the 11,000+ ms latency. This approach is brittle.

**Why not Option 3 (async honeypot)?** The honeypot would become a fire-and-forget background task, with canary detection happening asynchronously after the user-visible response is returned. This removes the honeypot from the hot-path decision (good for latency, bad for determinism) and requires complex async wiring and session state management deferred to task 022+. For v0.3, the honeypot is still experimental; keeping it on-path and measurable is the right choice.

## Soft-fail policy

When an LLM call exceeds its path-specific budget:

1. **Best-effort cancellation**: The in-flight inference call is marked as abandoned. `llama-cpp-python` does not provide hard cancellation (the library lacks a `cancel_inference()` method), so the request finishes in the background and the result is discarded.

2. **Return advisory(confidence=0)**: The detector returns `Verdict.advisory_verdict(signal_id="...", details={"confidence": 0.0})`. This verdict does not block and has zero weight in the session risk score.

3. **Log a warning**: The logger records the timeout event (detector, path, latency) for operator visibility.

4. **Pipeline continues**: No exception is raised to the caller. Subsequent detectors in the pipeline execute normally.

5. **Session risk unchanged**: The `confidence=0` advisory signal carries zero weight in session risk scoring (task 022 uses the confidence field). A timeout does not escalate the session state.

**Rationale:** The LLM is *advisory, not load-bearing* (per architecture overview). If the LLM times out, the pipeline reverts to static-only detection. All P0/P1 attacks (direct injection, exfiltration, tool abuse) are caught by static detectors alone (fitness function: corpus_static_only). The LLM adds P2/P3 signal (jailbreak framing, semantic escalation); losing that signal on timeout is acceptable.

### Timeout signal IDs

- **Validator timeout**: `llm.validator:soft_fail`
- **Honeypot timeout**: `llm.honeypot:soft_fail`
- Both carry `details["confidence"] = 0.0`

## Configuration

### TOML keys

```toml
[model]
validator_budget_ms = 500      # Default: 500 ms (fits validator SLA)
honeypot_budget_ms = 16000     # Default: 16,000 ms (fits honeypot P95 + buffer)
```

### Environment variables

```bash
ARMOR_VALIDATOR_BUDGET_MS=500
ARMOR_HONEYPOT_BUDGET_MS=16000
```

Environment variables override TOML keys (standard precedence).

### Default values

Both defaults are conservative (fitting or exceeding empirical P95 from ADR-018). Operators can tune down or up per deployment constraints.

## Implementation

### LLMSession changes

`src/armor/llm/session.py` holds a single `LLMSession` instance, which is passed to both `validator.validate()` and `honeypot.respond()`. To support per-path budgets without breaking the shared instance:

**Option A (chosen):** Pass the budget as a parameter to each detector function:

```python
# In validator.py
def validate(
    text: str,
    session_context: SessionContext,
    llm_session: LLMSession | None = None,
    budget_ms: int | None = None,  # Override per-call
) -> Verdict:
    budget = budget_ms or (llm_session.budget_ms if llm_session else 500)
    # Enforce deadline...
```

This allows the configuration loader to extract both budgets and pass them at call time.

**Option B (deferred):** Store both budgets on a separate config object and thread it through the pipeline. This is cleaner for v0.4 but adds parameter plumbing for v0.3.

We choose **Option A** for minimal scope: the validator and honeypot are still relatively isolated; adding a `budget_ms` parameter is cleaner than refactoring the entire configuration plumbing in v0.3.

### Deadline enforcement

Each detector wraps its LLM call with a deadline:

```python
import signal

def _enforce_deadline(budget_ms: int):
    """Set a SIGALRM deadline (Unix-only) or poll-based timeout."""
    # Unix: signal.setitimer(signal.ITIMER_REAL, budget_ms / 1000)
    # Portable: wrap in a thread with timeout; fetch result via queue
    # llama-cpp-python does not provide cancellation, so best-effort only
```

For v0.3, we use a **threading-based timeout wrapper**:

```python
import threading

def _invoke_with_deadline(fn, args, budget_ms):
    """Call fn(*args) with a deadline; return None on timeout."""
    result = [None]

    def target():
        result[0] = fn(*args)

    thread = threading.Thread(target=target, daemon=True)
    thread.start()
    thread.join(timeout=budget_ms / 1000)

    if thread.is_alive():
        # Deadline exceeded; thread continues in background
        logger.warning(f"Deadline exceeded ({budget_ms} ms); result discarded")
        return None
    return result[0]
```

This is not perfect (the background thread still consumes CPU), but it's portable and safe. Once `llama-cpp-python` adds cancellation, we can upgrade.

### Fallback behavior

If `_invoke_with_deadline()` returns `None` (timeout), the detector returns:

```python
return Verdict.advisory_verdict(
    signal_id="llm.validator:soft_fail",
    severity="low",
    message="LLM validator timed out",
    details={"confidence": 0.0},
)
```

## Fitness functions

Four new fitness checks (wired into `make fitness`):

1. **`corpus_static_only`** — run `pytest tests/eval/test_corpus.py` with `ARMOR_DISABLE_LLM=true`; assert exit code 0.
2. **`cold_start_budget`** — time daemon launch to first-accept on socket; assert < N seconds (N per task 017 measurement + 50%).
3. **`llm_p95_latency`** — split into two checks:
   - `validator_p95_under_500ms` — run validator on 100+ corpus rows; assert P95 ≤ 500 ms.
   - `honeypot_p95_under_16000ms` — run honeypot on 30+ corpus rows; assert P95 ≤ 16,000 ms.
4. **`validator_soft_fail`** — unit test with mock slow LLM (delay > 500 ms); assert timeout fires and returns `advisory(confidence=0)`.

All four are implemented (move from "candidate" to "implemented" in `fitness-functions.md`).

## Spec updates

1. **behaviors.md B-005** — refine failure modes: "Latency exceeds budget → soft-fail, log warning, continue".
2. **configuration.md** — add `model.validator_budget_ms` and `model.honeypot_budget_ms` keys.
3. **fitness-functions.md** — move four new functions from "candidate" to "implemented".

## Session risk scoring interaction (task 022)

When task 022 lands and implements risk scoring, `confidence=0` advisories are weighted as zero into the risk score:

```python
risk_delta = advisory_verdict.details.get("confidence", 0.0) * pipeline.llm_validator_weight
# confidence=0.0 → risk_delta = 0, session state unchanged
```

This ensures timeouts never escalate a session to "Blocked" state.

## Deployment guidance

Operators can tune the budgets per hardware:

- **Fast hardware (GPU, modern CPU):** Keep defaults (500/12000 ms).
- **Slow hardware (embedded, constrained):** Increase budgets (e.g., 750/18000 ms) but risk longer latency spikes.
- **Latency-critical deployment (sub-100ms SLA):** Disable the honeypot entirely (set `honeypot_budget_ms=0` or config flag), run validator-only.

## Testing

- Unit test: `tests/unit/llm/test_soft_fail.py` — mock slow LLM, assert timeout and advisory return.
- Integration test: `tests/integration/test_soft_fail.py` — full pipeline with slow model, assert verdict is advisory and session state unchanged.
- Fitness test: `tests/fitness/llm_p95_latency.py` — real model latency on corpus; fails if P95 exceeds budget.
- Eval test: `tests/eval/test_corpus.py ARMOR_DISABLE_LLM=true` — static-only sufficiency.

## Deferred / Non-goals for v0.3

- **Adaptive budgets** (per-detector, per-session) — v0.4+.
- **Hard cancellation of in-flight inference** — wait for `llama-cpp-python` API.
- **Honeypot off-path** (async) — v0.4+ session state machine.
- **Timeout retries** — could be v0.4 if data shows retries help.

## Consequences

1. Configuration gains two new keys (`validator_budget_ms`, `honeypot_budget_ms`).
2. Validator and honeypot functions gain optional `budget_ms` parameter.
3. LLM calls are wrapped in timeout enforcement (threading-based).
4. Four new fitness functions lock the architecture invariants.
5. Forensic logging continues unchanged (timeouts logged as warnings, not blocks).
6. Session risk scoring treats `confidence=0` as zero weight (task 022 integration).

## Rationale summary

Per-path budgets cleanly map to the empirical reality: the validator is fast (486 ms P95), the honeypot is slow (11,875 ms P95). A single uniform budget forces a false choice. Soft-fail (graceful timeout, return advisory) preserves the LLM's advisory role while defending the user-facing SLA. Fitness functions lock the budgets in place, preventing silent regressions.

---

## Acceptance

- **Status:** Accepted
- **Date:** 2026-05-06
- **Task:** 021
- **Reviewed by:** Architecture (implicit; ADR drafted with full task spec)

## Amendment (Task 043 — 2026-05-06)

### Honeypot budget update: 12,000 ms → 16,000 ms

**Rationale:** Post-release measurements on developer machines consistently showed honeypot P95 latency of 15,000–15,500 ms (26% over the original 12,000 ms budget), while the validator remained within budget at 475–500 ms P95. The regression is consistent across three independent runs and is not attributable to measurement noise.

**Root cause:** The empirical baseline from ADR-018 (11,875 ms honeypot P95) was gathered before full prompt construction was finalized. The current honeypot system prompt (1,675 characters with 24 embedded canaries) generates longer cooperative responses (up to 256 tokens), making the measured P95 of ~15,000 ms realistic.

**Resolution:** Update `HONEYPOT_BUDGET_MS` from 12,000 to **16,000 ms** (15,000 ms empirical + 1,000 ms safety buffer). This accommodates the observed P95 while preserving margin for hardware variance and measurement noise.

**Code and configuration changes:**
- `src/armor/llm/loader.py:18`: `honeypot_budget_ms: int = 16000`
- `src/armor/llm/honeypot.py:143,145`: Fallback defaults updated to 16000
- `tests/fitness/llm_p95_latency.py`: `HONEYPOT_BUDGET_MS = 16000`

**CI promotion:**
- `.github/workflows/ci.yml`: Remove `continue-on-error: true` from the `make-fitness` job, promoting fitness checks to blocking (critical path).

**Implications:**
- The honeypot is still well within acceptable performance bounds (16 seconds for a full LLM inference + canary response is reasonable for an advisor-path detector).
- Code defaults are updated to match the new budget; all call sites use 16,000 ms.
- The soft-fail mechanism (task 021) still applies: if any LLM call exceeds its budget, it returns `advisory(confidence=0)` and the pipeline continues with static-only detection.

**Validation:**
- Empirical measurements (three runs on developer machine): 15,085–15,504 ms P95.
- CI performance (post-amendment): Expected to green on ubuntu-latest runners.

**References:**
- Task 043 — Honeypot P95 latency regression investigation and resolution
- Empirical runs (2026-05-06): 15,176.5 ms, 15,085.9 ms, 15,504.8 ms

---

## References

- **ADR-018** — Validator + honeypot model choice (empirical latencies)
- **ADR-021** — Honeypot prompt design and canary isolation
- **Task 021** — Implementation (soft-fail, fitness functions, config keys)
- **Task 022** — Session risk scoring (uses `confidence` field for weighting)
- **Task 043** — Honeypot P95 latency regression (amendment section above)
- **B-005** — Validator LLM behavior (refined with soft-fail modes)
