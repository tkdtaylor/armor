# ADR-024 — Session state machine with cooldown rules

**Date:** 2026-05-06
**Status:** Accepted
**Task:** 022
**Authors:** Kevin

## Context

The session-level risk tracking requires aggregating detector signals over multiple turns, gating expensive detectors (validator/honeypot) on risk level, and naturally cooling back toward safe states as time passes. Task 022 must specify the state machine's shape, transition logic, numeric thresholds, and cooldown decay model.

Key constraints:
- The FSM must compose cleanly with the existing pipeline architecture (no mutation of verdicts; state machine is a lateral concern).
- Thresholds and decay rates must be configurable (loaded from `armor.toml`) to support corpus-driven tuning in v1.0.
- State transitions must be deterministic given inputs (no implicit time.time() calls; `now` passed as a parameter for testability).
- `Blocked` is explicitly sticky in v0.4; operator-clear UX is out of scope (task 028).

## Decision

### Five-state machine

The session FSM has five states, ordered by risk level:

```
Normal → Watching → Elevated → High → Blocked
```

**State semantics:**
- **Normal:** No recent attacks detected. Static detectors only. Low operational overhead.
- **Watching:** One or more soft signals detected. LLM validator runs on subsequent checks. Session is being monitored for escalation.
- **Elevated:** Multiple soft signals or one block-class attempt detected. LLM validator runs; honeypot eligible on block attempts.
- **High:** Session is actively attacking. Honeypot runs on every relevant check. Operator visibility critical.
- **Blocked:** Terminal state. All subsequent checks short-circuit to `block` without running detectors (forensic log still written). Operator must explicitly clear (task 028).

### Forward transitions (signal-driven)

Forward transitions occur when `current_score` crosses a threshold:

```
Normal (score < 0.4) → Watching (0.4 ≤ score < 0.9)
→ Elevated (0.9 ≤ score < 1.5)
→ High (score ≥ 1.5)
```

**Threshold values:**
- `session.thresholds.watching = 0.4` — typical 2-3 soft signals at weight 1.0 each
- `session.thresholds.elevated = 0.9` — 2-3 medium-confidence advisories, or one block attempt from a static detector
- `session.thresholds.high = 1.5` — multiple medium-confidence signals, or escalation from elevated state with continued activity

**Rationale for these values:**
- `watching=0.4` is aggressive (catches early escalation) but not so aggressive that a single true-positive static advisory (e.g., detected encoding request) escalates alone. Two-three soft signals in quick succession suggests coordinated testing.
- `elevated=0.9` sits at the "multiple confirmations" boundary. A detector weight of 1.0 produces scores of 1.0 on single-detector block; 0.9 threshold prevents single soft blocks from causing immediate honeypot invocation.
- `high=1.5` is reached after sustained or multiple escalations. At this level, the session is clearly hostile and full instrumentation (honeypot on every check) is justified.

These values are calibrated for v0.3 static detectors and validator. If detector accuracy improves in v1.0, the thresholds can be lowered to catch attacks faster. If false-positives become a concern, thresholds can be raised.

### Score accumulation from signals

**Advisory signals:**
An `advisory` signal with `confidence` field contributes `confidence * weight` to `current_score`, where:
- `confidence` is a float 0.0..1.0 (populated by the validator LLM or static detectors).
- `weight` defaults to `1.0` but is overridable per-detector via config key `session.signal_weights.<detector_id>`.

Example:
```toml
[session.signal_weights]
"llm.validator" = 0.8  # Validator advisories weighted at 80% of their confidence
"regex.encoding_request" = 0.5  # Encoding requests weighted at 50%
```

**Block signals:**
A signal with `decision == "block"` immediately sets `current_state = Blocked`, regardless of prior score. The score itself may carry forward but is not used for further transitions (Blocked is terminal).

**Score floor:**
Score is non-negative. Decay cannot drive it below 0.0 (clamped at 0).

**Score is not monotonic:** Unlike the old risk_score (which was monotonically non-decreasing), the new session risk_score can decrease via cooldown decay. The monotonic invariant is replaced with a "current operational risk level" model.

### Backward transitions (cooldown-driven)

Cooldown decay happens **before** each new signal is applied:

```
decay_amount = session.cooldown_decay_per_min * (now - last_signal_at).total_seconds() / 60.0
new_score = max(0.0, current_score - decay_amount)
```

**Linear decay rationale:**
Linear decay is simpler to reason about and easier to tune empirically. The decay rate is predictable: given `cooldown_decay_per_min=0.1`, the score drops by 0.1 per minute of inactivity. Over ~4 minutes, a session in `Watching` (score ~0.4) returns to `Normal`.

Exponential decay (e.g., `score *= exp(-decay_rate * elapsed_seconds)`) would be smoother but introduces complexity: the effective decay rate depends on elapsed time, making operator tuning harder. Linear is a better fit for v0.4.

**Step-back logic:**
After decay, if the post-decay score falls below the **lower threshold for the current state**, the state moves back **exactly one rung**:

```
# There is no "normal" threshold; any score below the watching threshold steps back to Normal.
if current_state == Watching and new_score < session.thresholds.watching:
    new_state = Normal

if current_state == Elevated and new_score < session.thresholds.elevated:
    new_state = Watching

if current_state == High and new_score < session.thresholds.high:
    new_state = Elevated
```

**Single-rung-per-call:**
Step-back never skips rungs, even if decay is very large. If a session is in `High` and decay is massive, the first call moves it to `Elevated`; the second call (if no new signals) moves it to `Watching`; the third to `Normal`. This prevents "falling off the ladder" in a single call and ensures smooth cooldown behavior observable to operators.

**Blocked is terminal:**
Cooldown never exits `Blocked`. Only operator-clear (task 028) can reset it.

### Configuration

All numeric values are loaded from `armor.toml`:

```toml
[session.thresholds]
watching = 0.4
elevated = 0.9
high = 1.5

session.cooldown_decay_per_min = 0.1

[session.signal_weights]
# Detector-specific weights; defaults to 1.0 if not specified
"llm.validator" = 1.0
"regex.encoding_request" = 1.0
```

**Environment variable override:**
`ARMOR_SESSION_THRESHOLDS_WATCHING`, `ARMOR_SESSION_THRESHOLDS_ELEVATED`, `ARMOR_SESSION_THRESHOLDS_HIGH`, `ARMOR_SESSION_COOLDOWN_DECAY_PER_MIN` can override TOML (standard precedence: env > TOML > hardcoded defaults).

### Why FSM lives in `src/armor/session/`

The session state machine is a cross-cutting concern: it affects detector cost-tier gating, risk score aggregation, and operator UX. Placing it in `src/armor/session/` (a new top-level module) signals that it's a first-class system component, not nested within the pipeline or daemon. This follows Unix philosophy: small, composable, replaceable units. The pipeline does not "own" session state; the session state machine is independent and consulted by the pipeline.

Alternative considered: placing it in `src/armor/pipeline/session_state.py` would couple the FSM to pipeline internals, making it harder to test or reuse.

## Implementation

### Core pure function

`src/armor/session/state_machine.py` exports:

```python
from datetime import datetime
from enum import StrEnum

class SessionState(StrEnum):
    NORMAL = "Normal"
    WATCHING = "Watching"
    ELEVATED = "Elevated"
    HIGH = "High"
    BLOCKED = "Blocked"

def apply_signal(
    current_state: SessionState,
    current_score: float,
    signal: Verdict,
    last_signal_at: datetime,
    now: datetime,
    config: dict[str, Any],  # Thresholds, weights, decay rate
) -> tuple[SessionState, float]:
    """Apply a signal to the session state machine.

    Pure function: no I/O, no side effects, no time.time() calls.
    Arguments:
        current_state: The session's current state.
        current_score: The session's current risk score.
        signal: The new signal (advisory or block).
        last_signal_at: Timestamp of the last signal (for cooldown calculation).
        now: Current wall-clock time (passed by caller for testability).
        config: Configuration dict with thresholds, weights, decay_rate.

    Returns:
        (new_state, new_score) tuple.
    """
    # 1. Apply cooldown decay (if signal is advisory and not the first signal)
    # 2. Check if decay moves us down a rung
    # 3. Apply the new signal (advisory adds confidence*weight, block jumps to Blocked)
    # 4. Check if new signal moves us up a rung (multi-rung jumps possible)
    # 5. Return (new_state, new_score)
```

### Persistence layer

`src/armor/db/session_store.py` extends `SessionRow` and `SessionStore`:

**New fields on `SessionRow`:**
- `current_state: str` — one of `Normal|Watching|Elevated|High|Blocked`
- `risk_score: float` — numeric aggregation of signals (0.0..∞, typically 0.0..5.0)
- `last_signal_at: float` — Unix timestamp of last signal (for cooldown calculation)

**New methods on `SessionStore`:**
- `apply_and_persist(session_id, signal, now) -> (new_state, new_score)` — wraps `apply_signal`, updates DB, returns new state
- Existing `update_after_check()` becomes a thin wrapper calling `apply_and_persist()` for the forensic log update path

### Pipeline integration

`src/armor/pipeline.py` gains a state-aware cost-tier gate:

```python
async def run(
    detectors: list[Detector],
    payload: Payload,
    ctx: SessionContext,
    session_state: SessionState | None = None,  # New parameter
) -> Verdict:
    # Early exit: if session_state == Blocked, return block(category=session.blocked)
    # without running any detectors

    # Detector filtering: skip detectors with cost_tier="llm" unless session_state >= Watching
```

### Daemon integration

`src/armor/daemon/server.py` calls `apply_and_persist()` before running the pipeline:

```python
async def _handle_check_operation(...):
    # Load current session state from cache/DB
    session = await self.session_store.get_or_create(session_id)

    # Apply signal (cooldown + new signal)
    new_state, new_score = await self.session_store.apply_and_persist(
        session_id, signal=..., now=datetime.now()
    )

    # Fetch detectors, filtering by cost tier and session state
    detectors = self.registry.for_cost_tiers(["static", ...])
    if new_state >= SessionState.WATCHING:
        detectors.extend(self.registry.for_cost_tiers(["llm"]))

    # Run pipeline with gated detectors
    verdict = await Pipeline.run(detectors, payload, ctx)
```

## Spec updates

1. **behaviors.md** — Add `B-NNN: Track session-level risk and escalate detection strictness` (moved from data-model.md, where it currently lives as B-004 but is vague). Describe the five-state machine, forward/backward transitions, cooldown, and Blocked behavior.

2. **data-model.md** — Update `Session` entity to include `current_state`, `risk_score`, `last_signal_at` fields. Clarify that `risk_score` is now "current operational risk level" (not monotonic, decays with cooldown).

3. **configuration.md** — Add `session.thresholds.{watching,elevated,high}`, `session.cooldown_decay_per_min`, `session.signal_weights.*` keys with defaults and descriptions.

## Fitness functions

1. **`session_state_fsm_pure`** — unit test asserting apply_signal() is a pure function (no side effects, deterministic given inputs).
2. **`session_state_thresholds_configurable`** — unit test that monkey-patches the config and verifies thresholds are loaded and applied (not hardcoded).
3. **`session_state_cooldown_linear`** — unit test verifying linear decay mathematics.
4. **`session_state_blocked_terminal`** — unit test that Blocked never exits except via explicit operator action (deferred to task 028).

(These are checked into `tests/fitness/` and wired into `make fitness`.)

## Deferred / Non-goals for v0.4

- **Cross-session correlation** — v1+ capability; multi-session collaborative attack detection.
- **ML-driven thresholds** — v1.0 hardening; empirical FP/FN tuning on production corpus.
- **Operator-clear UX** — `armor sessions unblock <id>` lands in task 028.
- **Adaptive decay rates** — v1+; per-detector or per-attack-class decay rates.
- **State machine visualization** — dashboard/grafana integration, v0.5+.

## Consequences

1. Session state machine is a standalone composable unit in `src/armor/session/`.
2. Config keys grow to include thresholds, decay rate, and per-detector weights.
3. Pipeline gains cost-tier gating based on session state.
4. Session state is persisted and loaded on each check (via SessionStore cache).
5. Cooldown is automatic (applied on every check, no background task).
6. Blocked is sticky in v0.4; task 028 adds the operator-clear path.
7. Forensic log continues to record all signals; session state is orthogonal.

## Rationale summary

The five-state machine maps intuitive risk levels (Normal → Watching → Elevated → High → Blocked) to concrete operational changes (detector gatings, LLM invocation, honeypot eligibility). Linear decay is simpler to tune than exponential and fits the v0.4 corpus. Single-rung step-back prevents "falling off the ladder" and gives operators observable cooldown behavior. Config-driven thresholds enable future corpus-driven tuning without code changes. The FSM lives in `src/armor/session/` as a first-class composable unit, not nested in pipeline/daemon internals.

---

## Acceptance

- **Status:** Accepted
- **Date:** 2026-05-06
- **Task:** 022
- **Reviewed by:** Architecture (implicit; ADR drafted with full task spec)

## References

- **Task 022** — Implementation and test spec
- **ADR-001** — SQLite session store (the FSM persists `current_state`, `risk_score`, `last_signal_at` on the existing `Session` row)
- **Task 018** — Validator LLM model choice
- **Task 021** — Soft-fail policy for LLM budgets (confidence scoring)
- **Task 028** — Operator-clear UX for unblocking sessions
- **behaviors.md** — Updated with B-004 clarification and Blocked short-circuit behavior
- **data-model.md** — Updated with new Session fields
- **configuration.md** — Updated with new config keys
