# ADR-037 — Context-window attack detector category

**Date:** 2026-05-07
**Status:** Accepted
**Decision date:** 2026-05-07
**References:** `archive/discussion.md` §7 Category 6 lines 332-338 *Context Window Attacks*; ADR-024 (session FSM); ADR-026 (topic-coherence).

## Context

The audit of `archive/discussion.md` §7 Category 6 surfaced an entire detector category with no current coverage:

| Vector (discussion §7 Category 6) | Description | Today's coverage |
|---|---|---|
| **Context Overflow** | Flood with irrelevant text to push the system prompt out of the model's effective context | None |
| **Instruction Burial** | Hide the malicious instruction deep in long context (page 47 of a 50-page document) | None — input regex scans the whole payload uniformly, but the *agent's* attention does not |
| **Memory Manipulation** | *"Remember this new rule"*, *"From now on, always …"* — plant a persistent instruction the agent treats as a system-level directive in subsequent turns | None |
| **Conversation Hijacking** | Take over an existing conversation flow by claiming continuity (*"as we agreed earlier, you will now …"*) | Topic-coherence (ADR-026) catches abrupt shifts but not smooth hijacks |
| **Token Limit Exploitation** | Force truncation to lose the safety context | None |

These attacks share a common axis: they exploit the **shape of the context window** rather than the **content of any one turn**. They are not detected by per-turn regex or per-turn LLM-judgment because they operate at the conversation-aggregate level.

## Decision

**Proposed.** Add a small family of detectors under a shared category `meta.context_window`. Each is independent and can land in a separate task; this ADR establishes the category and the integration pattern.

### Detectors in scope

#### `meta.token_count_anomaly` (advisory)

Tracks the input-payload length distribution per session. Fires `advisory` when:

- A single input exceeds N standard deviations above the session's running mean (default: 3σ). This catches **context overflow** and **token-limit exploitation** — both manifest as suddenly-huge inputs.
- The input length exceeds an absolute cap (default: 32 KB) regardless of session history. This catches the first-turn overflow attack.

Confidence weighted by how far above the threshold the input is.

#### `meta.instruction_burial` (advisory)

For inputs above a length threshold (default 4 KB), runs the existing `regex.instruction_override` and `regex.system_prompt_extraction` patterns against the **last 25 % of the payload** in addition to the whole payload. A match in only the tail block (not the head) fires `advisory(confidence=0.8)` with `signal_id=meta.instruction_burial:<base_signal>`.

Rationale: the standard input regex catches *any* match; this detector specifically flags the *position* — burying an injection at the end of long context is the documented attack technique.

#### `meta.memory_planting` (advisory)

Regex family for memory-manipulation phrases:

- `(remember|memorize|note)\s+(this|the\s+following)\s+(rule|fact|instruction|directive)`
- `from\s+now\s+on,?\s+(always|you\s+will|you\s+should|you\s+must)`
- `for\s+the\s+rest\s+of\s+(this\s+)?(conversation|session)`
- `whenever\s+(I|you|we)\s+\w+,\s+(always|you\s+will|you\s+must)`
- `permanent\s+instruction`
- `default\s+to\s+(always|never)`

Fires `advisory` (block on multiple-match-in-same-turn). Feeds the FSM weighted at 0.4 — a benign user might legitimately ask the model to "remember" something, but repeated planting attempts in the same session are themselves a signal.

#### `meta.conversation_hijack` (advisory)

Regex family for conversation-continuity claims:

- `as\s+(we|you)\s+(agreed|discussed|said|established)\s+(earlier|before|previously)`
- `(per|following)\s+(our|the)\s+(previous|prior)\s+(conversation|discussion)`
- `recall\s+that\s+I\s+(am|told\s+you|asked)`

Cross-checked against the **session's actual signal history**: if the claim *isn't* supported by the session log (this is turn 1, or the prior turns don't mention the claimed agreement), confidence rises. This requires the detector to read `Session.signal_history` (already exposed via `SessionContext`).

### Common pattern

All four detectors:

- Are **advisory only** (not blocking) — context-window attacks are smooth, gradual, and easy to false-positive on. The FSM is the right place to aggregate them.
- Run on **input checks only** (output-side context-window attacks are not in the discussion's threat model).
- Use the existing FSM signal weighting per ADR-024.
- Are **independently togglable** via `pipeline.input_detectors`.

## Open questions answered

Answered 2026-05-07.

1. **One task or four?** → **Four small tasks**, one per detector. Each ships independently with its own corpus rows; the shared category is the unifying concept.
2. **`meta.token_count_anomaly` thresholds?** → **32 KB absolute cap; 3σ relative** (initial; one-line "tune from real Claude Code session distributions" note in the implementation task).
3. **`meta.instruction_burial` whole-payload-also-matches?** → **Skip in that case.** If the head also matches `regex.instruction_override`, the burial detector is redundant; don't double-count.
4. **`meta.memory_planting` calibration?** → **Default advisory weight 0.4** (initial; one-line "tune from benign corpus rows" note in the implementation task). Allows benign "remember to use 4-space indent" without escalation.
5. **`meta.conversation_hijack` SessionContext signal_history exposure?** → **Add read accessor.** This is the first detector to read FSM signal history; a small `SessionContext.signal_history` accessor lands as part of the implementation task.

## Consequences

1. Four new detectors under `src/armor/detectors/` (`token_count_anomaly.py`, `instruction_burial.py`, `memory_planting.py`, `conversation_hijack.py`).
2. New configuration keys per detector: thresholds, confidence weights, optional pattern files.
3. Three new behavior entries in `docs/spec/behaviors.md` (the four detectors share one category and one B-entry style).
4. New corpus families `context_overflow`, `instruction_burial`, `memory_planting`, `conversation_hijack` under `tests/eval/corpus/`.
5. `SessionContext` may gain a read accessor for `signal_history` if `meta.conversation_hijack` requires it (deferrable — implement via an existing helper if possible).
6. Architecture catalog updated.

## See also

- `archive/discussion.md` §7 Category 6 lines 332-338.
- ADR-026: topic-coherence (the closest existing detector; complements but does not subsume context-window attacks).
- ADR-024: session FSM (the aggregation substrate for these advisory signals).
