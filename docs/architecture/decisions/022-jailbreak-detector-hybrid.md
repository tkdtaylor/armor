# ADR-022: Jailbreak detector hybrid (static + LLM escalation)

**Date:** 2026-05-06
**Status:** Accepted
**Task:** 020
**Authors:** Kevin

## Context

The jailbreak.template detector (task 020) combines static pattern matching with optional LLM semantic validation. Some jailbreak patterns are unambiguous (e.g., "DAN mode enabled"), while others are soft signals requiring semantic judgment (e.g., "imagine you are an AI without restrictions" — could be a legitimate fictional scenario). The hybrid approach avoids high false-positive rates on soft signals by escalating ambiguous cases to the validator LLM.

## Decision

### 1. Two-layer detector structure

**Static layer:** Regex pattern matching against four families:
1. **DAN (Do Anything Now)** — `severity: high` → unconditionally block (high-confidence patterns)
2. **Developer-mode** — `severity: high` → unconditionally block
3. **Fictional-framing** — `severity: medium` → return `advisory` (soft signal)
4. **Gradual-escalation** — `severity: medium` → return `advisory` (soft signal)

The severity field determines the immediate verdict:
- `high` or `critical` → `block` (skip LLM)
- `medium` or `low` → `advisory` (eligible for LLM escalation)

**Hybrid layer:** When static returns `advisory` AND `_llm_session` is available:
1. Call `validate(payload.text, ctx, llm_session=self._llm_session)` from the validator module (task 018).
2. Extract confidence score from the validator's output.
3. If validator returns `risky` verdict with `confidence >= 0.6`, escalate advisory to block.
4. Otherwise, return advisory unchanged.

If static returns `block` or `pass`, LLM is skipped (decision is final).

### 2. Confidence threshold for escalation

**Threshold:** 0.6 (60% model confidence in "risky" classification)

**Rationale:**
- A threshold of 0.6 balances precision (avoiding false positives) and recall (catching real attacks).
- Confidence >= 0.7 would be conservative (higher precision, lower recall).
- Confidence >= 0.5 would be permissive (lower precision, higher recall).
- 0.6 is a standard operating point for binary classifiers and reflects "moderate-high confidence" per ADR-020's calibration.

**Implication:** A soft-signal pattern + LLM verdict "risky" with confidence 0.55 does NOT escalate to block (confidence below threshold). The advisory stands, feeding into session risk scoring (task 022).

### 3. Composite verdict signal structure

When escalating advisory to block via LLM:
- **signal_id:** `<pattern_id> (llm:<confidence>)` — e.g., `jailbreak.template:fictional-framing-001 (llm:0.75)`
- **severity:** elevated to `high`
- **details dict:** Includes:
  - `family`: the pattern family (e.g., `"fictional-framing"`)
  - `llm_confidence`: the LLM confidence score (0..1)
  - `llm_verdict`: the LLM's verdict ("risky" or "safe")
  - `escalation_reason`: brief description

If advisory is NOT escalated (LLM low confidence or unavailable):
- **signal_id:** `<pattern_id>` (no LLM component)
- **severity:** `medium` (as per pattern)
- **details dict:** Includes:
  - `family`: the pattern family
  - `llm_confidence`: (if LLM ran) the confidence score
  - `llm_verdict`: (if LLM ran) the verdict
  - `llm_available`: boolean (false if no session injected)

### 4. Relationship to other components

**Validator gating (task 018):** The validator LLM is a separate detector (`llm.validator`) with its own gating rules (triggered on prior advisory OR when session is Watching+). The jailbreak.template detector uses the same validator infrastructure (_llm_session injection), but adds its own escalation logic.

**Session risk scoring (task 022):** Advisories (escalated or not) feed into session risk accumulation with their confidence scores. A block from jailbreak.template (either static or LLM-escalated) resets the escalation decision; the payload is rejected immediately.

**Honeypot invocation (task 019 gate, task 022 wiring):** Block verdicts (including those from LLM escalation) trigger the honeypot gate when session state is Elevated+. The honeypot path is independent of the detector's internal logic.

### 5. Test strategy

**Static-only eval (CI gate with `ARMOR_DISABLE_LLM=true`):** Corpus rows use `static_only_expected` field, which reflects the static layer verdict only. TPs have `static_only_expected: "block"` (high-confidence patterns), and TNs have `static_only_expected: "pass"`. Soft-signal rows have `static_only_expected: "advisory"`.

**With-LLM eval (integration tests, mocked LLM):** Corpus rows use `with_llm_expected` field, which reflects the hybrid verdict after LLM escalation. For soft-signal rows:
- If `with_llm_expected: "block"`, the LLM mock returns `risky` with `confidence >= 0.6`.
- If `with_llm_expected: "advisory"`, the LLM mock returns `safe` or `risky` with `confidence < 0.6`.

This separation allows the eval harness to exercise both layers independently.

### 6. Detector cost and resource budgeting

- **Static layer cost:** O(n) regex matching, microseconds per pattern. No latency budget constraint.
- **Hybrid layer cost:** One LLM call (if advisory detected). Falls under the existing `pipeline.per_detector_budget_ms` (default 100 ms, with LLM allowed up to 500 ms per task 018). Detector returns `advisory` unchanged if LLM call exceeds budget or fails.

### 7. Fallback behavior (LLM unavailable or error)

If `_llm_session` is None or an exception occurs during LLM escalation:
- Log the condition at warn level.
- Return the static advisory unchanged.
- Do NOT block (fail-open per detector design principle).

This ensures the detector degrades gracefully when the LLM is unavailable or misconfigured.

## Rationale

1. **Two-layer hybrid design:** High-confidence patterns (DAN, developer-mode) block immediately, avoiding unnecessary LLM calls. Soft patterns benefit from semantic judgment, improving recall without harming precision.

2. **Pattern severity field as the decision rule:** Severity already encodes analyst confidence in the pattern; leveraging it for immediate-block vs escalation decisions is natural and maintainable.

3. **Confidence threshold at 0.6:** Calibrated to task 018's validator accuracy and the project's precision/recall balance. Lower thresholds would over-block benign queries; higher thresholds would under-detect soft attacks.

4. **Composite signal with LLM metadata:** The signal_id and details preserve provenance (which pattern matched, what the LLM said), enabling downstream diagnostics and tuning.

5. **Test separation (static_only vs with_llm):** Allows independent validation of each layer and explicit demonstration of escalation behavior. The `static_only_expected` field is the source of truth for the static layer; `with_llm_expected` documents the intended behavior after escalation.

6. **No daemon-side wiring needed for v0.3:** The detector is self-contained and testable with mock LLMSession injection. Task 022 (session state machine) will add daemon-side invocation logic for risk scoring; the detector itself needs no changes.

## Consequences

1. **New detector:** `jailbreak.template` (id, category, cost_tier) in the direct_injection category.

2. **New pattern file:** `src/armor/detectors/jailbreak_patterns.yaml` with four families, ≥12 patterns total.

3. **Enhanced corpus:** `tests/eval/corpus/jailbreak.yaml` includes both `static_only_expected` and `with_llm_expected` fields; corpus must have ≥30 TPs and ≥15 TNs per family requirements.

4. **Unit tests:** `tests/unit/detectors/test_jailbreak_template.py` exercises both static and hybrid layers in isolation.

5. **Integration tests:** Corpus eval (task 014's CI gate) runs in two modes:
   - Static-only: `ARMOR_DISABLE_LLM=true`, checks `static_only_expected` verdicts.
   - With-LLM: Full harness with mocked LLM, checks `with_llm_expected` verdicts.

6. **Fitness function:** `tests/fitness/jailbreak_counts.py` asserts family counts and TP/TN minimums.

7. **Spec updates:**
   - New behavior `B-NNN` in `docs/spec/behaviors.md` (jailbreak detection, families, hybrid escalation).
   - Jailbreak signal taxonomy in `docs/spec/data-model.md`.
   - Fitness check documentation in `docs/spec/fitness-functions.md`.

## Alternatives considered

1. **Single-layer static only (no LLM):** Would require aggressive regex patterns to avoid false positives on soft signals, leading to reduced recall. Rejected because soft patterns benefit from semantic judgment.

2. **LLM-only (no static patterns):** Would require LLM on every check (high latency, resource overhead). Also less robust to adversarial prompt injection against the LLM itself. Rejected because high-confidence patterns should block immediately.

3. **Separate detector for LLM escalation:** Would complicate pipeline composition and require wiring LLM verdicts back to static detectors. Rejected because hybrid logic is tightly coupled and self-contained within the detector.

4. **Higher confidence threshold (0.7+):** Would reduce false positives but also reduce recall on borderline cases. Rejected because 0.6 aligns with industry-standard classifier operating points and task 018's calibration.

5. **Lower confidence threshold (0.5):** Would increase recall but also false positives. Rejected for the same reason.

## Implementation Notes (v0.3 — Task 020)

- The detector `JailbreakTemplate` class is self-contained at `src/armor/detectors/jailbreak_template.py`.
- The `_llm_session` attribute is injected for testing; production wiring (daemon side) deferred to task 022.
- Corpus includes ≥30 TPs (block expected) and ≥15 TNs (pass expected), spanning all four families.
- Each family must have ≥3 TPs and ≥1 TN per fitness constraints.
- Unit tests exercise both static and hybrid paths with real assertions (not smoke tests).
- Integration tests with mocked LLM validate escalation behavior.

## See also

- ADR-020: Validator LLM output contract and confidence calibration.
- ADR-021: Honeypot system prompt design and canary value isolation.
- Task 022: Session state machine and risk scoring (will wire honeypot invocation).
- Task 014: Eval harness CI gate (corpus-driven testing infrastructure).

---

## Acceptance

- **Status:** Accepted
- **Task:** 020
- **Implementation:** `src/armor/detectors/jailbreak_template.py`, `src/armor/detectors/jailbreak_patterns.yaml`
- **Tests:** `tests/unit/detectors/test_jailbreak_template.py`, `tests/eval/corpus/jailbreak.yaml`, `tests/fitness/jailbreak_counts.py`
- **Spec:** `docs/spec/behaviors.md`, `docs/spec/data-model.md`, `docs/spec/fitness-functions.md`
