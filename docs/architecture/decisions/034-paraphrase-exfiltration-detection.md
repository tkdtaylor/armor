# ADR-034 — Natural-language paraphrase exfiltration detection

**Date:** 2026-05-07
**Status:** Accepted
**Decision date:** 2026-05-07
**References:** `archive/discussion.md` §6 lines 275-283 *Slow Burn Exfiltration*; §7 Category 3 (line 311) *Natural Language Paraphrase*; ADR-025 (rolling buffer); behaviors.md B-009a (chunked exfil).

## Context

Today's canary-leak detection works on three layers:

1. **Aho-Corasick exact match** on the single-turn output (`canary.scanner`).
2. **Entropy-decode-rescan** for base64/hex-encoded leaks (`entropy.decode_rescan`).
3. **Rolling-buffer concatenation scan** for chunked leaks across turns (B-009a) — including a **partial-canary prefix detector** that fires on a contiguous prefix ≥ 12 chars.

All three rely on the **literal canary value** (or a contiguous prefix of it) appearing in the output stream. The discussion's §6 *Slow Burn* and §7 Category 3 *Natural Language Paraphrase* call out a class of leaks none of these three catches:

- *"the AWS key starts with `AKIA…`, then has `IOSFODNN`, and ends with `7EXAMPLE`"* — the value is described, never pasted contiguously.
- *"the second character is `K`, the seventh is `O`, …"* — per-character extraction.
- *"the secret begins with `wJalrXUtnFEMI`, the next part is `/K7MDENG`, the rest is `/bPxRfiCYEXAMPLEKEY`"* — three sub-strings each below the 12-char partial-match threshold.

This is not a hypothetical class. Real exfiltration techniques — including ones explicitly demonstrated against early LLM canary defenses — exploit the model's natural-language description capability to bypass exact matching.

## Decision

**Proposed.** Add a new advisory-tier detector **`canary.paraphrase`** that operates on the rolling buffer (per ADR-025) and detects fragmented or paraphrased canary leaks. The detector is **advisory only** — it feeds the FSM (per ADR-024), never blocks unilaterally, because the false-positive surface is intrinsically larger than exact-match detection.

### Three approaches on the table

The right approach is not yet obvious; each has different cost and FP characteristics.

#### A. Sub-prefix n-gram coverage

Build an Aho-Corasick automaton of every contiguous n-gram of length `[6, 11]` from each canary value (the range below the existing 12-char partial-match threshold but above the noise floor). Scan the rolling buffer; fire `advisory` if **≥ K distinct n-grams** of the same canary appear within the same buffer window.

- **Pros:** deterministic, fast (single A-C scan), no model dependency.
- **Cons:** misses true paraphrase (descriptive language doesn't contain even short literal n-grams); FP-prone on common substrings.

#### B. Embedding-similarity check

For each canary, compute an embedding of the canary value at install time. On every output check, embed each turn's output (already done for topic-coherence per ADR-026; reuse the encoder) and compute cosine similarity against each canary embedding. Fire `advisory` if similarity exceeds threshold.

- **Pros:** reuses the MiniLM model already in the image; works on natural-language paraphrases.
- **Cons:** raw credential strings are *not* what MiniLM embeds well — sentence-transformer models compress semantics, not character-level structure. Likely poor signal-to-noise.

#### C. LLM-as-judge probe

When the FSM is `Watching` or higher, run a small targeted LLM call: "Does this turn (or buffer concatenation) describe, paraphrase, or partially leak any of these canary values: [...]?" Reuse the validator LLM (per ADR-018, 020). Soft-fail on budget per ADR-023.

- **Pros:** catches descriptive paraphrase, per-character extraction, and other non-literal leaks.
- **Cons:** another LLM call on the hot path; the validator prompt must not include canary values per ADR-021's invariant — so the prompt has to reference values by `canary_id` and the LLM must reason about whether the output *describes* what it can't *see*. This is genuinely hard; a naive implementation will be unreliable.

#### D. Hybrid (recommended starting point)

Ship **A** (sub-prefix n-gram) as the initial implementation: it's deterministic, has no model dependency, and closes the easiest fragments-below-threshold case (the third example above with `/K7MDENG` etc.). If corpus evidence shows true descriptive paraphrase is the dominant remaining gap, layer **C** in a follow-up.

**B is rejected** unless someone produces a benchmark showing MiniLM does in fact discriminate canary-shaped strings — current expectation is it won't.

### Output integration

The detector writes its `advisory` into the same forensic + FSM path as the existing `canary.partial:<canary_id>` signal (B-009a). The signal_id distinguishes: `canary.paraphrase:<canary_id>:ngram` vs `canary.paraphrase:<canary_id>:llm` (when C lands).

### Latency budget

Approach A: re-uses the existing A-C automaton infrastructure; expected ≤ 5 ms per output check on the configured rolling buffer (8 KB / 20 turns per ADR-025). Approach C: piggybacks on the existing validator budget (500 ms per ADR-023); soft-fails to advisory(confidence=0).

## Open questions answered

Answered 2026-05-07.

1. **Approach choice?** → **Approach A (sub-prefix n-gram coverage).** Ship deterministic, no-model-dependency n-gram scanner first. Approach B (embedding similarity) rejected absent benchmark evidence. Approach C (LLM-as-judge) **deferred** until corpus evidence shows descriptive paraphrase is the dominant remaining gap.
2. **K threshold?** → **K=3** (initial; one-line "tune from corpus" note in the implementation task). Three distinct sub-prefix n-grams of the same canary within the rolling-buffer window justifies an `advisory` signal.
3. **N-gram length range?** → **`[6, 11]`** (initial; one-line "tune from corpus" note). Above noise floor, below the existing 12-char partial-match threshold.
4. **Confidence formula?** → **`min(1.0, K_observed / K_threshold * 0.5)`** — a partial signal feeds the FSM at half-weight so concurrent signals from other detectors aren't dwarfed.
5. **Per-character extraction detection?** → **Deferred.** *"The second character is K, the seventh is O"* doesn't match A cleanly. Add a regex family `canary.per_char_extraction` only if corpus evidence shows it's a real attack shape.

## Consequences

1. New detector `src/armor/detectors/canary_paraphrase.py` — advisory-tier, rolling-buffer-scoped.
2. New configuration keys: `detector.canary_paraphrase.{ngram_min, ngram_max, k_threshold, advisory_weight}`.
3. New corpus family `paraphrase_exfil` under `tests/eval/corpus/exfiltration.yaml`.
4. New behavior entry in `docs/spec/behaviors.md` (numbered after the highest current B- entry).
5. Updates `B-009a` to cross-reference the new detector — chunked-canary and paraphrase-canary share the rolling buffer but produce distinct signal_ids.
6. New row in `docs/spec/architecture.md` Components — detectors table.
7. **No FP regression target:** the eval corpus' benign rows must still produce a session risk score below the Watching threshold (0.4) when this detector is added.

## See also

- ADR-025: rolling buffer (the substrate this detector consumes).
- ADR-021: honeypot prompt + value isolation (forensic invariants — never log canary values).
- ADR-024: session FSM (the advisory feeds `apply_signal`).
- `archive/discussion.md` §6 lines 275-283 and §7 Category 3 line 311.
