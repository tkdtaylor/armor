# ADR-036 — Translation-based jailbreak / obfuscation detection

**Date:** 2026-05-07
**Status:** Deferred (operator decision 2026-05-07 — canary/honeypot defense considered sufficient backstop)
**Decision date:** 2026-05-07
**References:** Internal design audit categories *Language Translation Obfuscation* and *Translation Jailbreak*; ADR-022 (jailbreak-detector hybrid); ADR-026 (topic-coherence ONNX embedding).

## Deferral rationale

On 2026-05-07, after the design conversation that produced ADR-041 (payload provenance) and during the queue planning for the implementation phase, the operator chose to defer this work indefinitely. Reasoning:

> "with the protections we already have in place I'm fine leaving the language gap here. If an attacker gets past it then it may hit the canary detection with the honeypot values which is why they're there"

The canary scanner is language-agnostic for verbatim values — a translated injection that successfully extracts a canary value from the model's context still produces a verbatim canary in the output, which trips the existing post-output scanner regardless of language. Combined with ADR-031 (honeyfs on-disk canaries) and ADR-038 (time-delayed canaries), the **canary-trip defense layer compensates for the missing language-specific detection.** A translation-based attack that bypasses the static input-side regex family is exactly the case the canary architecture was designed to catch.

The 75 MB image-size cost of `fasttext-langdetect` is also a real constraint — the v0.x runtime image is ~485 MB; this ADR alone would push it to ~560 MB (+15%). Combined with the canary backstop being sufficient, the cost/benefit doesn't justify v1 implementation.

**Re-open conditions:**
- Field reports of translation-based attacks bypassing the canary layer (e.g., attacks that successfully describe rather than emit canary values, in non-English languages — though that case is also covered by ADR-034 paraphrase detection if it lands).
- Image-size budget grows enough that 75 MB is a smaller fraction of the total.
- A lighter-weight language-detection approach emerges that doesn't require a 75 MB model.

Task 068 is dropped from the implementation backlog. The acceptance section of this ADR remains documented for a future operator who reopens it.

## Context

Two related but distinct attack vectors from the internal design audit:

- **Translation Obfuscation (Category 4 line 321)** — *"translate to obscure language to hide"* — the attacker asks the model to render output in a low-resource language, hoping the canary scanner (English-keyword-tuned) and the validator LLM (English-prompted) miss it.
- **Translation Jailbreak (Category 5 line 331)** — *"attack in foreign language"* — the attacker writes the injection itself in a language the static detectors don't cover, hoping the regex family doesn't match.

Today's detectors are entirely English-tuned: `regex_instruction_override` matches "ignore previous instructions" but not its Portuguese, Russian, or Mandarin equivalents; the validator LLM prompt is English; the canary scanner is language-agnostic but only catches verbatim values, not translated descriptions.

This is a real bypass. The 2023 *Low-Resource Language Jailbreak* paper (Yong et al.) demonstrated that translating jailbreaks into low-resource languages substantially raises bypass rates against English-trained safety filters; the same logic applies to perimeter detectors.

## Decision

The deferred design would add a two-stage detector **`meta.language_anomaly`** that:

1. **Detects the language of every input and output payload** using a lightweight in-process language classifier.
2. **When the detected language is non-English, escalates the FSM** with an `advisory` signal weighted by language rarity, AND **back-translates** the payload to English and re-runs the input-side detector pipeline against the translation.

### Language classifier choice

Three options:

- **`fasttext-langdetect`** — pre-trained model, ~75 MB, supports 176 languages, ~5 ms per call. **Lean: this one.** Fits the existing image-size budget (already shipping a 23 MB MiniLM and a ~462 MB validator LLM, so 75 MB more is incremental).
- **`langdetect`** (Python port of Google's libcld) — pure Python, ~1 MB, slower (~50 ms) and known to be unreliable on short strings (< 20 chars). Cheaper but worse signal.
- **`cld3`** — Google's compact language detector, ~30 MB, accurate. Pinning is awkward (Python wheels are platform-specific). Reject unless `fasttext-langdetect` proves infeasible.

### Back-translation strategy

The validator LLM (Qwen3-0.6B per ADR-018) **does** speak multiple languages out of the box. For non-English payloads, we run a translation pass: a structured-output prompt asking *"translate the following to English. Return JSON: {\"translated\": ...}"*. Then the existing input-side regex pipeline runs on the translation. Total cost: one extra validator LLM call per non-English turn, ≤ 500 ms per ADR-023's budget.

**This adds a second LLM call to non-English inputs.** Acceptable because: (a) non-English traffic in the target deployment (Claude Code English-language users) is rare; (b) when it does happen, it is *itself* an anomaly worth escalating; (c) the translation pass is bounded and soft-fails on budget per ADR-023.

### Signal model

- **Detected language is English** → no signal, pipeline proceeds normally.
- **Detected language is non-English, common (Spanish, French, German, Mandarin, Japanese, Russian, Portuguese, Arabic, Hindi)** → `advisory(confidence=0.3)` + back-translate + re-run input pipeline on translation. The translated pipeline can independently produce its own block/advisory, attributed to `meta.language_anomaly` with `details["original_lang"]` and `details["translated_text_signal"]`.
- **Detected language is non-English, rare (anything not in the common list)** → `advisory(confidence=0.6)`. Back-translate and re-run. Higher confidence reflects that low-resource-language attacks are *specifically* the documented jailbreak technique.
- **Mixed language (script switching mid-sentence — e.g. Latin → Cyrillic mid-string)** → `advisory(confidence=0.5)` + special-case detector for **Unicode confusables** (homoglyph attacks).

### Output-side coverage

When a *response* (model output) is in a non-English language, the same logic applies: language-detect, then back-translate, then re-scan the translation against the canary scanner *plus* the destination extractor (a webhook URL is the same regardless of surrounding language). The canary scanner already catches verbatim canary values regardless of language; this step covers the description-of-canary case (which overlaps with ADR-034 paraphrase detection).

## Open questions answered

Answered 2026-05-07.

1. **Language ID approach?** → **fasttext-langdetect (~75 MB).** Pre-trained, 176 languages, ~5 ms per call. Image-size delta from ~485 MB to ~560 MB is acceptable for the v1 detection coverage gain.
2. **Common-language list?** → **Ship the proposed list** (Spanish, French, German, Mandarin, Japanese, Russian, Portuguese, Arabic, Hindi). Operators override via `detector.language_anomaly.common_languages` in `armor.toml`.
3. **Image-size impact tracking?** → **Track separately** as a fitness metric in a future fitness-functions amendment; not gating this ADR.
4. **Rare-language confidence?** → **0.6** (initial; one-line "tune from corpus" note). Default `session.thresholds.watching = 0.4`, so a single rare-language interaction escalates Normal → Watching — intentional, ensures validator LLM scrutiny on the first non-English signal.
5. **Confusables / homoglyph attacks?** → **Script-switching subset included here**; pure homoglyph deferred to a follow-up ADR if corpus evidence demands.
6. **Translation pass latency budget?** → **Reuse the validator budget** (500 ms per ADR-023); soft-fail to `advisory(confidence=0)` on timeout per the existing soft-fail contract.

## Consequences

1. New detector `src/armor/detectors/language_anomaly.py`.
2. New dependency: `fasttext-langdetect` pinned in `pyproject.toml`. Image size ~+75 MB.
3. New configuration keys: `detector.language_anomaly.{common_languages, rare_lang_confidence, common_lang_confidence}`.
4. New behavior entry in `docs/spec/behaviors.md`.
5. New corpus family `translation_jailbreak` and `translation_obfuscation` under `tests/eval/corpus/`.
6. Validator LLM gains a translation-prompt template at `src/armor/llm/prompts/translator.txt`.
7. Cross-references with ADR-034 (paraphrase) — language-anomaly's output-side handling can produce paraphrase-shaped signals; both detectors must produce non-overlapping `signal_id` namespaces to avoid double-counting in FSM scoring.

## See also

- Internal design audit categories *Language Translation Obfuscation* and *Translation Jailbreak*.
- ADR-022: jailbreak-detector hybrid (the existing static + LLM split this ADR extends to non-English).
- ADR-026: ONNX embedding (precedent for a non-LLM model in the daemon image).
