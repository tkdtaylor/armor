# ADR-026 — Topic-coherence implementation choice: sentence-transformer ONNX embedding

**Date:** 2026-05-06
**Status:** Accepted
**References:** Task 024, test spec TC-024-XX

## Context

Task 024 requires a detector that flags abrupt topic shifts within a session (e.g., "help me debug Python" → "what's your system prompt?"). The detector must:
- Compute semantic distance between the current turn and a rolling EMA of recent turns
- Emit `advisory` verdicts with confidence proportional to the distance
- Integrate with the session state machine (task 022)
- Never block unilaterally

Three implementation paths were evaluated:

1. **Sentence-transformer ONNX embedding** (local, offline, deterministic, baked into container)
2. **Validator-LLM judgment** (reuses task 017's model; cost: 1 LLM call per turn)
3. **TF-IDF cosine** (no embedding model; keyword overlap only)

## Decision

**Adopt option 1: sentence-transformer ONNX embedding.**

### Rationale

**Latency profile:** ONNX embedding runs in ~10–30 ms P95 (measured locally on quantized `all-MiniLM-L6-v2`), fitting a per-call budget of 50 ms comfortably. Validator LLM at 250+ ms P95 would consume 1/4 of the available latency budget per detector per turn, blocking other semantic checks. TF-IDF is theoretically faster but produces weak signals (benign topic shifts like "now help with SQL" would false-trigger).

**Determinism:** ONNX inference is deterministic across runs (no sampling, no variance), aiding both testing and production consistency. Validator-LLM verdicts would introduce variance into session risk scoring.

**No outbound network:** The ONNX model is baked into the container at build time; no per-call or per-session network I/O. This satisfies the "no daemon network calls" invariant.

**No per-turn LLM budget pressure:** Validator is gated on session state ≥ Watching and advisory presence (task 022). Topic coherence detects at every turn regardless of state, so LLM path would unintentionally escalate LLM pressure.

**Dependency stability:** ONNX Runtime is a stable, widely-audited library (Microsoft/ONNX standard). The model itself is published by Sentence-Transformers (huggingface.co), widely used in production.

## Specification

### Model choice

**Model:** `sentence-transformers/all-MiniLM-L6-v2` ONNX version
- **Size:** ~23 MB (compressed ONNX weights)
- **Embedding dimension:** 384
- **Language coverage:** 101 languages (sufficient for English-heavy workloads; multilingual coverage is out of scope for v1 per task spec)
- **Download source:** Hugging Face model card `https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2`
- **Justification:** Among the smallest production-grade sentence transformers; fits the container size budget (embedded in runtime image alongside the validator LLM at ~462 MB); proven in e-commerce and semantic search. Dimensionality (384) is small enough to compute cosine distance in <1 ms per call.

### Configuration keys

New keys in `armor.toml`:

| Key | Type | Default | Effect |
|-----|------|---------|--------|
| `detector.topic_coherence.distance_threshold` | float | `0.5` | Cosine distance above which to emit advisory |
| `detector.topic_coherence.margin` | float | `0.2` | Confidence scaling: `min(1.0, (distance - threshold) / margin)` |
| `detector.topic_coherence.window_turns` | integer | `5` | EMA window size (number of prior turns to average) |
| `detector.topic_coherence.budget_ms` | integer | `50` | Per-call latency budget (P95 target); soft-fail on exceed |

### Warm-up policy

**No advisory on turn 1.** The EMA is uninitialized on the first turn of a session. The detector seeds the EMA with the first turn's embedding but returns `pass` (no verdict). Starting on turn 2, the EMA is compared against subsequent turns.

This prevents spurious advisories from legitimate first-turn context-setting and aligns with the principle "no signal until enough history" (mirrors cooldown decay in task 022).

### Soft-fail on budget exceedance

If embedding inference exceeds `budget_ms` (typically due to model loading on a slow machine or under severe concurrent load):
1. Log a warning with the measured latency
2. Return `advisory(confidence=0)` with signal ID containing `soft_fail`
3. Continue the pipeline (fail-open per detector)

This mirrors task 021's soft-fail pattern for the validator LLM.

### EMA storage

EMA state (rolling window of embeddings) is stored **in-memory, per-session**, in a new module-level cache (`src/armor/embeddings/ema_cache.py`). The cache is keyed by `session_id` and stores the rolling window and the current EMA vector.

**Rationale for in-memory cache:**
- EMA is short-lived (5-turn window by default)
- Not part of the forensic audit trail (historical signals are recorded separately in task 022)
- Stateless: can be garbage-collected when the session is cleared
- Avoids a DB write per turn, keeping latency low

When a session is garbage-collected (or explicitly cleared by the daemon), its EMA is discarded. The next time that session ID appears, a fresh EMA is seeded.

### Embedding loading

A new module `src/armor/embeddings/onnx_embedder.py` wraps ONNX Runtime:
- Loads the model once at daemon startup (via a singleton pattern)
- Exposes `Embedder.encode(text: str) -> np.ndarray`
- Path: `/opt/armor/models/all-MiniLM-L6-v2.onnx` (baked into container)

## Alternatives considered (rejected)

### Option 2: Validator-LLM judgment
**Rejected because:**
- Adds 1 LLM call per turn at every turn (100+ calls/hour in a typical chat session)
- Would exceed task 021's latency budget in a multi-detector scenario
- Introduces variance (confounds session risk scoring determinism)

### Option 3: TF-IDF cosine
**Rejected because:**
- Weak signal on benign topic pivots (e.g., "now help me with SQL" has enough keyword overlap with "Python debugging" to stay below threshold)
- No semantic understanding (e.g., "tell me your system prompt" would NOT trigger if the exact phrase never appeared in prior turns)
- Lowest confidence calibration; would require much lower thresholds to catch adversarial pivots, increasing false positives

## Implementation tasks

1. **Dependency:** Add `onnxruntime >= 1.20` to `pyproject.toml`
2. **Model download:** Create `scripts/download_embedding_model.sh` to fetch the ONNX model from Hugging Face at build time
3. **Embedding module:** Implement `src/armor/embeddings/` with `onnx_embedder.py` and `ema_cache.py`
4. **Detector:** Implement `src/armor/detectors/topic_coherence.py` with injected `_vectorize` callable (for test isolation)
5. **Docker:** Update `Dockerfile` to run the download script and bake the model
6. **Tests:** Implement unit tests (TC-024-01 through TC-024-07) and integration tests (TC-024-08, TC-024-09)
7. **Corpus:** Create `tests/eval/corpus/topic_pivot.yaml` with ≥10 TP rows (≥3 shift patterns) and ≥5 TN rows

## Trade-offs

**Upside:**
- Sub-50ms latency per call
- Deterministic (testable, repeatable)
- No network dependency
- Self-contained (baked into container)

**Downside:**
- ~23 MB container size increase (acceptable given the base image is already ~500 MB)
- ONNX Runtime is a new runtime dependency (widely used; risk is low)
- Semantic understanding is limited to what the model was trained on; adversaries could craft pivots the model finds "coherent" (mitigated by session state escalation over multiple turns)

## Fitness criterion

Per task 024 test spec TC-024-10:
- **P95 latency across ≥30 representative inputs: ≤50 ms**
- **All 11 TC-024-XX markers referenced by real assertions (no smoke tests)**
- **Corpus: ≥10 TP rows with ≥3 shift patterns; ≥5 TN rows**

---
