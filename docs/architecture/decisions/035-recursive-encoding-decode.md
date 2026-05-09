# ADR-035 — Multi-layer / recursive encoding decode

**Date:** 2026-05-07
**Status:** Accepted
**Decision date:** 2026-05-07
**References:** Internal design audit category *Encoding & Obfuscation Attacks / Multi-Layer Encoding*; behaviors.md B-006; ADR-014 (output entropy policy).

## Context

`docs/spec/behaviors.md` B-006 currently states:

> *"Recursive decode is not supported — single pass only; deferred until corpus evidence shows a measurable false-negative class that recursion would catch."*

This was a deliberate v1 simplification. The design audit named multi-layer encoding explicitly. A real attacker can pipeline `base64(hex(canary))` (or any nesting) and bypass a single-pass `entropy.decode_rescan` because the first decode pass produces another encoded blob, not the canary.

Reversing the deferral is non-trivial because **recursive decode is a budget hazard**. A maliciously-constructed input can force unbounded decoding (a self-referential base64 chain, a high-entropy non-canary that decodes to another high-entropy non-canary indefinitely). Single-pass decode bounds the work; recursion needs explicit termination conditions.

## Decision

Replace the single-pass decode in `entropy.decode_rescan` with a **bounded-depth recursive decode** that terminates on any of:

1. **Depth cap** — `entropy.max_decode_depth`, default `3`. A 4-layer encoding is exotic enough that a configurable knob is sufficient; the daemon does not need to chase arbitrary depth.
2. **Per-detector budget** — the existing `pipeline.per_detector_budget_ms` (default 100 ms) bounds total wall-clock work; recursion stops when the budget is consumed.
3. **No-progress termination** — if a decode pass produces output whose entropy is **lower than the input's entropy minus a margin** (default 0.5 bits/char), the chain has clearly stopped reducing structure; stop. This catches the "decode to garbage" case and the "fixed point" case (a string whose base64 decodes to itself or to similarly-shaped junk).
4. **Successful canary match** — at any depth, if the post-decode plaintext contains a canary value (Aho-Corasick hit), the detector returns `block` immediately; depth and budget are irrelevant past the first hit.

### Decoder set per pass

Each pass attempts each decoder in order, on each high-entropy substring identified in the previous step:

- **Base64** (`base64.b64decode`, with both standard and URL-safe alphabets).
- **Hex** (`bytes.fromhex` after a permissive prefix strip).
- **ROT13** *(skip — not high-entropy; covered by the encoding-request input detector).*
- **URL-encode** (`urllib.parse.unquote`, only when input contains `%[0-9A-Fa-f]{2}`).
- **Gzip / zlib** *(deferred — adds a magic-byte check; can land in a follow-up ADR if corpus evidence demands).*

Each successful decode produces a plaintext that is then re-scanned for canaries (existing A-C automaton) and, if no hit, re-evaluated for high entropy and fed into the next pass.

### Forensic record

When a recursive chain trips, the forensic record records the **decode chain** (`b64 → hex → utf-8`) and the **terminal canary_id**. The chain is recorded by name only — the intermediate plaintext is **never stored** (would violate the canary forensic-safety invariant; the final canary is referenced by `canary_id`).

### Per-pass cost

Each decode + re-scan pass on a 4 KB candidate substring is ≤ 5 ms in the validator's reference profile. Three passes ≤ 15 ms; well within the 100 ms per-detector budget.

## Open questions answered

Answered 2026-05-07.

1. **Depth cap default?** → **3.** Real attacks rarely exceed 2 layers; 3 gives headroom; 5 is a budget hazard with diminishing returns. Configurable via `entropy.max_decode_depth`.
2. **No-progress entropy margin?** → **0.5 bits/char** (initial; one-line "tune from corpus" note). Configurable via `entropy.no_progress_margin_bits`.
3. **Configurable decoder set?** → **No for v1.** The four codecs (base64, hex, URL-encode, with ROT13/gzip explicitly excluded) are well-known and Python-native; adding more is an ADR-level decision.
4. **Forensic `signal_id` format for recursive chain?** → **`entropy.decode_rescan:<chain>:<canary_id>`** where `<chain>` is the codec sequence joined by `.` (e.g. `entropy.decode_rescan:b64.hex:aws-key-001`). Operators reading the audit log see the attack technique.
5. **Telemetry on recursion depth distribution?** → **Yes, log under `details["decode_depth"]`** per incident; out-of-band tuning input for future revisions of the depth cap.

## Consequences

1. `src/armor/detectors/entropy_decode.py` is rewritten from single-pass to bounded-recursive.
2. New configuration keys: `entropy.max_decode_depth`, `entropy.no_progress_margin_bits`.
3. `docs/spec/behaviors.md` B-006 is rewritten — the "Recursive decode is not supported" sentence is removed; the bounded-recursion contract replaces it.
4. New corpus rows under `tests/eval/corpus/exfiltration.yaml` family `multi_layer_encoding`: `b64(hex(canary))`, `hex(b64(canary))`, `urlencode(b64(canary))`, plus FP rows (`b64(b64(b64(benign)))` produces low-entropy intermediate at some depth and must not block).
5. Updated forensic-record schema: `details["decode_chain"]` is a new optional field.
6. **Latency regression target:** the existing `tests/fitness/test_llm_p95_latency.py` framework (helpers in `tests/fitness/_llm_p95_helpers.py`) gains a per-detector budget assertion for `entropy.decode_rescan`, capping P95 at 30 ms.

## See also

- ADR-014: output entropy policy (the original single-pass decision this ADR revises).
- behaviors.md B-006: the spec sentence this ADR rewrites.
- Internal design audit category *Multi-Layer Encoding*.
