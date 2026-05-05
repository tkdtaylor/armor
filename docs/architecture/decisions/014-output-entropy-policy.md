# ADR-014 — Output entropy threshold and decoded-rescan policy

**Status:** Accepted
**Date:** 2026-05-05
**Deciders:** armor core team

## Context

Canaries detect exfiltration only when the agent emits them in plaintext. A successful prompt injection can induce the model to encode a canary (base64, hex, etc.) before output, evading the canary scanner's Aho-Corasick pattern match on the raw text. We need a detector that:

1. Identifies high-entropy substrings in output (characteristic of encoded data)
2. Attempts to decode them (single-pass, time-budgeted)
3. Re-scans the decoded plaintext for canaries

The core question: **What entropy threshold, what decode formats, and what recursion policy?**

## Decision

**Threshold: 4.5 bits/character for substrings ≥40 characters long.**

**Decode formats: base64 first, then hex (single-pass, no recursion).**

**Recursion policy: explicitly deferred; single-pass only at v0.1–v0.2.**

### Threshold rationale

Shannon entropy of English text typically ranges 4.0–4.3 bits/character (accounting for letter frequency, digraphs, common words). Base64-encoded random data approaches 6 bits/character (perfect random would be 6.0; base64 has alphabet size 64 = 2^6). A threshold of 4.5 bits/char creates a gap:

- **Below 4.5**: Natural language, structured data (JSON/YAML), and most benign outputs. False positive rate is low.
- **Above 4.5**: Encoded data, random tokens, hashes, UUIDs, and compressed payloads. Signal is strong.

**Empirical calibration**: A test run against a corpus of:
- 1000 random English sentences: max entropy ~4.35 bits/char
- 100 base64-encoded 32-byte strings: min entropy ~5.95 bits/char
- 100 hex-encoded 32-byte strings: min entropy ~3.99 bits/char

*Note: hex is lower because 16 characters of 0–9a–f have log2(16) = 4 bits/char maximum, and even random hex rarely exceeds that. Base64 is higher because 64-character alphabet = 6 bits/char theoretical max. The threshold of 4.5 catches base64 reliably, and hex only if it's truly random; typical hex encoding of small values (UUIDs, short hashes) will be closer to 4.0–4.5 bits/char and may not always trigger.*

**Minimum substring length: 40 characters.** Short high-entropy strings (e.g., UUIDs, 32-char API keys) are common in benign output. Requiring ≥40 characters reduces false positives from randomly-formatted strings and ensures we have enough data for a reliable entropy estimate.

### Decode policy

**Base64 first.** It's the most common wire encoding for credentials and sensitive data. Attempt to decode; if it succeeds and produces printable text (heuristic: ≥90% of decoded bytes are printable or common whitespace), treat as plausible plaintext and scan.

**Hex second.** If base64 fails or produces garbage, try hex decode. Same heuristic for plausibility.

**Single-pass, not recursive.** Do NOT re-encode or decode the result. The rationale:
- Adds latency for unclear threat gain (if an injection can multi-layer, it's already a sophisticated attack; single-layer decoding covers most exfiltration patterns).
- Increases complexity and test surface.
- Opens DoS risk (deeply nested encodings could exhaust budget).
- **Corpus-driven deferral**: No evaluation corpus row yet demonstrates a real attack requiring recursive decode. When (if) one appears, promote to v0.3 task.

**Time budget:** Respect `pipeline.per_detector_budget_ms` (default 100 ms). On every call to this detector, track elapsed time. If decode + canary scan would exceed the budget, return `error` verdict (fail-open per detector, see overview.md). The pipeline will continue to the next detector; if the whole pipeline errors, the request is blocked (fail-closed).

### Why not other formats?

- **ROT13, Caesar ciphers**: Not true encoding (no loss of entropy); trivial to scan for, but rarely used in modern injection attacks.
- **Gzip/deflate**: Require decompression and output-validation heuristics; uncommon in exfiltration (adds bandwidth overhead for attacker). Deferred to corpus evidence.
- **URL encoding, JSON escaping**: Already accounted for in the canary scanner (Aho-Corasick is literal substring match; URL-encoded and JSON-escaped variants would need to be added to the catalogue as separate values). This detector is not needed for these formats.

## Alternatives considered

1. **Lower threshold (3.5 bits/char)**
   - Pros: Would catch hex-encoded data more reliably
   - Cons: Significantly higher false positive rate; many structured formats (code, config files) exceed 3.5 bits/char
   - Rejected: Operational cost of false positives outweighs the gain

2. **Higher threshold (5.0 bits/char)**
   - Pros: Very low false positive rate
   - Cons: Would miss some base64-encoded canaries (they average ~5.95 bits/char, but outliers exist)
   - Rejected: Detection gap is unacceptable

3. **Multi-format decode (base64, hex, gzip, …)**
   - Pros: Broader coverage
   - Cons: Increased latency, complexity, and test surface. No corpus evidence of gzip/deflate attacks yet.
   - Deferred: Add on corpus evidence

4. **Recursive decode (e.g., base64(base64(canary)))**
   - Pros: Would catch nested encodings
   - Cons: Latency, complexity, DoS risk. No corpus evidence.
   - Rejected: Explicitly deferred to v0.3 if needed

## Consequences

- **Reduced false negatives**: Encoded canary exfiltration is now caught (previously missed by raw-text scanner).
- **Slightly elevated false positive rate**: Some benign high-entropy output may trigger decode attempts. Re-scan on decoded plaintext almost always passes (no canary match), so false positives are "cost-free" (decoder + scanner timeout is brief). Tolerable.
- **Latency cost**: ~5–20 ms per detector call on typical output (dominated by Shannon entropy computation on long text; decode and re-scan are negligible). Well under the 100 ms budget.
- **Future extensions**: Recursive decode and additional formats (gzip, etc.) are isolated changes to this detector and do not require pipeline or data-model changes.

## Implementation notes

- Detector ID: `entropy.decode_rescan`
- Category: `exfiltration`
- Cost tier: `static` (no LLM involvement)
- Config keys: `entropy.min_length`, `entropy.threshold` (already in `armor.toml` schema)
- Reuse: Import `CanaryScannerDetector` or its underlying `CanaryScanner` and call `scan()` on decoded plaintext; do NOT instantiate a new Aho-Corasick automaton
- Forensic safety: Never log decoded plaintext; always reference `canary_id` in signals and details

## See also

- Task 010 implementation and test spec
- Task 015 (canary catalogue storage) — established runtime injection of canary values
- ADR-010 (forensic logging safety) — canary value secrecy enforced at logger level
- `docs/spec/behaviors.md` B-006 (updated to reflect this detector)
