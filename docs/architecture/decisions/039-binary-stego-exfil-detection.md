# ADR-039 — Steganographic / file-binary exfiltration detection

**Date:** 2026-05-07
**Status:** Deferred (deferred-design ADR — no code ships)
**Decision date:** 2026-05-07
**References:** `archive/discussion.md` §7 Category 3 line 309 *Steganography*; ADR-014 (output entropy); ADR-033 (indirect injection).

## Context

`archive/discussion.md` §7 Category 3 line 309 names *"Steganography — hidden data in images/audio"* as an exfiltration vector. The current detector pipeline has no path that inspects binary file content — every detector operates on text payloads.

Real exfiltration via steganography is rare in the LLM-agent threat model **today**, because:

1. Most agent tools (`Read`, `WebFetch`, `Grep`) return text, not binary.
2. The agent itself does not natively encode data into images; it would have to emit a `Write` of a payload-bearing image, which presupposes a code-execution capability the model doesn't have intrinsically.
3. Image/audio steganography requires either a tool that produces media output (rare in agent tooling) or an MCP server that returns media (rare in practice).

The vector becomes load-bearing in two specific scenarios:

- **Indirect injection via image OCR** — covered by ADR-033 (Q: OCR scope, deferred).
- **Output exfiltration when the agent has access to a code interpreter that can produce images** — niche.

## Decision

**Proposed — deferred until corpus evidence.** This ADR documents the gap and the proposed v1+ approach so future work has a starting point, but explicitly **does not** ship a detector in the next release. The cost of binary-content inspection (a libmagic dependency, a steganography-specific scanner, and either OCR or audio-decoding subsystems) is not justified against the current attack surface.

The ADR is published in `Status: Proposed` rather than dropped entirely so that:

- A future operator who hits this attack class has a starting design.
- The discussion-audit cross-reference in ADR-031 remains complete.
- Re-opening is a one-line status flip plus implementation work, not a re-proposal.

### Proposed v1+ approach (when the work happens)

#### Detector 1: `meta.binary_payload` (advisory)

Triggers on tool-call payloads where the value is bytes (not str) or where the textual payload contains substrings matching known binary-format magic numbers (`PNG\x89`, `GIF89a`, `JPEG\xff\xd8`, `RIFF…WAVE`, …). Fires `advisory(confidence=0.5)` — not blocking, because legitimate workflows do involve binary data; the advisory feeds the FSM and gates the validator LLM for closer inspection.

#### Detector 2: `meta.image_steganography` (advisory)

For PNG/JPEG/GIF payloads above a size threshold:

- Strip the file to its raw pixel data.
- Compute the **LSB byte-bag entropy** — the entropy of the least-significant-bit plane across all pixels. Natural images have low LSB entropy (smooth gradients, JPEG quantization residue); LSB-stego payloads have high LSB entropy (random ciphertext written into LSBs).
- Fire `advisory` if LSB entropy > threshold (default 7.5 bits/byte).

Standard signal; widely-known LSB-stego detection technique. Not perfect (DCT-domain steganography evades LSB analysis), but the discussion's threat model describes naive amateur steganography, not state-actor-grade payload hiding.

#### Detector 3: `meta.audio_steganography` (advisory)

Same family as image: LSB analysis on PCM samples for WAV files. Skipped for compressed formats (MP3, AAC) — LSB stego doesn't survive lossy compression, so an attacker writing into a compressed format is doing something more sophisticated than this detector targets.

### Image dependency footprint

`Pillow` (~3 MB, MIT) covers PNG/JPEG/GIF/BMP. `wave` is stdlib for WAV. Total image-size impact: ~3 MB. Fine.

The work is dominated not by dependencies but by **corpus construction** — red-team rows demonstrating the attack are non-trivial to generate, and without them the detector's calibration is guesswork.

## Open questions answered

Answered 2026-05-07.

1. **Is this work wanted in v2+?** → **Status: Deferred-design.** No code ships. The threat-model cost-benefit does not justify the work for Claude Code's typical workflow. Reopen if (a) MCP servers proliferate that return media, (b) operator field reports show this vector being used.
2. **OCR coupling with ADR-033?** → **Distinct ADRs.** OCR-as-indirect-injection (ADR-033) is about *text hidden in images that ends up in agent context*; this ADR is about *bytes hidden in images that exit as exfiltration*. Different attack shapes, different detectors.
3. **Run on Write or Read?** → **Both** (when implemented), with different signal weights — outbound stego (Write) is more concerning than inbound (Read, which is also partially covered by ADR-033).

This ADR is published as a **deferred-design ADR**: it documents the gap and the proposed approach so future operators have a starting design, but ships no code in this batch. Re-opening is a one-line status flip plus implementation work.

## Consequences

1. **No code change shipped under this ADR.** This is a deferred-design ADR.
2. When/if the work happens: new detectors `meta.binary_payload`, `meta.image_steganography`, `meta.audio_steganography` under `src/armor/detectors/`.
3. New dependency `Pillow` pinned in `pyproject.toml`.
4. New corpus family `binary_steganography` under `tests/eval/corpus/`.
5. ADR-033's OCR-deferred decision is unchanged by this ADR — they cover different attack shapes.

## See also

- `archive/discussion.md` §7 Category 3 line 309.
- ADR-033: indirect injection (the adjacent attack class — text in images, vs this ADR's bytes in images).
- ADR-014: output entropy (the existing entropy-based detection family this would extend).
