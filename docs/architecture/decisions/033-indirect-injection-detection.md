# ADR-033 — Indirect / second-order injection detection

**Date:** 2026-05-07
**Status:** Accepted
**Decision date:** 2026-05-07
**References:** `archive/discussion.md` §7 Category 2 (lines 295-301) *Indirect / Second-Order Injection*; ADR-031 (honeyfs); ADR-024 (session FSM).

## Context

The current detector pipeline runs only on **first-party text payloads**: user input (`armor check input`) and model output (`armor check output`), plus tool-call shape/risk validation (`armor check tool`). It has no detection on **second-hand text** that enters the agent's context via tool results — the discussion's Category 2:

| Vector | Where it enters | Today's coverage |
|---|---|---|
| Malicious document upload (PDF/Word/HTML embedded prompt) | `Read` tool returns content; agent treats it as data, model treats it as instructions | None |
| Website fetch poisoning | `WebFetch` tool returns page content; injected `<!-- ignore previous instructions -->` block | None |
| Database field injection | An MCP server returns a row whose `notes` field contains an injection | None |
| Email / message injection | A mail-fetching MCP returns a message body with hidden instructions | None |
| Image-text (OCR) injection | An image-reading tool returns extracted text containing instructions | None |

This is now arguably **the most important attack class** for a tool-using agent, because: (a) Claude Code routinely calls `Read`, `WebFetch`, `Grep`, and any number of MCP servers whose results land directly in the model's context; (b) the user-side `check input` pipeline never sees these payloads.

## Decision

**Proposed.** Add a new check operation **`armor check fetched`** (working name) that runs the input-side detector pipeline against tool-call *results* before they reach the agent's context. The Claude Code integration wires this on `PostToolUse` for read-side tools (`Read`, `Grep`, `Glob`, `WebFetch`, MCP `read_*` patterns, …) — the daemon receives the tool result body and replays the input-side regex family against it (instruction-override, roleplay-hijack, system-prompt-extraction, encoding-request, authority-impersonation per Task 061), plus the validator LLM gated by session state.

### Three integration shapes considered

1. **Wrap the tool result via PostToolUse** *(recommended)* — Claude Code's `PostToolUse` hook fires after the tool returns; the hook calls `armor check fetched`. On `block`, the hook replaces the tool result with a sanitized stub (e.g. `[armor: tool result blocked — see incident <id>]`) before the model sees it. Pros: no protocol change to the agent; stops injection at the trust boundary. Cons: requires hook profile updates; the model still sees *something*, so the stub itself must be unambiguous.
2. **Pre-flight via PreToolUse on the *next* turn** — read the prior turn's tool results from the session log. Pros: works without PostToolUse. Cons: too late — the model has already read the injection.
3. **MCP middleware** — a small armor-MCP server that other MCP servers chain through. Pros: clean for MCP-only deployments. Cons: doesn't cover Claude Code's built-in `Read`/`WebFetch`; deferred.

### Detector reuse

The existing input-side detectors (regex_instruction_override, regex_roleplay_hijack, regex_system_prompt_extraction, regex_encoding_request, jailbreak_template, llm_validator) are reused **as-is**. The new op is a routing primitive, not a new detector class — it points an existing pipeline at a different payload boundary.

### File-content scanning specifics

For binary or structured tool results (PDF/Word/image/HTML), a content-extraction shim runs *before* the detector pipeline:

- **HTML** — strip tags, run on visible text + `alt`, `title`, comment nodes (injections love HTML comments).
- **PDF** — extract text with a small dependency (`pdfminer.six` or `pypdf`); scope: text only, no OCR.
- **OCR-on-images** — **out of scope for v1.** The discussion lists it; the cost (Tesseract or similar in the daemon image, ~150 MB) is too high relative to the marginal coverage. Defer to a future ADR if corpus evidence shows it matters.

### Pipeline placement

`check fetched` runs **before** the agent's context is updated, on the `PostToolUse` boundary. A blocked tool result generates a forensic incident with `attack_category="indirect_injection.<vector>"` and the destination side (the tool name) recorded in `details["source_tool"]`.

## Open questions answered

Answered 2026-05-07.

1. **Integration shape?** → **PostToolUse hook only.** `armor check fetched` fires from the Claude Code `PostToolUse` hook on read-side tools (Read, WebFetch, Grep, Glob, MCP `read_*`). On block, the hook substitutes a sanitized stub for the tool result. MCP middleware integration is deferred to a future ADR — the PostToolUse path covers Claude Code's built-in tools AND any MCP without a second integration surface.
2. **Stub message format?** → `[armor: tool result blocked — incident <id>]`. Short, unambiguous, references the forensic record so an operator can investigate without the model hallucinating around an empty result.
3. **Length cap?** → **4 KB chunked windows.** Tool results above 4 KB are processed in 4 KB windows; first chunk to trip wins; remaining chunks are recorded in the forensic incident's `details["additional_chunks"]` array but do not generate additional verdicts.
4. **Whitelist for safe sources?** → **Yes.** `pipeline.fetched_source_whitelist` configuration key (default empty); a tool-result whose source-tool name matches the whitelist skips the pipeline.
5. **Encoding-request detector on tool results?** → **`SessionContext.payload_source` field.** New field with values `user | model | fetched | tool`; encoding-request detector returns `pass` when source is `fetched` (a wiki page about base64 must not block).
6. **FSM coupling?** → **Yes, lower weight.** `indirect_injection.*` blocks escalate the FSM via the standard `apply_signal` path, but the per-detector weight is `0.5` (vs the default `1.0` for direct-injection blocks) — the agent didn't try to attack, the content did.
7. **OCR scope?** → **Deferred.** Cost (Tesseract ~150 MB) too high relative to coverage; revisit when corpus evidence demands.

## Consequences

1. New op `check.fetched` in the daemon IPC protocol (data-model.md *Wire / interchange formats*).
2. New CLI subcommand `armor check fetched <text> --source-tool <name>`.
3. Hook clients gain a new `PostToolUse` profile entry (Claude Code integration).
4. New `SessionContext` field `payload_source: "user" | "model" | "fetched" | "tool"`.
5. New corpus family `indirect_injection` under `tests/eval/corpus/`.
6. New behavior `B-012: Detect indirect injection in tool-call results` in `docs/spec/behaviors.md`.
7. New cross-container edge in `docs/spec/architecture.md` cross-container edges table: *PostToolUse hook → daemon → check.fetched*.
8. Threat-model addition: §10 *Indirect injection via tool-call results* in `docs/architecture/threat-model.md`.
9. Optional dependency: `pdfminer.six` or `pypdf` for PDF text extraction. Pinned in `pyproject.toml` under an `[indirect]` extra so the daemon image stays slim if the operator opts out.

## See also

- `archive/discussion.md` §7 Category 2 lines 295-301: the threat-model rows this ADR addresses.
- ADR-031: honeyfs — the bait-placement counterpart; ADR-031 places the bait, ADR-033 catches the recon.
- ADR-024: session FSM — the FSM-coupling decision in Q5 wires here.
