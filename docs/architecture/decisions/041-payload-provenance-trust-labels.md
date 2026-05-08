# ADR-041 — Payload provenance / trust labels (calibration, not gating)

**Date:** 2026-05-07
**Status:** Accepted
**Decision date:** 2026-05-07
**References:** ADR-033 (indirect injection — supersedes its `SessionContext.payload_source` proposal); `archive/discussion.md` §7 Category 2; tasks 065, 075; `docs/spec/data-model.md` `Payload` and `SessionContext` entities.

## Context

The 2026-05-07 design conversation surfaced that armor has **no first-class concept of payload provenance**. Today's `Payload` carries `text`, `tool`, `params` — no marker for *where the data came from*. The only crude trust differentiation is the IPC op name (`check.input` = user; `check.output` = model; `check.tool` = tool params), which is *behavioral* (which pipeline runs) rather than *data-typed* (the payload doesn't carry its own provenance).

ADR-033 (indirect injection) noticed the gap and proposed `SessionContext.payload_source: "user" | "model" | "fetched" | "tool"` as a workaround. That proposal is **wrong-shaped** for two reasons:

1. **Provenance is a property of the data, not the session.** Ten checks within one session can each have different provenance; putting the marker on `SessionContext` forces every detector to remember to pass it correctly per-call and conflates session-level state with per-payload metadata.
2. **It's gating, not calibrating.** ADR-033's intent — "encoding-request detector returns `pass` when source is `fetched`" — treats provenance as a binary on/off switch for whole detectors. A better model: provenance is a **calibration parameter** that scales detector outputs (confidence, severity) to reflect how strict we should be with each finding.

The audit also surfaced a real-world dogfooding constraint: **with strict indirect-injection scanning enabled, building armor itself would have been blocked.** Reading [archive/discussion.md](../../archive/discussion.md) (a transcript explicitly *about* prompt injection), reading the eval corpus (every TP row *is* an attack string), web-fetching prompt-injection research, and reading our own `regex_*.py` source files would all FP against the indirect-injection pipeline. Antivirus must exempt its own definition files; the same property is required here.

## Decision

Add a first-class **payload provenance label** that scales detector strictness, plus an **exemption mechanism** for paths/sources the operator declares off-limits to indirect-injection scanning.

### 1. `Payload.source` — typed enum, lives on `Payload`

Replace the never-implemented `SessionContext.payload_source` proposal from ADR-033 with `Payload.source: Source`:

```python
class Source(StrEnum):
    USER_INPUT             = "user_input"
    MODEL_OUTPUT           = "model_output"
    TOOL_PARAMS            = "tool_params"
    TOOL_RESULT_TRUSTED    = "tool_result_trusted"
    TOOL_RESULT_UNTRUSTED  = "tool_result_untrusted"

@dataclass(frozen=True)
class Payload:
    text: str = ""
    tool: str | None = None
    params: dict[str, object] | None = None
    source: Source = Source.USER_INPUT  # default for backwards compat
```

The IPC op name is the **default mapping** (the daemon assigns the source on op routing), and the request can override it explicitly:

| IPC op | Default `Payload.source` | Explicit override allowed |
|---|---|---|
| `check.input` | `USER_INPUT` | yes (e.g. CLI for testing) |
| `check.output` | `MODEL_OUTPUT` | yes |
| `check.tool` | `TOOL_PARAMS` | no — the params *are* the model's output |
| `check.fetched` (new, per ADR-033) | `TOOL_RESULT_UNTRUSTED` | yes — `--source-tool` and an operator allowlist may upgrade to `TOOL_RESULT_TRUSTED` |

### 2. Calibration via per-source multipliers (not gating)

Each detector returns its raw verdict as today. The pipeline applies a **single per-source multiplier** to confidence before the verdict materializes:

```
adjusted_confidence = raw_confidence × source_multiplier[payload.source]
adjusted_verdict    = scale_to_decision(adjusted_confidence, advisory_threshold, block_threshold)
```

**Default multipliers** (tunable per ADR via `armor.toml`):

```toml
[pipeline.source_multipliers]
user_input            = 1.0   # baseline
tool_params           = 1.0   # already through tool-schema validation
model_output          = 1.0   # canary / entropy detectors are calibrated for this
tool_result_trusted   = 0.5   # operator vouched; surface but soft-pedal
tool_result_untrusted = 1.5   # the indirect-injection vector; bump strictness
```

Multipliers apply to **all detectors that accept that source**. Some detectors are structurally meaningless on certain sources (running `cmd_injection.bash` against `USER_INPUT` is wasted compute) — those combinations are gated by the detector itself returning `pass` early; the multiplier is a *strictness* knob layered on top of the detectors that do apply.

The simpler-than-matrix shape (one multiplier per source, applied uniformly) is intentional: per-(detector × source) cells are over-engineering until corpus evidence shows specific cells need different multipliers. Operators get one knob per source dimension; per-detector calibration emerges from each detector's own confidence formula. If corpus tuning later shows we need finer granularity, this ADR is superseded.

`canary.scanner` and `canary.paraphrase` are notable: a verbatim canary leak is a leak regardless of source. Their internal confidence formula is high enough that even at 0.5× they still produce blocks — provenance softens, but doesn't suppress, the canary signal.

### 3. Exemption mechanism — paths/domains that bypass scanning entirely

Distinct from the trust multiplier: certain content is **research material**, not an attack vector. Reading the eval corpus to debug a detector, fetching a CTF writeup to extract a new pattern, or reading our own `regex_*.py` to mirror a structure must not FP against the indirect-injection pipeline.

```toml
[pipeline.exempt]
read_paths = [
  "tests/eval/corpus/**",       # the corpus IS attack data
  "archive/**",                 # historical / research material
  "docs/architecture/decisions/**",
  "docs/spec/**",
  "discussion.md",              # the project's bootstrapping discussion
  "**/regex_*.py",              # our own detector patterns
]
webfetch_domains = [
  "owasp.org",
  "huggingface.co/papers/**",
  "arxiv.org/**",
  "github.com/anthropic-ai/**",
]
```

When the hook (per task 065) is about to call `armor check fetched <text> --source-tool <tool>`, it first checks the path/domain against `pipeline.exempt.*`. If matched, the hook skips the call entirely — the daemon never sees the payload, no incident is logged, no pipeline runs. This is the cheapest possible escape valve and keeps the daemon-side simple (no special-case logic for self-exemption).

### 4. Default exemption list ships in the bundled `armor.toml`

The defaults above are bundled with the package. A fresh install does the right thing for security-research workflows out of the box — no operator action required to develop *on* armor or other security projects with similar shape. Operators can tighten the list by removing entries (e.g., a deployment that doesn't host security research can drop `arxiv.org/**`).

### 5. Self-aware first-boot warning

If the daemon starts in a directory that contains `src/armor/` and `tests/eval/corpus/` (i.e., the operator is developing armor itself), log one warning line at startup:

```
WARN: armor running from inside an armor-development tree. Consider enabling
      pipeline.exempt.read_paths for tests/eval/corpus/, archive/, and similar
      research paths to avoid false positives on your own corpus.
```

This is **advisory only** — it does not gate startup, does not auto-add exemptions, does not modify config. It just makes the friction discoverable. The operator chooses.

### 6. Default-protect, power-user-informed-opt-out

The design philosophy: armor must be **useful in active form for end users by default**, AND **not interfere with informed power users building security-adjacent projects**. Concretely:

- The default multipliers favor protection (UNTRUSTED bumped to 1.5×, not 1.0×).
- The default exemption list is *narrow* — it covers the unambiguous research-material cases (corpus, ADRs, archive, well-known security research domains) but does NOT broadly exempt project roots, home directories, or git repos.
- An operator developing a new security tool that doesn't fit the bundled exemption pattern must read the boot warning, read the documentation, and explicitly add their paths. They're informed, they accept the risk, and the friction is bounded to a one-time config edit.

This trades off correctly: the *casual* operator gets strong protection for free; the *expert* operator gets a clearly-marked escape valve. Neither is broken to serve the other.

### 7. Threat-model entry

A new boundary `§11. Dogfooding limitation: armor does not scan its own development inputs by default` lands in `docs/architecture/threat-model.md`. It documents:
- The exempt-path mechanism and its rationale
- The *trust assumption*: an operator-configured exemption is operator-vetted
- The *threat*: an attacker who can write to an exempt path (e.g., commits malicious content to `tests/eval/corpus/`) bypasses indirect-injection scanning. Defense: the exempt paths are on the operator's local filesystem under their control; this is the same trust boundary as their git repo's content. Out of scope: protecting an operator from themselves.

## Rationale

1. **Provenance is per-payload, not per-session.** Putting `source` on `Payload` is the only honest model — different checks within one session legitimately have different provenance, and the data should carry its own label.
2. **Calibration is finer-grained than gating.** A regex match in `USER_INPUT` and the same match in `TOOL_RESULT_UNTRUSTED` aren't binary-different — they're confidence-different. The multiplier model captures that without forcing per-detector folklore about which sources to skip.
3. **Simple multiplier beats matrix at v1.** Per-(detector × source) cells are a 2D config explosion that operators don't yet have evidence to populate. One knob per source is enough until corpus tuning proves otherwise.
4. **Exemptions are first-class, not bolted on.** Without an exemption mechanism, building armor itself with armor running is impossible — and any operator working on adjacent security tools hits the same wall. Shipping the mechanism + sensible defaults is the only way the tool is *usable* in active mode for the audience that builds security-adjacent things.
5. **Defaults protect the casual operator; opt-out is informed.** The boot warning makes the friction discoverable without auto-disabling protection. The casual operator never has to think about exemptions; the expert operator finds the escape valve clearly.
6. **Supersedes ADR-033's `SessionContext.payload_source`.** ADR-033 was right about needing a source marker, wrong about where to put it. This ADR fixes the location and generalizes the consumer.

## Consequences

1. **`src/armor/types.py`** gains:
   - `Source` StrEnum
   - `Payload.source: Source` field (default `Source.USER_INPUT` for backwards compat)
2. **`src/armor/daemon/server.py`** assigns `Payload.source` based on op routing (defaults table above) before invoking the pipeline.
3. **`src/armor/pipeline.py`** applies the per-source multiplier to detector verdicts before composition. The multiplier table is loaded from `pipeline.source_multipliers` in `armor.toml`.
4. **`armor.toml`** gains two new top-level blocks:
   - `[pipeline.source_multipliers]` (5 keys, defaults above)
   - `[pipeline.exempt]` (`read_paths` array, `webfetch_domains` array)
5. **`docs/spec/data-model.md`** `Payload` entity — add `source: Source` field with the enum values.
6. **`docs/spec/configuration.md`** — document both new config blocks plus the bundled-defaults policy.
7. **`docs/spec/behaviors.md`** — extend B-005 (pipeline composition) to mention multiplier application; new section "Source-aware calibration" describing the model.
8. **`docs/architecture/threat-model.md`** — new §11 *Dogfooding limitation*.
9. **`docs/architecture/overview.md`** — add a short paragraph on payload provenance / trust labels in the data-flow section.
10. **Hook script (per task 065)** — reads `pipeline.exempt.read_paths` and `pipeline.exempt.webfetch_domains` from a path the daemon exposes (e.g. `armor config show --section pipeline.exempt`) before deciding whether to call `armor check fetched`.
11. **Backwards compatibility:** `Payload.source` defaults to `USER_INPUT`. Existing callers (CLI, SDK pre-update) that don't set the field continue to work; they're treated as user input. No breaking change for SDK v0.x consumers.
12. **Fitness function:** `tests/fitness/test_payload_source_propagation.py` asserts that every `check.*` IPC path sets `Payload.source` correctly per the defaults table. Wired into `scripts/fitness.sh`.
13. **ADR-033 amended:** the `SessionContext.payload_source` field is *removed* from ADR-033's design; ADR-033 now references this ADR for the source mechanism. Task 065 implements the source on `Payload` directly.

## Open questions answered

Answered 2026-05-07 (in-conversation, before drafting).

1. **Where does the source label live?** → `Payload.source` (per-payload), NOT `SessionContext.payload_source` (per-session).
2. **Taxonomy?** → 5 labels: `USER_INPUT | MODEL_OUTPUT | TOOL_PARAMS | TOOL_RESULT_TRUSTED | TOOL_RESULT_UNTRUSTED`.
3. **Gating or calibration?** → **Calibration** (multiplier on confidence). Detectors run on every applicable source; strictness scales with provenance.
4. **Multiplier granularity?** → **Per-source uniform multiplier** (option b). One knob per source, applied across all detectors that accept that source. Per-(detector × source) matrix is over-engineering until corpus evidence demands it.
5. **Default multipliers?** → `user_input=1.0`, `tool_params=1.0`, `model_output=1.0`, `tool_result_trusted=0.5`, `tool_result_untrusted=1.5`. Tune from corpus.
6. **Default for `Read` of an unmarked path?** → **TRUSTED** (multiplier 0.5). Most Reads in a typical Claude Code workflow are operator-owned files. UNTRUSTED is opt-in via the exemption-mechanism inverse — operators add specific paths to the indirect-injection pipeline if they want them scanned more strictly. Combined with the exempt-paths list, this gives a workable low-friction default.
7. **MCP responses default?** → **UNTRUSTED**. MCP servers are operator-installed, but the *content* they return often comes from external sources (Slack messages, Linear tickets, web pages); treat as untrusted by default with operator-configurable per-MCP override.
8. **Exemption mechanism?** → **Yes** — `pipeline.exempt.read_paths` (glob list) and `pipeline.exempt.webfetch_domains` (glob list). Hook checks these BEFORE calling `armor check fetched`; daemon never sees exempt content.
9. **Default exemption list?** → Ships in bundled `armor.toml`: `tests/eval/corpus/**`, `archive/**`, `docs/architecture/decisions/**`, `docs/spec/**`, `discussion.md`, `**/regex_*.py`, plus `owasp.org`, `huggingface.co/papers/**`, `arxiv.org/**`, `github.com/anthropic-ai/**` for webfetch.
10. **Self-aware boot warning?** → **Advisory only** — log a one-line WARN at daemon startup if `cwd` looks like an armor-development tree. Does NOT gate startup, does NOT auto-add exemptions.
11. **Design philosophy?** → **"Default-protect; power-user-informed-opt-out."** Casual operators get strong protection for free; expert operators get a clearly-marked escape valve. Neither audience is broken to serve the other.

## Alternatives considered

- **Keep `SessionContext.payload_source`** (ADR-033's original proposal). Rejected — wrong shape; provenance is per-payload, not per-session. Forces every detector to remember to pass the field per-call.
- **Per-(detector × source) multiplier matrix.** Rejected for v1 — over-engineering. Adopt if corpus tuning reveals specific cells need different multipliers.
- **Trust as binary gating** (detector either runs or doesn't, based on source). Rejected — too coarse. The same regex shape in USER_INPUT vs UNTRUSTED carries different signal strength; binary gating throws away that information.
- **Auto-enable broad exemptions when armor detects an armor-dev tree.** Rejected — silent default-disable of a security feature based on heuristic detection violates the "default-protect" principle. The advisory boot warning makes the friction discoverable without compromising defaults.
- **Whitelist `read_trusted_paths` instead of `read_untrusted_paths` inverse.** Considered. Both shapes work; the chosen shape (default TRUSTED multiplier 0.5, with `pipeline.exempt.read_paths` as a hard escape and operator opting *into* stricter scanning per-deployment) is simpler. A future ADR can add `read_strict_paths` if corpus evidence shows a need.
- **No exemption mechanism, just very-low multipliers (e.g. 0.05) on TRUSTED**. Rejected — soft-pedaling still surfaces verdicts that have to be triaged. Exemptions are the cleaner model for "this is research material, do not even run the pipeline."

## See also

- ADR-033: indirect-injection detection (consumer of this primitive; supersedes its own `SessionContext.payload_source` proposal in favor of `Payload.source`).
- ADR-031: honeyfs (per-recipe canaries on disk; orthogonal — canaries trip regardless of source per §6 above).
- ADR-024: session FSM (the multiplier feeds `apply_signal` confidence; FSM thresholds are unchanged).
- `docs/architecture/threat-model.md` §11 *Dogfooding limitation* (added in the implementation commit).
