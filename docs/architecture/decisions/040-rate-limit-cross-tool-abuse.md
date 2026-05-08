# ADR-040 — Rate-limit-bypass / cross-service tool abuse detection

**Date:** 2026-05-07
**Status:** Accepted
**Decision date:** 2026-05-07
**References:** `archive/discussion.md` §7 Category 7 lines 345-346 *Rate Limit Bypass*, *Cross-Service Attack*; ADR-024 (session FSM); behaviors.md B-010 (tool param schema).

## Context

`archive/discussion.md` §7 Category 7 lines 345-346 calls out two tool-abuse vectors with no current coverage:

| Vector | Description (discussion) | Today's coverage |
|---|---|---|
| **Rate Limit Bypass** | Abuse rate limits via automation — high-frequency tool calls, retry-storms, parameter-permutation sweeps | None — `armor check tool` is per-call shape/risk validation only |
| **Cross-Service Attack** | Use one tool to attack another (e.g., `Read .env`, then `WebFetch` the contents to an attacker URL) | None — each tool call is validated in isolation |

The current `armor check tool` (B-010) validates **a single tool call's** shape and risk rules. It has no view of:

- How frequently this session has called `WebFetch` in the last minute.
- Whether the *combination* of "Read `.env`" + "WebFetch some-host" within N turns is a known attack chain.
- Whether parameter-permutation sweeps (`Read /etc/passwd`, `Read /etc/shadow`, `Read /etc/sudoers`, …) are happening.

Today's coverage is good at "is this individual tool call dangerous on its own" and bad at "is this *pattern* of tool calls dangerous in aggregate."

## Decision

**Proposed.** Add two session-level detectors under category `meta.tool_pattern`:

### Detector 1: `meta.tool_rate_anomaly` (advisory)

Tracks per-session, per-tool call counts in a sliding window. New configuration:

- `detector.tool_rate.window_seconds` (default `60`) — rolling window length.
- `detector.tool_rate.thresholds` (default per-tool table — see below) — calls-per-window-second above which to fire `advisory`.

Default per-tool thresholds (calls per 60 s):

| Tool | Threshold | Rationale |
|---|---|---|
| `WebFetch` | 10 | A real workflow rarely needs more than a handful of fetches per minute; bursts indicate scraping or beacon. |
| `Read` | 30 | Bursts of reads are common in code-exploration workflows; threshold set high to minimize FP. |
| `Bash` | 20 | Same logic as Read. |
| `Write` | 15 | Higher write volume is unusual outside scaffolding; tune from corpus. |
| `Grep` | 60 | Grep is naturally bursty (one user query → many greps); near no threshold. |
| (other) | 30 | Default for unknown tools. |

The detector fires `advisory(confidence)` where `confidence = min(1.0, observed / threshold - 1.0)` — once the threshold is crossed, confidence ramps with the overshoot.

State storage: extend the existing `Session` row with a per-tool sliding-window counter (or store in an in-memory cache keyed by session_id, garbage-collected with the session).

### Detector 2: `meta.tool_chain` (block / advisory depending on chain)

Pattern-matches sequences of tool calls in the session's recent history against a curated **attack-chain catalogue**. Each chain has a sequence template, a minimum match strength (loose / strict), and a verdict (advisory / block).

Initial chain catalogue (seed examples — full catalogue lives in a YAML file shipped alongside the detector):

| Chain | Match | Verdict |
|---|---|---|
| `Read(*.env)` → `WebFetch(*)` within 5 turns | strict | block |
| `Read(*.aws/credentials)` → any tool with the read content | strict | block |
| `Read(*.ssh/id_*)` → any output containing `BEGIN OPENSSH PRIVATE KEY` | strict | block |
| `Read(/etc/passwd)` → `Read(/etc/shadow)` → `Read(/etc/sudoers)` (parameter sweep) | loose | advisory |
| `Bash(git config user.email)` → `Bash(git config user.password)` (credential sweep) | loose | advisory |

Chain matching uses a **session log replay**: on every tool check, walk back through the recent N tool calls and try to extend any partially-matched chain template. A complete match fires the configured verdict.

This complements honeyfs (ADR-031): an attacker who reads `~/.aws/credentials` (a honey-file in the canonical sandbox container) and then `WebFetch`s anywhere triggers `meta.tool_chain` *in addition to* the canary scanner trip on the WebFetch payload — defense in depth.

### Coupling with FSM (per ADR-024)

Both detectors feed the FSM via the standard `apply_signal` path. `meta.tool_rate_anomaly` is advisory only; `meta.tool_chain` may emit `block` directly (matching a known attack chain is high-confidence) or escalate FSM to `Blocked` for the rest of the session.

## Open questions answered

Answered 2026-05-07.

1. **Default rate thresholds source?** → **Ship the proposed conservative-high values** (one-line "tune from corpus" note in the implementation task). The defaults in the threshold table above are starting points; corpus data drives ongoing refinement.
2. **Chain catalogue operator-extensible?** → **Yes.** Bundled chains in `src/armor/detectors/tool_chains.yaml`; operator-specific chains in `tool_chains.user.yaml` (path configurable). Cross-organization sharing deferred.
3. **Cross-session correlation?** → **Out of scope** for this ADR; a future ADR can extend the chain detector to correlate across `session_id` boundaries.
4. **Sliding-window storage?** → **In-memory** (lost on daemon restart). The rate-anomaly detector is most useful within a continuous session; persistence adds complexity without clear benefit.
5. **`meta.tool_chain` sees blocked calls?** → **No.** Chains only consider calls that completed (passed validation); blocked calls are recorded in the forensic log but don't contribute to chain matching.

## Consequences

1. Two new detectors `src/armor/detectors/tool_rate_anomaly.py`, `src/armor/detectors/tool_chain.py`.
2. New configuration block `[detector.tool_rate]` with the threshold table.
3. New bundled file `src/armor/detectors/tool_chains.yaml` — the seed chain catalogue.
4. `Session` data model gains a per-tool sliding-window counter (in-memory only; not persisted).
5. New behavior entries in `docs/spec/behaviors.md` for both detectors.
6. New corpus families `tool_rate_burst` and `tool_chain_attack` under `tests/eval/corpus/tool_abuse.yaml`.
7. Cross-reference with B-010 (per-call tool param schema) — same category, different scope (single-call vs aggregate).
8. **Coupling with ADR-031:** the seed chain catalogue includes patterns matching honeyfs's recipe paths (`Read(.aws/credentials)` etc.), so honeyfs and this detector together close the recon-then-exfil loop.

## See also

- `archive/discussion.md` §7 Category 7 lines 345-346.
- ADR-031: honeyfs (the recipe paths form the substrate for chain matching).
- ADR-024: session FSM (the signal aggregation substrate).
- behaviors.md B-010: per-call tool param schema (single-call counterpart).
