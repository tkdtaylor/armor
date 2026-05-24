# ADR-038 — Time-delayed / context-specific canaries

**Date:** 2026-05-07
**Status:** Accepted
**Decision date:** 2026-05-07
**References:** Internal design audit category *Time-delayed canaries*; ADR-010 (catalogue storage); ADR-031 §4 (`armor honeyfs rotate`); data-model.md `CanaryCatalogue`.

## Context

The current catalogue (per ADR-010 and data-model.md *CanaryCatalogue*) is **frozen at daemon boot** — the active set is loaded once and immutable for the daemon's lifetime. ADR-031 §4 introduced `armor honeyfs rotate` as the operator-driven primitive for swapping the active set, but rotation is a **whole-set replacement**, not a context-conditioned activation.

The design audit called out a finer-grained idea: **canaries that are active only in specific conversation contexts**. The motivation: a sophisticated attacker who has reconnaissance access (read-only shell inside the container) can enumerate every active canary value once, then craft injections that *avoid* those specific values — bypassing detection. If the active set varies by context, single-shot enumeration buys the attacker less.

Concrete scenarios where context-specific canaries would help:

- **Per-tool activation** — a `wallet-*` canary in the honeypot prompt is only active when the agent has used a `WebFetch` or external-URL tool in this session (i.e., when there is plausibly a destination for exfiltration). Outside that context the wallet canary is dormant; an attacker who reads the catalogue and avoids the wallet value gains no advantage if they never trigger the activating tool.
- **Per-time-window** — different canary subsets active in different daemon-uptime windows (e.g., week-of-the-year mod N). Forces an attacker to time their reconnaissance and exfil close together.
- **Per-session-state** — different canaries active when FSM state is `Watching` vs `Elevated` (the agent saw an injection signal and is now in a more aggressive honeypot regime).

## Decision

Extend the catalogue schema with an optional `activation` field (a structured rule) and the `Catalogue` loader to evaluate the activation rule per check rather than at boot. The active subset varies per check; the *full* catalogue (with all rules) remains frozen at boot.

### Schema extension

Add an optional `activation` field to each catalogue row:

```json
{
  "canary_id": "wallet-001",
  "kind": "wallet",
  "service": "ethereum",
  "marker_rule": "0x[a-fA-F0-9]{64}",
  "activation": {
    "type": "tool_used",
    "tool": "WebFetch",
    "scope": "session"
  },
  "active": true
}
```

Activation rule types (at minimum):

| Type | Meaning |
|---|---|
| `always` (default if `activation` absent) | Active in every check. Today's behavior. |
| `tool_used` | Active iff the named tool was used at least once in the current session. |
| `fsm_state_at_least` | Active iff the session FSM state ≥ named threshold (`Watching`, `Elevated`, `High`). |
| `time_window` | Active iff `(daemon_uptime_days + canary_id_hash) mod period == 0`. |
| `session_turn_min` | Active iff session turn count ≥ threshold (e.g. canary becomes active only after 10 turns; combats one-shot recon). |

The `Catalogue` exposes a new method `active_for(ctx: SessionContext) -> list[CanaryRow]` that filters by the activation rule. The Aho-Corasick scanner is rebuilt **per check** *only when the active subset changes from the previous call's subset* (cached by the hash of the active `canary_id` set). On a typical session, the subset changes a handful of times across hundreds of turns, so the per-check cost is negligible.

### Honeypot prompt regeneration

Per ADR-031 §5, the honeypot prompt references active canaries. With per-check activation, the prompt becomes **per-check** — the honeypot LLM sees only the credentials currently active for this session/check. Acceptable cost: prompt-string templating is single-digit microseconds.

### Honeyfs implications

ADR-031's recipe table installs files at canonical paths *unconditionally*. Time-delayed canaries do **not** change what's on disk — the on-disk values stay; the *scanner activation* changes. An attacker reading `~/.aws/credentials` always sees a canary value; the difference is whether that value is currently armed in the scanner.

This is intentional: rotating files on disk is expensive and conspicuous (new mtime on a credentials file is itself a giveaway). Rotating the *scanner's active set* is cheap and invisible.

### Compatibility

Existing catalogue rows without an `activation` field default to `{"type": "always"}` — fully backwards-compatible. ADR-031's recipe table and ADR-032's catalogue expansion ship without activation rules; this ADR is the optional layer on top.

## Open questions answered

Answered 2026-05-07.

1. **Fixed set of activation types or open-ended?** → **Fixed set** with a clear extension path: `always | tool_used | fsm_state_at_least | time_window | session_turn_min`. Open-ended invites a security-relevant DSL that needs its own threat-model entry.
2. **`tool_used` activation counts blocked attempts?** → **Yes.** An attempt is itself a signal of intent; the canary arms on attempt, not just successful tool calls.
3. **`fsm_state_at_least` after FSM cooldown?** → **Stays active for the rest of the session.** Once elevated-state canaries are revealed, dropping them re-exposes the post-cooldown session to the bypass this ADR addresses.
4. **`time_window` daemon-restart survival?** → **Anchor to wall-clock day-of-year** (mod period), not uptime. Restarts don't shift the activation schedule.
5. **Telemetry on activation rule efficacy?** → **Out-of-band tuning concern.** No specific instrumentation gated by this ADR; can be added later as needed.
6. **`armor honeyfs rotate` resets activation history?** → **No.** `rotate` swaps values, not session state. `tool_used` keeps remembering which tools were used; `session_turn_min` keeps counting turns.

## Consequences

1. Schema extension on `CanaryCatalogue` data-model entity (`activation` optional field).
2. New module `src/armor/canaries/activation.py` with the rule evaluator.
3. `Catalogue.active_for(ctx)` method; `CanaryScanner` rebuilds its automaton on subset change (with a cache).
4. Per-check honeypot prompt regeneration (existing `prompts/honeypot.txt` becomes a template; `honeypot.py` materializes it per call).
5. `data-model.md` updated for the schema extension; `behaviors.md` B-002 updated to note that the active subset is now per-check.
6. New corpus rows under `tests/eval/corpus/exfiltration.yaml` exercising activation rules (e.g., a turn that does *not* use `WebFetch` should not match a `tool_used:WebFetch` canary).
7. New fitness function: `tests/fitness/test_canary_activation_consistency.py` — assert that for any session, an activated-then-deactivated canary, if reactivated, produces the same value (not regenerated mid-session).
8. **Performance budget:** per-check active-set re-evaluation must complete in ≤ 1 ms. Aho-Corasick rebuild on subset change ≤ 5 ms. Both are well within the per-detector budget.

## See also

- Internal design audit category *Time-delayed canaries*.
- ADR-010: catalogue storage (the schema this ADR extends).
- ADR-031 §4: `armor honeyfs rotate` (the whole-set rotation primitive; this ADR is the per-check counterpart).
- ADR-024: session FSM (the source of `fsm_state_at_least` rule data).
