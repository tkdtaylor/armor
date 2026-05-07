# ADR-025 — Rolling buffer sizing and cooldown interaction

**Date:** 2026-05-06
**Status:** Accepted
**Task:** 023
**Authors:** Kevin

## Context

Task 023 introduces rolling-window exfiltration detection to defeat chunked canary leakage. An attacker can emit fragments of a secret across multiple turns, evading single-turn detectors. The rolling buffer aggregates the last N outputs and re-scans them for canary matches and entropy anomalies.

Key questions to resolve:
1. **Buffer sizing:** What are sensible defaults for `capacity_chars` and `capacity_turns`?
2. **Cooldown interaction:** When the session state steps back to Normal (cooldown), should the buffer reset or persist?
3. **Partial-match threshold:** At what prefix length of an active canary should we emit a partial-match advisory?

## Decision

### Buffer sizing: 8 KB characters, 20 turns

**Choice:**
- `capacity_chars: 8192` (8 KB)
- `capacity_turns: 20`

Eviction is FIFO from the front; whichever limit is hit first triggers eviction.

**Rationale:**

- **8 KB characters:** A typical LLM output turn is 500–2000 characters. 8 KB = ~4–16 turns worth of content. This balances:
  - **Attack window:** Long enough to hold a fragmented AWS key (AKIA key is ~40 chars; splitting across 5 turns with context = ~200 chars per turn = needing ~1 KB). A chunked GitHub PAT (ghp_ keys are ~40 chars) has similar requirements. 8 KB allows an attacker to leak even verbose fragments across 5–10 turns comfortably.
  - **Memory footprint:** SQLite on-disk storage is negligible; the constraint is pipeline latency. Re-scanning 8 KB against the Aho-Corasick automaton takes ~1–2 ms.
  - **False negatives:** Smaller buffers (e.g., 2 KB) risk missing an attack split across many short turns.
  - **False positives:** Larger buffers (e.g., 64 KB) increase noise (benign output over 30+ turns is likely to contain a random substring that matches a common prefix).

- **20 turns:** A session's typical interaction is 3–7 turns. 20 turns covers extended sessions (research, brainstorming, code review) without requiring per-user tuning. Holding 20 turns × ~1 KB per turn = ~20 KB per session is acceptable for the in-memory cache + SQLite persistence. An attacker leaking over 20 turns is already highly suspicious; the session state machine will have escalated to `High` or `Blocked` by then.

### Cooldown interaction: buffer persists across cooldown

**Choice:** When the session steps back to Normal (post-cooldown), the rolling buffer does NOT reset. It persists.

**Rationale:**

- **Attack continuity:** A clever attacker could space their fragments across many turns, wait for the cooldown to fire, and resume. If the buffer resets on cooldown, the fragments before and after the cooldown boundary are not scanned together. Persistence defeats this strategy.
- **Cooldown semantics:** Cooldown is decay in *risk score*, not amnesia. If the attacker hasn't changed their behavior (still fragmenting), the session should still see the aggregate evidence.
- **Implementation:** Persistence is the natural default (the buffer is stored in SQLite; we load it on session access). Resetting would require explicit logic, which adds code and test burden for a weak rationale.
- **Trade-off:** If the buffer never resets, a very long session could accumulate noise from legitimate activity. This is addressed by the `capacity_chars` and `capacity_turns` limits; after 20 turns, the oldest turns are evicted. A months-long session would naturally see the buffer window slide forward.

**Alternative considered:** Reset on step-back to Normal. This would require explicit code and a database trigger or cleanup logic. The added complexity is not justified by the security benefit — the state machine's thresholds already gait escalation, and the buffer size itself is the safety valve.

### Partial-match threshold: 12 characters

**Choice:** `detector.canary.partial_match_min_chars: 12`

**Rationale:**

- **False positives:** A random 12-character substring is unlikely to collide with a canary prefix by chance. Common English bigrams and trigrams are 2–3 chars. A 12-char prefix (e.g., "ghp_12345678" or "AKIA1234567") is specific enough.
- **Attack window:** The first 12 characters of an AKIA key or GitHub PAT are enough to identify the family and hint at the full secret. An attacker fragmenting a 40-char key across 4 turns could emit 10 chars per turn, hitting 12 on the 2nd turn. A 12-char threshold catches this quickly.
- **Advisory vs block:** A partial match triggers an `advisory` signal (increments session risk, feeds into `apply_signal`), not a block. If the partial is later followed by more fragments and the full canary matches, the block signal fires. The advisory allows the session to escalate without false-positive blocking.

**Alternative considered:** 8 characters (more aggressive, higher false-positive risk; "AKIA" family prefix + 4 random chars still identify the key). The 12-char threshold is conservative and data-driven from the canary format itself.

## Spec updates (same commit)

1. **`behaviors.md`** — Add B-NNN: "Rolling-buffer exfiltration detection: concatenate the last N outputs, re-scan for canaries and entropy anomalies, emit block on chunked-canary match, emit advisory on partial-canary prefix ≥ K chars."
2. **`data-model.md`** — Add `SessionRollingBuffer` table schema (session_id FK, turn_id, text, created_at).
3. **`configuration.md`** — Add keys:
   - `session.rolling_buffer.capacity_chars: 8192` (default)
   - `session.rolling_buffer.capacity_turns: 20` (default)
   - `detector.entropy.rolling_threshold: 4.5` (bits/char, distinct from per-turn threshold)
   - `detector.canary.partial_match_min_chars: 12` (characters)

## Implementation notes

- The `RollingBuffer` class (in-memory) is a simple bounded deque; SQLite persistence is the source of truth. On session load, reconstruct the buffer from the `SessionRollingBuffer` table (newest-first, reverse to append order, then trim to capacity).
- Pipeline integration: After per-turn detectors run, append the output to the buffer. Then run the canary scanner and entropy analyzer against `buffer.concatenated()` using the rolling thresholds.
- Quarantine: A chunked-canary block quarantines all turn IDs in the buffer, not just the current turn.
- No explicit reset on cooldown — the buffer persists. The `capacity_turns` sliding window and per-turn eviction is the safety valve.

## Consequences

1. Sessions with extended output will naturally accumulate buffer state; cleanup happens on session close (task 028 future work).
2. The rolling-buffer table grows on every output check; a `vacuum` policy on session end or 24h cleanup (ADR-011) is required.
3. Partial-match advisories will increase session risk score; operators should tune `session.thresholds.watching` and `session.thresholds.elevated` based on corpus data.

## Deferred

- **Inference-time streaming:** The buffer operates on completed outputs only. Stream-chunked detection (mid-generation) is v1+ work.
- **Cross-session replay:** Attackers coordinating across multiple sessions; v1+ backlog.

---

## Acceptance

- Status: Accepted
- Date: 2026-05-06
- Task: 023
- Reviewed by: (implicit with task spec)

## References

- Task 023 — Implementation and test spec (rolling buffer)
- ADR-024 — Session state machine (the rolling buffer feeds `apply_signal` for partial-match escalation; FSM gates which detectors run)
- Task 022 — Session state machine (defines escalation via `apply_signal`)
- ADR-001 — SQLite session store (the rolling buffer is persisted in a new `session_rolling_buffer` table on the same database)
- ADR-027 — Multi-turn eval corpus format (corpus rows reference task 023)
