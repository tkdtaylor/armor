# ADR-015: Destination whitelist source and format

**Status:** Accepted
**Date:** 2026-05-05
**Decider:** Architecture review

## Context

Task 011 implements an exfiltration detector that extracts URLs, IP addresses, and email addresses from model output and returns them as a destinations list. The detector needs a way to suppress advisories for legitimate, known-safe destinations (internal APIs, approved C2 servers, etc.) without blocking them entirely.

Multiple whitelisting strategies exist:

1. **Local TOML list** — Simple, no external dependencies, loaded once at daemon boot, immutable for daemon lifetime.
2. **Runtime HTTP fetch** — Fetch allowlist from external config server, requires network capability, violates no-network invariant of the daemon.
3. **Canary catalogue integration** — Whitelist destinations that are also known to be canary URLs (honeypots). Would require the canary catalogue to explicitly mark destinations as "honeypot URLs" or similar. Deferred to v0.3 when honeypot injection patterns are implemented.
4. **Per-check inline whitelist** — Allowlist passed in the request payload. Adds complexity to the check protocol; per-turn granularity not needed for v0.2.

## Decision

Use a **local TOML configuration key** (`destination_whitelist`) in `armor.toml`. The whitelist is loaded once at daemon boot and frozen for the daemon's lifetime. Default is an empty list `[]`, meaning no destinations are whitelisted by default (all extracted destinations produce `advisory` verdicts).

The whitelist uses **exact-match semantics only** — no wildcards, no globbing, no subdomain matching. A destination matches if it is identical to a whitelist entry (case-insensitive comparison).

**Rationale for each choice:**

- **Local TOML, not HTTP fetch**: Armor is designed to work air-gapped. Outbound network calls from the daemon are forbidden by the no-network invariant. The operator configures the whitelist once at deployment time, not dynamically.

- **Exact-match, not wildcard**: Exact-match keeps the whitelist small and predictable. Wildcard matching (e.g., `*.example.com`) would require prefix/suffix/glob logic and creates room for ambiguity (does `*.example.com` match `evil-prefix.example.com`?). If an operator needs fine-grained domain matching, they add specific entries (`api.example.com`, `auth.example.com`, etc.). Subdomain handling is deferred to v0.3+ if demand arises.

- **Frozen at boot, not re-read per check**: Configuration changes require daemon restart. This is consistent with the rest of the system (pipeline detectors are fixed at boot, canary catalogue is fixed at boot). A dynamic reload mechanism would add stateful complexity without clear v0.2 demand.

- **Not integrated with canary catalogue (deferred to v0.3)**: At v0.2, canaries are used to detect exfiltration (if a canary value leaks, block). At v0.3, honeypot URLs will be injected as canaries to trap the model into sending data to fake destinations. At that point, it makes sense to whitelist known-good honeypot URLs so the detector doesn't advisory on them. For now, keep the concerns separate: canaries detect leakage, destination whitelist suppresses known-good exfil attempts.

## Consequences

**Positive:**
- Simple, zero external dependencies, no network calls.
- Frozen configuration prevents accidental inconsistency mid-session.
- Exact matching is easier to reason about than glob patterns.
- Operators can easily edit `armor.toml` and restart the daemon to adjust the whitelist.

**Negative:**
- Wildcard/glob users must enumerate all subdomains explicitly.
- No dynamic reload without restart (if this becomes a pain point, v0.3 can add a SIGHUP handler).
- Defers honeypot-URL whitelisting to v0.3, requiring revisit when that feature lands.

## Notes

The whitelist key in `armor.toml`:

```toml
destination_whitelist = [
  "internal.example.com",
  "approved-api.vendor.com",
  "192.168.1.100"
]
```

Type: array of strings (case-insensitive, exact-match comparison).
Default: `[]` (empty, all destinations advisory).

The detector will read this config value at daemon boot and store it in an instance variable, using it for all subsequent checks. No re-read on failure; if the config value is corrupt or missing, it falls back to `[]` (safe default).

## Related ADRs

- **ADR-001**: Foundational stack — daemon architecture; config is loaded once at boot for consistency.
- **ADR-010**: Canary invariants (never leak canary values in logs; log canary_id instead). This ADR is about destinations, but the principle is similar — never leak sensitive data in logs.
