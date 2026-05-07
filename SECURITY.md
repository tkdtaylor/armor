# Security policy

armor is a security tool. Vulnerability disclosure is non-negotiable for this project.

## Reporting a vulnerability

**DO NOT file a public issue.** Public issues for security vulnerabilities are visible to attackers before a fix lands and put downstream users at risk.

Use one of these private channels instead:

1. **GitHub Security Advisory** (preferred): open a private advisory at <https://github.com/tkdtaylor/armor/security/advisories/new>. This creates a private discussion that only maintainers can see and lets us coordinate a fix without publishing the details.
2. **Email:** `tools@taylorguard.me` with subject prefixed `[armor-security]`. PGP-encrypted reports welcome but not required.

Please include:

- A clear description of the vulnerability and its impact (what an attacker gains).
- A minimal reproduction (input, expected vs. actual behavior, environment).
- Whether you've already disclosed this to anyone else.
- Whether you'd like public credit when the fix lands.

## What's in scope

armor is a defense-in-depth security layer for LLM agents. The following are **in scope** for security reports:

- **Detection bypass:** an attack input that should be detected (per the published threat model and red-team corpus) but is not.
- **Daemon vulnerabilities:** anything that crashes the daemon, leaks file descriptors, escalates privileges, or escapes the Unix-socket sandbox.
- **Canary leakage:** any path through which a canary value (not `canary_id`) reaches the forensic log, the quarantine table, an outbound network call, or a verdict's serialized form.
- **No-network invariant violation:** any code path inside `src/armor/daemon/` that makes an outbound network call (DNS, HTTP, etc.).
- **Quarantine encryption flaws:** weak key derivation, IV reuse, plaintext leakage of quarantined payloads.
- **IPC protocol vulnerabilities:** anything that lets a malformed IPC request return a `decision: pass` response or crash the daemon.

## What's out of scope

- **Side-channel attacks** (timing oracles, response-size oracles): on the v1+ roadmap, currently explicitly NOT defended against — see `docs/architecture/threat-model.md`.
- **Cross-tenant isolation:** armor is single-tenant by design. Issues based on multi-tenant scenarios are not in scope.
- **Compromised model weights:** if an attacker controls the model file you load, all bets are off — armor assumes the model file is trusted at boot.
- **Denial of service via input volume:** rate-limiting is the host application's responsibility.
- **Vulnerabilities in upstream dependencies that are already publicly disclosed and patched** in a newer version we haven't yet pulled in. Please file these as bug reports via the standard issue template referencing the upstream advisory.

## Disclosure timeline

- **Acknowledgement:** within 5 business days of receipt.
- **Fix target:** within 90 days for CRITICAL/HIGH severity; longer for MEDIUM/LOW with negotiation.
- **Coordinated disclosure:** we will agree on a public-disclosure date with the reporter before the fix is published. By default, disclosure happens on the day the fix lands in `main`.
- **CVE assignment:** we'll request a CVE for any vulnerability with a published fix, naming the reporter unless they request anonymity.

We do not currently offer a bug bounty.

## Threat model

The project's threat model is documented in [`docs/architecture/threat-model.md`](docs/architecture/threat-model.md) — read it before filing a report to confirm the issue falls within the defended-against surface.
