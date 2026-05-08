# ADR-032 — Canary catalogue expansion to the high-value-targets table

**Date:** 2026-05-07
**Status:** Accepted
**Decision date:** 2026-05-07
**References:** `archive/discussion.md` §11 (lines 418-477) *High-Value Targets List*; ADR-010 (catalogue storage); ADR-021 (honeypot prompt + value isolation); ADR-031 (honeyfs on-disk placement, §3 recipe table).

## Context

The 2026-05-07 audit of `archive/discussion.md` against the current spec surfaced that the bundled catalogue ships with **8 kinds × 3 entries = 24 canaries total**: AWS access keys, GitHub PATs, Stripe keys, generic URLs/paths/hostnames/emails, and crypto wallets. The original design table in `archive/discussion.md` §11 enumerates dozens of credential families an attacker realistically tries to extract — and several of the most relevant ones for an LLM-agent guardrail are entirely absent.

Notably missing from `src/armor/canaries/default_catalogue.json`:

- **Third-party LLM-provider keys** — `OpenAI sk-…`, `Anthropic sk-ant-…`, `Cohere`, `HuggingFace hf_…`. These are arguably *the* highest-value extraction targets in an LLM agent.
- **Source-control tokens beyond GitHub PAT** — `ghs_/gho_/ghu_/ghr_` (other GitHub token kinds), `glpat-…` (GitLab), Bitbucket app passwords.
- **Communication-platform tokens** — Slack `xoxb-/xoxp-/xoxa-`, Discord, Twilio `SK…`, SendGrid `SG.`.
- **Cloud-provider keys beyond AWS access keys** — AWS *secret* keys (paired with access keys; honeyfs §3 expects this pairing), GCP service-account JSON, Azure credential entries, Firebase, Google API `AIza…`.
- **Authentication artifacts** — JWT (`eyJ…` 3-part), SSH private keys (PEM with `-----BEGIN OPENSSH PRIVATE KEY-----`), TLS server certs + private keys.
- **Database / connection strings** — `mongodb://`, `postgres://`, `redis://`, `.pgpass` lines.
- **Wallet expansions** — Bitcoin WIF format, Ethereum 64-char hex, Solana base58, BIP39 seed phrases (12-/24-word), MetaMask vault JSON.
- **Webhook/internal-infrastructure URLs** — Slack/Discord webhook URLs in their canonical `hooks.slack.com/services/T…/B…/…` and `discord.com/api/webhooks/…` shapes.

ADR-031's recipe table (§3) already names many of these kinds (`gitlab-pat-*`, `slack-token-*`, `openai-key-*`, `jwt-*`, `cert-*`, `kube-config-*`, `db-password-*`); honeyfs cannot render them until the catalogue actually emits them.

## Decision

**Proposed.** Expand `src/armor/canaries/default_catalogue.json` to cover every kind named in ADR-031 §3's recipe table, plus the third-party LLM-provider keys called out above. Each new kind ships with:

- **`canary_id`** — sequential, kind-prefixed (e.g. `openai-key-000`).
- **`kind`** — taxonomy bucket (`credential | url | path | hostname | wallet | email | jwt | ssh-key | cert | kube-config | db-connection`).
- **`service`** — concrete provider (`openai | anthropic | gitlab | slack | …`).
- **`marker_rule`** — regex or algorithmic rule the canary scanner uses to validate that the install-time-generated value matches the expected shape (already part of the schema; ADR-010).
- **`active`** — boolean, default `true`.

Per-kind active counts: at least **3 entries per kind** (matching today's per-kind multiplicity), so a single leaked canary doesn't burn the entire kind for that installation.

### Candidate kinds and shapes

The full proposed inventory is intentionally not enumerated in this ADR — it would duplicate the recipe table in ADR-031 §3 and risk drift. The implementing task should treat ADR-031's recipe table as authoritative for kinds and add the LLM-provider-key kinds (`openai-key-*`, `anthropic-key-*`, `cohere-key-*`, `hf-token-*`) on top.

### Marker-rule strategy

For each new kind, the marker rule needs to satisfy two properties (per ADR-021 §1):

1. **Look real to an attacker** — the value passes a casual eyeball check (correct prefix, correct length, correct charset).
2. **Be deterministically identifiable to the canary scanner** — the value either matches a regex unique enough to avoid colliding with real credentials, or contains a known marker substring the install-time generator embeds.

Two approaches are on the table; choice is per-kind:

- **Shape-only marker** — generator picks a value matching the regex; the regex itself is the scanner's match rule. Works well for high-entropy formats (`AKIA[A-Z0-9]{16}`, `ghp_[A-Za-z0-9]{36}`).
- **Shape + embedded marker** — generator embeds a known short token (e.g. `HONEYPOT` or a daemon-installation-unique 8-char hex) inside the value. The scanner matches on the embedded marker. Necessary for low-entropy formats where shape alone collides with real values (e.g. BIP39 seed phrases — every 12-word phrase is "valid", so the marker needs to be one of the words at a known position).

## Open questions answered

Answered 2026-05-07.

1. **LLM-provider-key kinds in default catalogue?** → **Include.** `openai-key-*`, `anthropic-key-*`, `cohere-key-*`, `hf-token-*` ship as part of the default catalogue. Each entry's `Verdict.details["false_positive_risk"] = "high"` so operators tuning a workflow that legitimately discusses these key shapes can identify and exempt the rule. Maximum out-of-the-box protection given LLM-agent threat surface.
2. **JWT canaries — signed or random?** → **Random base64url segments** (no signing). A real JWT verifies; a canary doesn't need to. Recipients that try to verify get a parse/sig error after the canary scanner has already tripped.
3. **SSH private-key canaries — RSA or Ed25519?** → **Ed25519.** PEM body ~120 bytes vs RSA's ~3 KB; cheaper to embed in the honeypot prompt and on-disk recipe.
4. **Per-kind active count?** → **Per-kind override, default 3.** Pool sizes are tunable per kind in the catalogue schema; LLM-provider keys, AWS, and JWT may warrant 5+ entries based on corpus-driven tuning.
5. **Fitness function for catalogue/recipe-table sync?** → **Yes.** `tests/fitness/canary_kinds_match_recipe_table.py` asserts that every kind named in ADR-031 §3 is emitted by the catalogue, and vice versa.

## Consequences

1. New entries in `src/armor/canaries/default_catalogue.json` (schema only — values generated at install time per ADR-010).
2. `armor honeyfs install` (ADR-031 §4) renders more on-disk recipes by default once the catalogue grows.
3. Canary scanner's Aho-Corasick automaton grows by O(new-kinds × per-kind count) entries — negligible memory impact.
4. New corpus rows under `tests/eval/corpus/exfiltration.yaml` exercising each new kind's leak path.
5. `behaviors.md` B-002 list of canary kinds is updated.
6. Honeypot system prompt template (`src/armor/llm/prompts/honeypot.txt`) is regenerated per ADR-031 §5 to reference the new on-disk paths.
7. New fitness function `tests/fitness/canary_kinds_match_recipe_table.py` if Q5 is answered "yes".

## See also

- ADR-010: catalogue storage schema (the `kind`/`service`/`marker_rule` fields this ADR populates).
- ADR-021: honeypot prompt + value isolation (the prompt template this ADR forces a regeneration of).
- ADR-031 §3: per-kind on-disk recipe table — load-bearing for which kinds this ADR must add.
- `archive/discussion.md` §11 lines 418-477: original high-value-targets table.
