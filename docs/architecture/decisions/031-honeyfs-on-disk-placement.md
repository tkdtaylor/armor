# ADR-031: Realistic on-disk placement of canary honey-files (`honeyfs`)

**Status:** Accepted
**Decision date:** 2026-05-07
**Task:** TBD (will spawn one or more tasks under a follow-up `honeyfs` epic)
**Authors:** Kevin
**Open questions resolved:** 2026-05-07 — see *Acceptance — Open questions answered* below.

## Context

Canary tokens today exist in exactly two places:

1. The honeypot system prompt at inference time, after `_substitute_canary_values()` runs in `armor.llm.honeypot.respond` (per ADR-021).
2. A 0o600 values JSON file written post-install by `armor canary generate` (per ADR-010), at the path the operator passes to `--canary-values-path`.

That covers the scenario where an attacker prompt-injects the agent and the *honeypot LLM* hands the canary back in plaintext. It does **not** cover the scenario where a tool-using agent pivots from "ask the LLM" to filesystem reconnaissance — `cat ~/.aws/credentials`, `find / -name '*.pem'`, `ls ~/.ssh/`, `xxd ~/.bitcoin/wallet.dat`. Today those return either nothing or the operator's real credentials. Neither is a useful detection signal.

The original design discussion (now archived as `archive/discussion.md`, §11 *High-Value Targets List*, lines 418-477) enumerated a comprehensive table of credential types attackers attempt to extract — AWS keys, GitHub PATs, GitLab/Slack/Discord tokens, Stripe/Twilio/SendGrid keys, SSH private keys, JWT tokens, `.env` files, `~/.aws/credentials`, `~/.ssh/config`, BIP39 seeds, Ethereum/Solana/Bitcoin private keys, MetaMask wallets, internal hostnames, webhook URLs, K8s secrets, OpenAI/Anthropic/Cohere/HuggingFace tokens. Each row carried a realistic example value with an embedded marker. That table is the inventory this ADR builds on; the gap it leaves open is **where** those values live on disk so that a recon-then-exfil agent encounters them in the same locations a real engineer would store them.

This ADR establishes how `armor` lays canaries down at realistic filesystem locations — what we'll call **honeyfs** — and the lifecycle that keeps them from colliding with operators' real credentials.

## Decision

### 1. Placement target — inside the agent's sandbox container, at canonical real-world paths, with no giveaway naming

The single most important constraint: **honey-files must land in the filesystem the agent's tools actually read, at the paths a real engineer would store credentials, and nothing in those paths can hint that the files are bait.** Per the original Docker-as-sandbox design intent (`archive/discussion.md` §5), the daemon container *is* the agent's runtime environment in the canonical deployment; honeyfs places files inside that container at canonical real-world paths.

| Target | Where it works | Where it fails | Verdict |
|---|---|---|---|
| Daemon/sandbox container filesystem at canonical paths (`/root/.aws/credentials`, `/root/.ssh/id_ed25519`, …) | The agent's tools execute inside this container in the original sandbox-mode design; files at canonical paths are *exactly* where a real user keeps them | Doesn't help when the agent runs entirely outside the container (e.g. Claude Code on bare host without the agent containerized inside armor) | **Default** for the in-container deployment shape — the canonical pattern from `archive/discussion.md` |
| Per-project sandbox directory with armor-named root (`<project>/.armor-honey/`) | No collision risk | **Tips off any attacker with read access to the container** — a directory called `.armor-honey` (or `.armor`, `.honey`, `.canary`, `.trap`) is an obvious bait marker | **Reject** (originally proposed; user feedback corrected this) |
| Agent host filesystem (the user's `$HOME`) when the agent runs on the bare host (Claude Code) | Maps the in-container default to the host equivalent | Risk of clobbering real credentials; mutation outside the project root requires explicit operator consent | **Opt-in** — gated behind `armor honeyfs install --target $HOME --confirm`, opt-out by default |
| Shared volume mounted by both daemon and agent containers | Works for sibling-container deployments | Requires Compose/k8s mount configuration the operator must own | **Supported** as a documented recipe; not a default |
| MCP-served virtual honey-FS | No filesystem mutation; works in read-only environments | Requires the agent to enable an MCP; deeper integration; v2+ scope | **Defer** to a follow-up ADR |

**The naming rule.** Nothing visible to a process inside the container — file paths, directory names, environment variables, file contents, manifest paths — can contain the strings `armor`, `honey`, `canary`, `trap`, or any other word that signals "this is a trap." A read-only attacker who runs `ls -laR /` inside the container should see what looks like a populated developer environment, not bait. This rules out the original `<cwd>/.armor-honey/` sandbox proposal and any `.armor-canary` suffix pattern; the only places the string `armor` may appear are:

- Inside daemon-only artifacts that are not visible to the agent (the SQLite manifest table inside `armor.db`, daemon log lines, the daemon process name).
- In *proper* product naming on disk paths the agent doesn't read (the daemon binary, the daemon's own data dir).

A new fitness function (`tests/fitness/honeyfs_no_giveaway_paths.py`) walks every install profile and asserts that no recipe path or rendered file content contains a banned substring (`armor|honey|canary|trap|fake|bait|decoy`).

### 2. Conflict policy — fresh-container default; explicit consent for host installs

The in-container default deployment installs into a freshly-built container image where canonical credential paths are empty. Conflicts with real files don't arise — the container is the sandbox; nothing real lives there. The install proceeds unconditionally.

The host-install opt-in (`--target $HOME --confirm`) is the only mode where collisions are possible, and it preserves the never-overwrite semantics of the original proposal:

- **Path doesn't exist** → write the honey-file at the canonical path.
- **Path exists and is identical to one we previously wrote** (verified by SQLite manifest hash, see §4) → re-emit (idempotent re-install).
- **Path exists and is not in our manifest** → **abort the entire install** with a diff-style report. The operator must then either move their real file, install into a freshly-prepared user account, or run inside a dedicated container (the canonical mode).

The previously-proposed `--side-by-side` sentinel-suffix mode is **rejected** because the suffix would itself be a giveaway naming string visible to the agent (per §1's naming rule).

The collision check is by-path, not by-content. We never read an existing file we don't own.

### 3. Per-credential-kind file recipes

For every entry in the canary catalogue, honeyfs needs to know:
- The realistic on-disk **path**, rooted at the resolved `$HOME` of the user the agent runs as inside the container (or at canonical system locations like `/etc/ssl/private/` for service credentials).
- The realistic **file format** (INI, YAML, JSON, OpenSSH PEM, plain dotenv, binary wallet blob, etc.).
- The realistic **permissions** (most credential files are `0o600`; SSH directories `0o700`).
- The **surrounding content** that would normally live in such a file (e.g. an AWS credentials file has a `[default]` section header, a `region`, and the `aws_access_key_id` / `aws_secret_access_key` pair — the canary alone is not enough).

The initial recipe table (drawn from `archive/discussion.md` §11 + standard tool conventions, scoped to v1). Paths shown relative to `$HOME` unless prefixed with `/`:

| Catalogue kind | On-disk path | File format | Mode | Notes |
|---|---|---|---|---|
| `aws-key-*` | `.aws/credentials` | INI (`[default]` profile, `aws_access_key_id`, `aws_secret_access_key`, `region`) | 0600 | Pair access + secret keys; both are canaries |
| `aws-key-*` (config) | `.aws/config` | INI | 0600 | Companion file with `region`, `output` |
| `github-pat-*` | `.config/gh/hosts.yml` | YAML (`github.com:` block with `oauth_token`, `user`, `git_protocol`) | 0600 | Matches `gh auth login` output exactly |
| `gitlab-pat-*` | `.config/glab-cli/config.yml` | YAML | 0600 | Matches `glab auth login` |
| `ssh-key-*` (private) | `.ssh/id_ed25519` and `.ssh/id_rsa` | OpenSSH PEM with `-----BEGIN OPENSSH PRIVATE KEY-----` headers | 0600 | Public counterpart `*.pub` written too |
| `ssh-key-*` (config) | `.ssh/config` | OpenSSH config syntax (`Host` blocks pointing to canary hostnames from the `hostname-*` kind) | 0600 | Reinforces the trap — the Host entries reference canary hostnames |
| `kube-config-*` | `.kube/config` | YAML (`clusters`, `users`, `contexts` triple) | 0600 | `users[].user.token` is the canary |
| `gcp-key-*` | `.config/gcloud/application_default_credentials.json` | JSON service-account key | 0600 | Standard ADC layout |
| `azure-key-*` | `.azure/credentials` | INI | 0600 | Matches `az login` cache |
| `db-password-*` | `.pgpass` and `<project-root>/.env` | `host:port:db:user:pass` for `.pgpass`; `KEY=value` for `.env` | 0600 | Pair the canary into both — operators expect either |
| `stripe-key-*` | `<project-root>/.env` (line `STRIPE_SECRET_KEY=...`) | dotenv | 0600 | One of several env vars in a populated `.env` |
| `openai-key-*`, `anthropic-key-*` | `<project-root>/.env` | dotenv | 0600 | Same `.env` file, different lines |
| `slack-token-*`, `discord-token-*`, `sendgrid-key-*` | `<project-root>/.env` | dotenv | 0600 | Same |
| `wallet-*` (Bitcoin) | `.bitcoin/wallet.dat` | Binary blob with realistic header bytes + the canary serialized in | 0600 | Plausible binary shape (`bitcoind` magic header + version + version + a record block referencing the canary). Cryptographic correctness is not required — see §3 *Wallet realism* below |
| `wallet-*` (Ethereum) | `.ethereum/keystore/UTC--2024-01-01T00-00-00Z--<wallet-address-canary>.json` | Standard Web3 keystore JSON (kdf, ciphertext, iv, mac fields) | 0600 | Filename convention matters as much as content |
| `wallet-*` (MetaMask) | `.config/metamask/vault.json` | Encrypted-blob JSON shape (`{"data": "...", "iv": "...", "salt": "..."}`) | 0600 |  |
| `wallet-*` (Solana) | `.config/solana/id.json` | JSON byte-array shape | 0600 | Solana CLI convention |
| `wallet-*` (BIP39 seed) | `Documents/recovery-phrases.txt` | Plain text | 0600 | Common careless storage location |
| `jwt-*` | `<project-root>/.env` (line `JWT_TOKEN=...`) | dotenv | 0600 |  |
| `cert-*` | `/etc/ssl/private/server.pem` and `/etc/ssl/private/server.key` | PEM | 0600 (root-owned) | Pair cert + key at the canonical TLS-server location |
| `path-*`, `url-*`, `hostname-*` | Referenced from inside the structured files above (e.g. a `.ssh/config` `Host` entry pointing to a `hostname-*` canary, an `.env` `WEBHOOK_URL` line referencing a `url-*` canary) | n/a | n/a | These kinds become *content* inside the file recipes, not standalone files |
| `email-*` | `.gitconfig` (`user.email`) and `<project-root>/.env` (`SUPPORT_EMAIL=...`) | INI / dotenv | 0644 / 0600 |  |

The recipe table is **per-kind**, not per-canary. Each catalogue entry's `kind` field selects the recipe; the entry's generated value fills the relevant slot. A second `slot` field (added to the schema in a follow-up task) names *which* slot inside a multi-slot recipe (e.g. `aws-key-001` fills `[default].aws_access_key_id`; `aws-secret-001` fills `[default].aws_secret_access_key`).

**Wallet realism — plausible shape, not cryptographic correctness.** Binary and encrypted-keystore wallet recipes ship as **pure-Python in-process renderers** with no external dependencies (no shell-out to `eth-keyfile`, `bitcoin-cli`, or similar) — this keeps the daemon image self-contained and the install reproducible. The renderers produce files that match the *shape* a tool like `bitcoind`, `geth`, or `metamask import` expects (correct magic bytes, correct top-level JSON keys, correct filename conventions, correct file modes), but the embedded ciphertext / KDF blocks are **opaque random bytes**, not actual encryptions of the canary. This is intentional: an attacker doing reconnaissance reads the file, scans for credential-shaped substrings, and exfiltrates what they find — at which point the canary scanner trips on the embedded canary value. An attacker who instead tries to *load* the file with the real tool gets a parse error, but by then the recon has already happened and the bait is already inside the rolling output buffer. Spending engineering on real cryptographic correctness adds no detection power.

### 4. Lifecycle — unified install pipeline, single comprehensive default, SQLite manifest

honeyfs install is the **unified install pipeline** for canary values: it generates fresh per-deployment values, registers them with the live in-memory `Catalogue` (so the post-output canary scanner sees them immediately — see §6), persists them to the existing operator-controlled values JSON for restart durability, and lays them down on disk under their per-kind recipes. There is no longer a separate `armor canary generate` step that produces values divorced from the on-disk files; the previous CLI command becomes an alias of `armor honeyfs install --files-off` for backwards compatibility.

A new CLI subcommand group, `armor honeyfs`:

- `armor honeyfs install [--profile <name>] [--values-file <path>] [--target <root>] [--confirm]`
  - **Default profile is `comprehensive`** — every recipe in the table is rendered. The operator is not expected to modify this; the comprehensive default maximizes attack-surface coverage on a fresh container.
  - **Profiles are extensible.** A second-class `armor.toml` block (e.g. `[honeyfs.profiles.minimal]`) lets operators define custom profiles by listing recipe kinds to include or exclude. The shipped `comprehensive` profile is just the default; operators who want a smaller set author their own.
  - `--target` defaults to the resolved `$HOME` of the user the daemon (and therefore the agent in the canonical sandbox-mode deployment) runs as. Host-install on bare metal still requires `--target $HOME --confirm` per §1.
  - `--values-file` defaults to the existing `daemon.canary_values_path` so a daemon restart re-loads the same values (no canaries lost on bounce).
- `armor honeyfs status`
  - Queries the SQLite manifest, walks each recorded path, reports which files are still present, modified, or missing. Returns structured output suitable for monitoring.
- `armor honeyfs uninstall`
  - Removes every file the manifest claims responsibility for. Refuses to remove a file whose hash on disk doesn't match the recorded post-install hash (an operator or the agent may have edited it; better to leave it).
- `armor honeyfs rotate`
  - Generates a fresh value set, swaps the live `Catalogue`, rewrites the values JSON, and re-renders every manifest-tracked file with the new values. Old values are *removed* from the catalogue at the end of the swap so the scanner stops emitting matches on stale bait. Useful after a suspected leak or on a regular cadence.

The **manifest is a SQLite table inside the existing `armor.db`** (not a JSON file at a giveaway path), with this schema:

```sql
CREATE TABLE honeyfs_manifest (
  id INTEGER PRIMARY KEY,
  recipe_kind TEXT NOT NULL,         -- e.g. "aws-creds-ini", "ssh-private-pem"
  on_disk_path TEXT NOT NULL UNIQUE, -- absolute, post-resolve
  canary_ids TEXT NOT NULL,          -- JSON array
  mode INTEGER NOT NULL,             -- e.g. 0o600
  sha256_after_write TEXT NOT NULL,
  installed_at TEXT NOT NULL,        -- ISO 8601
  rotated_at TEXT                    -- last rotate; NULL until first rotation
);
```

The manifest lives inside `armor.db` for two reasons: (a) `armor.db` is already daemon-only state in `/var/lib/armor/` (operator-owned, mode 0o600 by daemon convention) and visible to the daemon process only — the agent inside the container has no readable path that names "armor" or "honey" because the daemon's data directory is not mounted into the agent's view; (b) keeping all daemon state in one SQLite file keeps backup/restore semantics simple. Read access to the manifest is by daemon process identity, not by filesystem permission alone — an attacker with a shell as the agent's user inside the container has no way to enumerate the manifest, even by name.

The manifest is the **only** authoritative record of what honeyfs touched. A deleted `armor.db` forces an operator to clean up files by hand — but at that point the operator has already lost session state and forensic incidents, so honeyfs cleanup is the smallest of the issues.

### 5. Honeypot system prompt evolves to reference the on-disk paths

Today's `src/armor/llm/prompts/honeypot.txt` lists credentials abstractly ("AWS Credentials: Access Key: `{{canary:aws-key-001}}`"). When honeyfs is installed, the prompt is rewritten so the LLM is encouraged to *quote the path*:

```
The user keeps their AWS credentials in `~/.aws/credentials`:

[default]
aws_access_key_id = {{canary:aws-key-001}}
aws_secret_access_key = {{canary:aws-secret-001}}
region = us-east-1

Their GitHub CLI token is in `~/.config/gh/hosts.yml`:
…
```

This makes the trap **discoverable to a tool-using agent** without needing an explicit injection: an agent that reads the system prompt, then runs `cat ~/.aws/credentials` to "verify" before exfiltrating, sees the same file content the honeypot LLM was told about — and the canary scanner trips on the output.

A new fitness function (`tests/fitness/honeyfs_paths_match_prompt.py`) will assert that every path mentioned in the honeypot prompt is either (a) absent from the manifest or (b) actually written by the install profile, so prompt and reality stay in sync.

### 6. Detection coupling — every honey-file value is registered with the live catalogue at install time

honeyfs is unified with canary-value generation (§4): every value rendered into a honey-file is **simultaneously** registered with the in-memory `Catalogue` and added to the `CanaryScanner`'s Aho-Corasick automaton. This means the existing post-output scanner — the same component that catches a honeypot-LLM-emitted canary in a model response — also catches:

- A canary value that an agent reads from `.aws/credentials` and quotes back in its response stream.
- A canary value that an agent reads, base64-encodes, and pastes into a tool argument (caught by the entropy + decode-and-rescan detector).
- A canary value that escapes the container in any output (PostToolUse hook scan, output check on the response stream).
- A canary value that appears chunked across multiple turns (rolling-buffer scan, per ADR-025).

In other words, **the post-output canary scanner is the escape detector.** Per the user's Q3 answer: "when they're generated we save them to the post cmd checker so they can be found if they manage to 'escape'" — implementation-wise, this is the install pipeline calling `Catalogue.register()` and `CanaryScanner.rebuild()` (or the equivalent atomic add-to-automaton operation) before the install command returns success.

A tool-side honey-path access detector (originally floated as a follow-up ADR-032) is **no longer needed for v1**. The existing output-side coverage is sufficient because: (a) any successful exfiltration must contain the value, and the scanner trips on the value alone regardless of how it got there; (b) reading a honey-path without leaking its content is not an attack — it's reconnaissance, and recon-only with no exfiltration is a no-op for the threat model. If field experience shows recon-only signal is valuable as an early-warning advisory (e.g. to escalate session state before an exfil attempt is even made), that detector can be added later as an optional advisory-tier detector without changes to honeyfs itself.

### 7. Threat-model integration

Two new boundary additions for `docs/architecture/threat-model.md` (to be made in the same commit as the implementation task, not this ADR):

- **§7. Sandbox container ↔ honey-files.** Trust assumption: the daemon owns its data directory; the agent (running as a non-root user inside the container) does not. Threat: a privilege-escalated process inside the container reads the daemon's data directory and discovers the SQLite manifest, learning which paths are bait and which are real (in a future deployment that mixes both). Defense: the daemon's data directory is not bind-mounted into the agent's process view in the canonical container image (Docker `USER` separation); read access to `armor.db` requires the daemon's UID. An attacker who escalates to the daemon's UID has already compromised the trust boundary that backs every other guarantee in this system, so honeyfs is not the load-bearing defense in that scenario.
- **§8. Manifest integrity.** A `armor.db` row tampered between install and uninstall could either (a) cause `uninstall` to skip files (leaving stale honey-credentials around) or (b) cause `uninstall` to delete a file the operator legitimately owns at the same path (only relevant in the host-install opt-in mode). Defense: every manifest row records `sha256_after_write`; uninstall refuses to remove a file whose current hash doesn't match. Worst case is a leftover honey-file that the operator removes by hand.
- **§9. Predictability of values via container introspection.** A read-only attacker inside the container can read every honey-file content (the values are in plaintext at the canonical paths — they have to be, to bait the agent). This means a one-shot disclosure exposes the value set. Defense: `armor honeyfs rotate` regenerates and re-registers values, atomically retiring the old ones from the catalogue scanner. Operators on a known-compromised host should rotate immediately; the values themselves are not secrets in the cryptographic sense — they're disposable detection markers.

## Rationale

1. **Container is the consent boundary; in-container default is friction-free.** A freshly-built sandbox container is a known-empty filesystem; installing into it at canonical paths needs no `--confirm` because there is nothing to overwrite. Mutating an operator's bare-metal `$HOME` is a much stronger change and remains explicit-opt-in.

2. **No giveaway naming.** A read-only attacker inside the container who runs `ls -laR /` should see what looks like a populated developer environment, not bait. Any path, file, or directory name containing `armor`, `honey`, `canary`, `trap`, `fake`, `bait`, or `decoy` defeats the entire premise — enforced by the `honeyfs_no_giveaway_paths.py` fitness function.

3. **Per-kind recipes, not per-canary.** A canary value is a string. A *credible* trap needs the surrounding INI/YAML/PEM/JSON scaffolding. Coupling the recipe to `kind` keeps the canary catalogue small and stable while letting the on-disk layer evolve.

4. **Manifest in SQLite, not on disk.** The manifest is daemon state, not user-visible artifact. Putting it in `armor.db` removes the discoverability problem entirely and aligns with how every other piece of daemon state (sessions, incidents, FSM rows) is stored. Hash-checked uninstall remains the seatbelt against accidental over-delete.

5. **Unified install pipeline.** Generating values, registering them with the live `Catalogue`, persisting the values JSON for restart durability, and rendering on-disk recipes — all in one atomic step. Stale-vs-fresh ambiguity windows are eliminated; the post-output scanner sees every value the moment honeyfs admits a file exists.

6. **Prompt and on-disk content must agree.** If the honeypot prompt says the AWS key is in `.aws/credentials` and the file isn't there, an agent that does the obvious double-check exits the trap. The fitness function makes drift loud.

7. **Output-scanner coverage is sufficient.** honeyfs is a *bait-placement* concern; detection is already covered by the existing canary scanner. Per Q3 the install pipeline registers every generated value with the live `Catalogue` immediately, so an "escape" — a value leaving the container in any output — trips deterministically. No new detector is needed for v1.

8. **Plausible shape beats cryptographic correctness for wallet recipes.** An attacker reading `wallet.dat` and exfiltrating its content trips on the value alone; a tool that tries to decrypt the file gets a parse error but only after the recon has already happened and the bait is already in the rolling buffer. Pure-Python in-process renderers keep the daemon image self-contained.

9. **Drawing on `archive/discussion.md` §11 keeps the catalogue scope honest.** The original design table named the credential types attackers actually go after; the recipe table here is the on-disk realization of that inventory. Nothing new is invented — the ADR just chooses *where* each row of the original table lives on disk.

## Consequences

1. **New CLI subcommand group:** `armor honeyfs install|status|uninstall|rotate`. `armor canary generate` becomes an alias of `armor honeyfs install --files-off` for backwards compatibility.
2. **New module:** `src/armor/honeyfs/` with one renderer per recipe kind (`aws_creds_ini.py`, `gh_hosts_yml.py`, `ssh_private_pem.py`, `kube_config_yaml.py`, `web3_keystore_json.py`, `bitcoin_wallet_dat.py`, …). Each renderer is a pure function `render(values: dict[str, str]) -> bytes`; testable in isolation; no external deps.
3. **Schema extension:** the canary catalogue gains an optional `slot` field (e.g. `aws_access_key_id`, `aws_secret_access_key`) to disambiguate entries that share a recipe.
4. **SQLite migration:** new `honeyfs_manifest` table inside `armor.db` (schema in §4); migration shipped as part of the implementation task.
5. **Catalogue + scanner integration:** the install pipeline atomically appends generated values to the in-memory `Catalogue` and rebuilds the `CanaryScanner` Aho-Corasick automaton before reporting success — so a successful `armor honeyfs install` guarantees that any subsequent output containing one of those values trips the post-output scanner. `rotate` performs the inverse atomic swap (new values added, old values removed) so stale bait stops emitting matches.
6. **Honeypot prompt regeneration:** `prompts/honeypot.txt` is regenerated at install time from the same recipes so the prompt and on-disk reality stay in sync.
7. **New fitness functions:** `tests/fitness/honeyfs_paths_match_prompt.py` (paths in the prompt match the manifest) and `tests/fitness/honeyfs_no_giveaway_paths.py` (no path or rendered content contains banned substrings `armor|honey|canary|trap|fake|bait|decoy`).
8. **Threat-model expansion:** three new boundaries (§7 sandbox container ↔ honey-files, §8 manifest integrity, §9 predictability of values via container introspection).
9. **Corpus rows:** new red-team scenarios under `tests/eval/corpus/scenarios.yaml` exercising the recon-then-exfil chain (`ls .aws/`, then `cat .aws/credentials`, then a tool call that exfiltrates the read content).
10. **Documentation:** README *Limitations* bullet updated — "armor's honey-files default to canonical paths inside the sandbox container with no giveaway naming; opt into the same layout on a bare-metal host with `armor honeyfs install --target $HOME --confirm`."
11. **Dockerfile entrypoint update:** the canonical container's entrypoint runs `armor honeyfs install` once on first boot (idempotent via SQLite manifest check) so a freshly-pulled image is bait-ready without operator intervention.

## Alternatives considered

- **Bake fully-rendered honey-files into the Docker image at build time.** Rejected — every container would ship with the *same* canary values, making one leaked image-layer compromise every deployment simultaneously. Install at first-boot regenerates per-deployment values and writes the files at canonical paths inside *that* container only.
- **MCP-served virtual honey-FS.** Rejected for v1 — adds a new protocol surface and depends on the agent enabling MCP. Reconsider in a future ADR once the on-disk approach has corpus coverage.
- **Embed honey-files inside an existing tool's on-disk cache (e.g. ride along with `~/.cache/`).** Rejected — too obscure; the goal is to be discoverable to an attacker who's read about typical credential-storage locations, not creative.
- **Skip per-kind recipes and just write the value into a file named after the canary id (`aws-key-001.txt`).** Rejected — fails the realism test; an attacker recognizes a non-credential layout and skips the bait. Also fails the §1 naming rule on its face.
- **Default placement at a sandbox directory whose name signals "armor"** (originally proposed `<cwd>/.armor-honey/`). **Rejected** per the user's Q2 answer — any path or directory containing `armor`, `honey`, `canary`, `trap`, `fake`, `bait`, or `decoy` is a giveaway to a read-only attacker inside the container and defeats the whole exercise.
- **Manifest as a JSON file at `<target>/.armor/honeyfs/manifest.json`.** Rejected — both the directory `.armor` and the filename `honeyfs/manifest.json` are visible to the agent inside the container and violate the §1 naming rule. SQLite-table-inside-`armor.db` (which lives in the daemon-only data directory) replaces it.
- **Two-step install — generate values first, then place files in a separate command.** Rejected — leaves a window where values exist in the catalogue but not on disk (or vice versa), giving an attacker a stale/inconsistent view. The unified pipeline (§4) generates, registers with the catalogue, persists the values file, and renders the on-disk recipes atomically.
- **Side-by-side `.armor-canary` suffix mode** for host installs that conflict with real files. Rejected per Q2 naming rule — the suffix is itself a giveaway. Conflicts now abort the install and the operator picks a clean target.
- **Shell out to reference wallet-format tools (`eth-keyfile`, `bitcoin-cli`, etc.)** at install time. Rejected per Q4 — adds external dependencies to the daemon image and makes the install non-reproducible across environments. In-process Python renderers are simpler and the realism trade-off (plausible shape, not cryptographic correctness) is acceptable because the canary scanner trips on the value alone regardless of whether a real tool would accept the file.

## See also

- ADR-010: Canary catalogue storage (schema bundled, values generated at install, injected at runtime). honeyfs reuses the same values file and the same `Catalogue` loader.
- ADR-021: Honeypot system prompt design and canary value isolation. honeyfs extends the prompt template to reference real on-disk paths.
- `archive/discussion.md` §11 (lines 418-477): *High-Value Targets List* — the credential-type inventory that motivates the per-kind recipe table.
- `docs/architecture/diagrams.md` §6: *Deployment topology — Claude Code hook integration.* Establishes that the agent's filesystem is the host, which is why the install target must be operator-supplied.
- `docs/architecture/threat-model.md` (current): no honeyfs entry yet; this ADR specifies the two new boundaries to add.
- ~~Future ADR-032 (proposed): tool-side honey-path access detector~~ — **dropped from v1 scope** per Q3. The post-output canary scanner is sufficient because every honey-file value is registered with the live `Catalogue` at install time. A recon-only advisory detector may be reconsidered in a future ADR after field experience.

### Adjacent gaps captured separately

A 2026-05-07 audit of `archive/discussion.md` against the implemented spec surfaced a constellation of related gaps — some directly load-bearing for honeyfs (the recipe table in §3 *assumes* the catalogue grows to cover those kinds; today it covers only 8 kinds × 3 entries, vs. the dozens of credential families enumerated in `archive/discussion.md` §11). Each gap is tracked as its own follow-up ADR or task so honeyfs's scope stays bounded. Honeyfs itself does not block on any of these — it can ship against today's smaller catalogue, and the values it lays down trip the post-output scanner regardless of how many other kinds exist alongside them.

| Tracker | Title | Relationship to honeyfs |
|---|---|---|
| ADR-032 | Canary catalogue expansion to the high-value-targets table | **Direct dependency for full coverage.** §3's recipe table names kinds (`gitlab-pat-*`, `slack-token-*`, `openai-key-*`, `jwt-*`, `cert-*`, `kube-config-*`, …) the catalogue does not yet emit. honeyfs renders whichever kinds the catalogue produces; ADR-032 is what grows that set. |
| ADR-033 | Indirect / second-order injection detection (fetched content, OCR, document scan) | **Adjacent.** honeyfs is bait placement; ADR-033 is detection on a separate input boundary (tool results before they reach the agent). They share no code path but together close the recon → exfil chain. |
| ADR-034 | Natural-language paraphrase exfiltration detection | **Failure-mode acknowledgement.** honeyfs's values still trip the post-output scanner on verbatim leak (§6), but a paraphrase ("the AWS key starts with AKIA…") bypasses both the canary scanner and the rolling-buffer partial-match. ADR-034 is the dedicated detector for that gap. |
| ADR-035 | Multi-layer / recursive encoding decode | **Adjacent.** Tightens the entropy-decode-rescan path so a base64-of-hex-of-canary leak still trips. honeyfs is upstream of this. |
| ADR-036 | Translation-based jailbreak / obfuscation detection | **Deferred 2026-05-07.** Operator chose to skip — canary-trip layer (this ADR + ADR-038) is sufficient backstop for the translation-jailbreak vector since canary leaks are language-agnostic. Re-open conditions documented in ADR-036. |
| ADR-037 | Context-window attack detector category (overflow, burial, memory manipulation, token-budget exploitation) | **Adjacent.** Input-side coverage; orthogonal to honeyfs. |
| ADR-038 | Time-delayed / context-specific canaries | **Direct extension.** §4 of this ADR establishes `armor honeyfs rotate` as the rotation primitive; ADR-038 generalises that to context-conditioned activation (different canary subsets active in different conversation contexts). honeyfs's manifest schema may need a `context_tag` column. |
| ADR-039 | Steganographic / file-binary exfiltration detection | **Adjacent.** Closes the §7 Category 3 *steganography* row; not load-bearing for honeyfs. |
| ADR-040 | Rate-limit-bypass / cross-service tool abuse detection | **Adjacent.** Session-level metric; orthogonal to honeyfs. |
| Task 061 | Authority-impersonation regex detector | Closes the explicit "P1/P2, not yet implemented" parenthetical in `behaviors.md` B-001. |
| Task 062 | Command-injection denylist gap fixes (`chmod 777`, `chown root:root`, `passwd root`, `crontab -e`, `systemctl stop docker`, `mount --bind`) | Hardens B-003; orthogonal to honeyfs. |
| Task 063 | Emotional-manipulation jailbreak patterns (`fictional-framing` family already covered; this adds the `emotional-manipulation` corpus family) | Off the canary path; jailbreak-template extension. |
| ADR-041 | Payload provenance / trust labels (calibration multiplier + exemption mechanism) | **Foundational primitive added 2026-05-07.** Supersedes ADR-033's `SessionContext.payload_source` proposal. honeyfs is unaffected — canaries trip on verbatim leak regardless of source per §6 above. The ADR also ships an exemption mechanism that prevents armor from blocking its own development workflow (reading this ADR, the eval corpus, etc.). |

The audit memo that produced this list is `archive/2026-05-07-discussion-audit.md` (kept locally, gitignored).

---

## Acceptance

- **Status:** Accepted — open questions answered 2026-05-07; ready for task scoping.
- **Reviewed by:** Kevin (2026-05-07).
- **Implementation task(s):** TBD — likely split as one task per concern (CLI lifecycle + SQLite manifest schema, per-kind recipe renderers including the in-process wallet/keystore renderers, honeypot-prompt regeneration tied to the install pipeline, threat-model + fitness updates including `honeyfs_no_giveaway_paths.py`, corpus rows for recon-then-exfil scenarios).

### Open questions answered

The four questions left open in the original Proposed-status draft were answered by Kevin on 2026-05-07. Verbatim answers and how each one was rolled into the ADR body above:

1. **Default install profile** — *"default install should be comprehensive, the operator is not likely to modify this but it's good if it's extensible so they can"*
   → §4 collapses the original `minimal | standard | full` triple into a single shipped `comprehensive` profile that is the default. Profile extensibility is preserved via an `[honeyfs.profiles.<name>]` block in `armor.toml` so operators who want a smaller set author their own.

2. **Placement / naming** — *"placement should default to as close to real world full path as possible in the container and should not contain any terms that would tip off something that only has access to the container that these are trap values, you mentioned `.armor-honey` that's a bad convention if we're trying to make these look like real sensitive values"*
   → §1 rewritten to make in-container canonical-path placement the default (the original sandbox-mode design from `archive/discussion.md`), reject the `.armor-honey` directory and the `--side-by-side` `.armor-canary` suffix mode (both contain giveaway naming visible to the agent), and add a hard naming rule plus a fitness function (`honeyfs_no_giveaway_paths.py`) that asserts no recipe path or rendered file content contains `armor`, `honey`, `canary`, `trap`, `fake`, `bait`, or `decoy`. The host-mode `--target $HOME` install becomes opt-in only.

3. **Visibility + escape detection** — *"these should only be visible from within the sandbox, when they're generated we save them to the post cmd checker so they can be found if they manage to 'escape'"*
   → §6 rewritten to make canary-value generation and on-disk placement a **unified install pipeline**: every value rendered into a honey-file is simultaneously registered with the live `Catalogue` and added to the `CanaryScanner`'s Aho-Corasick automaton. The existing post-output scanner therefore *is* the escape detector — no separate honey-path access detector is needed for v1 (the originally-proposed ADR-032 follow-up is dropped to "optional later" status). §4's manifest moves into a SQLite table inside `armor.db` (rather than a JSON file at a giveaway path) so an attacker with read-only shell access inside the container cannot enumerate the bait by name.

4. **Wallet recipe implementation** — *"I'd like to have this within the container itself for ease of use and to know we can reliably generate these values but open to suggestion if you think it's easier for them to shell out at install time"*
   → §3 *Wallet realism* added: wallet/keystore recipes ship as **pure-Python in-process renderers** with no external dependencies, no shell-out to `eth-keyfile`/`bitcoin-cli`/etc. The renderers produce files that match the *shape* tools expect (correct magic bytes, correct top-level keys, correct filenames, correct modes) but the embedded ciphertext is opaque random bytes — cryptographic correctness adds no detection power, since recon-and-exfil trips on the embedded canary value either way and load-then-fail tools never get a chance to invalidate the bait before the scanner has already caught the leak.
