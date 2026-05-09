# ADR-011 — Quarantine encryption at rest with Fernet

**Status:** Accepted
**Date:** 2026-05-05
**Deciders:** armor core team

## Context

Task 006 introduces the `QuarantinedPayload` table, which stores raw input and output text from security-relevant incidents (blocks). These payloads may contain:

- Actual user input that triggered a prompt injection attempt
- Model outputs that attempted exfiltration
- Tool parameters that matched a denylist pattern

All of this is sensitive forensic data. While the forensic `Incident` table contains hashes and metadata (never the canary value itself), the `QuarantinedPayload` table stores the full text for later forensic reconstruction.

If a deployed armor instance is compromised and an attacker gains read access to the SQLite database file, they should not be able to read the quarantined payloads — only an attacker with the encryption key can decrypt them.

**Constraints:**
- The encryption must be *at rest* — payloads are stored encrypted in the database.
- The key must be *local* — not fetched from an external KMS or HSM at runtime. This keeps armor air-gapped.
- The key must be *simple to manage* — operators should not need to run separate key-management infrastructure.
- The encryption must *fail fast* — a corrupted or missing key should be immediately obvious, not silently lose forensic data.

## Decision

**Use Fernet (from the `cryptography` library) to encrypt QuarantinedPayload rows at rest.**

### Rationale

1. **Authenticated encryption envelope**
   - Fernet combines AES-128-CBC encryption with HMAC-SHA256 authentication.
   - Provides both confidentiality and authenticity — an attacker cannot forge or modify encrypted payloads without the key.
   - Hard to misuse — the API does not expose raw cipher modes.

2. **No external dependency on key management**
   - The key is generated on first daemon startup: `Fernet.generate_key()`.
   - Persisted to `/var/lib/armor/.key` (mode 0600, owner read/write only).
   - Loaded on daemon restart.
   - No external KMS API call — works in air-gapped environments.

3. **Standard library in the Python ecosystem**
   - `cryptography` library is widely audited, actively maintained, and used in production systems.
   - Fernet is the recommended standard for symmetric encryption in Python (per OWASP).
   - No novel crypto implementation — we rely on vetted primitives.

4. **Fail-fast on key loss**
   - If the key file is deleted or becomes unreadable, decryption fails immediately.
   - Unrecovered payloads cannot be silently returned as garbage — the daemon either decrypts successfully or raises.
   - This prevents the dangerous pattern of "data loss hidden in log silence."

5. **Single point of failure is acceptable for forensic data**
   - Quarantined payloads are forensic artifacts for investigation, not the source-of-truth event log (that's the `Incident` table with hashes and metadata).
   - Loss of the key file means loss of historical payloads, but incidents remain queryable by hash, category, and metadata.
   - This is an acceptable tradeoff for simplicity.

## Alternatives considered

1. **Raw AES (no authentication)**
   - Pros: Simpler, no HMAC overhead.
   - Cons: No authenticity — attacker can forge or modify payloads. Fail-safe requires additional validation logic. Not recommended for sensitive data.

2. **libsodium / NaCl (ChaCha20-Poly1305)**
   - Pros: Modern, fast, excellent security properties.
   - Cons: Adds a heavy native dependency (`pypy-nacl`). Overkill for local at-rest encryption. Fernet achieves the same security with lighter deps.

3. **No encryption (plaintext storage)**
   - Pros: No key management overhead, no decryption latency.
   - Cons: Quarantined payloads are legible to anyone with DB read access. Unacceptable for sensitive forensic data.

4. **External KMS (AWS KMS, HashiCorp Vault)**
   - Pros: Centralized key management, audit trail, key rotation.
   - Cons: Requires network call on every daemon startup. Breaks air-gap requirement. Adds operational complexity.

## Consequences

- **Security**: Quarantined payloads are confidential at rest, provided the key file is protected (mode 0600).
- **Availability**: Loss of the key file means unrecoverable payloads (acceptable for forensic artifacts).
- **Operational**: Operators must back up the `.key` file together with the database. If the database is restored from an old backup without the matching key, those payloads will not decrypt.
- **Performance**: Encrypt/decrypt operations are fast (< 1ms per payload, dominated by DB I/O). No measurable impact on daemon latency.
- **Dependency**: Adds `cryptography` to runtime dependencies. Scanned for supply-chain safety before adding (dep-scan cryptography ✅).

## Implementation notes

- `QuarantineStore._load_or_create_key(key_path: Path)` handles key bootstrap:
  - If `key_path` exists and is readable, load it.
  - If `key_path` does not exist, generate `Fernet.generate_key()` and persist.
  - Verify the key file's parent directory is not world-writable (security gate).
  - Set file permissions to `0o600` (owner read/write, no others).
- All encrypt/decrypt operations happen in `QuarantineStore.write()` and on forensic export (implicit).
- Key is loaded once at daemon `start()`; re-used for all subsequent quarantine operations within the daemon's lifetime.
- No rotation — the active key is fixed for the daemon's lifetime. If rotation is needed, operators restart with a new key and the old quarantine rows become unreadable (acceptable, since rotation is not in v0.1 scope).

## See also

- [B-007: Capture forensic record on every block](../../spec/behaviors.md#b-007-capture-forensic-record-on-every-block)
- [data-model.md: Entity: QuarantinedPayload](../../spec/data-model.md#entity-quarantinedpayload)
- Task 006 (SQLite session store + forensic incident + quarantined payload) — implements this ADR
