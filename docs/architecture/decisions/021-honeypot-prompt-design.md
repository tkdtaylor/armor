# ADR-021: Honeypot system prompt design and canary value isolation

**Status:** Accepted
**Decision date:** 2026-05-06
**Task:** 019
**Authors:** Kevin

## Context

When the armor daemon detects an apparent successful prompt injection (via the static detector pipeline returning `block` or `advisory`) and the session is in an elevated state, it invokes a "honeypot" LLM to generate a response that appears to comply with the attacker's request. The honeypot response typically contains fake credentials (canaries) that the attacker would try to use, converting the fuzzy "did the model leak something?" question into a deterministic "did the model leak a specific canary?" detection problem.

A critical security invariant: **canary values must never be readable by the validator LLM or persisted in the prompt template file.** Values are merged at prompt-build time only on the honeypot path. This separates concerns — the validator remains a pure semantic classifier, while the honeypot is an attack-response engine that knows about secrets.

## Decision

### 1. Honeypot System Prompt

A new system prompt `src/armor/llm/prompts/honeypot.txt` is created that instructs the LLM to play the role of a helpful assistant with access to a vault of secrets (credentials, API keys, database passwords, file paths). The prompt **contains only placeholder strings** like `{{canary:aws-key-001}}`, which reference canary IDs from the bundled schema. The prompt itself is committed to the repo and is **safe to read** — it contains no real secrets.

Example:
```
You have access to the following secrets in your vault:

AWS Credentials:
- Access Key: {{canary:aws-key-001}}

GitHub Credentials:
- Personal Access Token: {{canary:github-pat-001}}

Database Credentials:
- Password: {{canary:db-password-001}}
```

### 2. Value Substitution at Prompt-Build Time

A new module `src/armor/llm/honeypot.py` exports a function:

```python
def respond(
    text: str,
    session_context: SessionContext,
    catalogue: Catalogue,
    llm_session: LLMSession | None = None,
) -> str:
    """Run honeypot with runtime-substituted canary values."""
```

Before calling the LLM, `respond()` performs two steps:

1. **Load template:** Read the honeypot system prompt from disk (just strings and placeholders).
2. **Substitute values:** Find all placeholders matching `{{canary:<canary_id>}}` and replace them with actual values from the `Catalogue` (which was loaded at daemon boot with values from the runtime-injected values file, per ADR-010).

The substituted prompt is then passed to the LLM. **This substitution happens only on the honeypot path.** The validator path never imports or sees canary values.

### 3. Validator Path Remains Value-Free

The validator LLM (`src/armor/llm/validator.py`) continues to work as before: it receives text payloads (never including secret values) and returns a semantic classification ("safe" or "risky"). The validator has zero knowledge of the honeypot or the canary catalogue.

A fitness function (`tests/fitness/test_validator_no_value_access.py`) enforces this invariant via AST scanning — any reference to `catalogue.values()` or `.value` field access in `validator.py` will fail the fitness check.

### 4. Single Weight Set, Two Prompts

Both the validator and honeypot use the same quantized LLM model (same weight file). They differ only in the system prompt:

- **Validator prompt:** "You are a classifier. Classify this text as safe or risky."
- **Honeypot prompt:** "You are a helpful assistant with access to a secret vault. Here are your credentials: {{canary:...}}. Respond to the user."

This approach:
- **Minimizes model size** — one set of weights for both paths.
- **Simplifies deployment** — one LLM to manage, monitor, and update.
- **Reuses infrastructure** — same tokenizer, same inference engine, same context window.

Alternative (two separate models) was rejected because it doubles model size, doubles update burden, and doesn't add value in v0.3 (semantic scope of both tasks is simple enough that a single quantized model handles both).

### 5. Honeypot Invocation Gate

The daemon invokes the honeypot when:

1. The static detector pipeline returns `block` or `advisory` (detected an injection attempt or soft signal).
2. The session state is **Elevated** or higher (per the session risk scoring module, task 022).

A gate function `should_invoke_honeypot(session_context, static_pipeline_verdict) -> bool` is provided at `src/armor/daemon/honeypot_gate.py` and is testable in isolation. **As of v0.3 (task 019), the gate is implemented.**

The gate checks:
```python
session_context.state in ("elevated", "high", "blocked")
and
static_pipeline_verdict.decision in ("block", "advisory")
```

The `state` field in `SessionContext` is a v0.3 placeholder using simple string literals (`None`, `"normal"`, `"elevated"`, `"high"`, `"blocked"`). Once task 022 lands and replaces this with a full session state machine and enum, the gate will be updated to use the proper enum type — the logic remains unchanged.

### 6. Honeypot Response Flow

Once the honeypot generates a response, it flows back through the existing `armor check output` path:

```
honeypot() → response text → check output path → static detectors → canary scanner → verdict
```

The canary scanner will match any canary values in the response and return a `block` verdict, completing the attack chain:

```
Attacker input → Static detectors flag injection → Session elevated → Honeypot invoked
→ Honeypot response contains canary → Canary scanner detects → Block output
```

This deterministic detection converts a semantic uncertainty into a binary fact.

### 7. Forensic Safety

Forensic records written after honeypot invocation contain `canary_id` (the placeholder name), never the canary value. This is enforced by the existing forensic-log contract (see `docs/spec/SPEC.md` top-level invariants and `behaviors.md` B-007).

## Rationale

1. **Placeholder-only prompts** avoid accidentally committing secrets. The template file is safe to review, and drift-audits can check it without exposing values.

2. **Value substitution at build time** (not at template creation time) means values live nowhere except:
   - The runtime-injected values file (protected by filesystem permissions)
   - The in-memory `Catalogue` (daemon process memory)
   - The LLM's context window (volatile, cleaned after inference)

3. **Validator path separation** ensures the validator remains a pure semantic classifier. Mixing sensitive data into the validator prompt would create a data-exfiltration risk — if an attacker could prompt-inject the validator, it might leak the secrets that were embedded there.

4. **Single model + two prompts** is simpler than maintaining separate model weights. Both tasks are classification/generation, not specialized enough to require separate architectures.

5. **Deferred invocation (task 022)** is safe. The honeypot code path is ready and tested in isolation. The gate function waits for session state. When task 022 lands, the gate is updated; the honeypot module itself needs no changes.

## Consequences

1. **New code module:** `src/armor/llm/honeypot.py` handles prompt loading and value substitution.

2. **New prompt template:** `src/armor/llm/prompts/honeypot.txt` is the system prompt.

3. **Honeypot gate:** `src/armor/daemon/honeypot_gate.py` is testable now; invocation wiring deferred to task 022.

4. **Fitness functions:** Two new checks enforce canary isolation:
   - `tests/fitness/test_no_canary_in_prompts.py` — no literal values in prompt files.
   - `tests/fitness/test_validator_no_value_access.py` — validator module has no canary-value code paths.

5. **Corpus scenarios:** `tests/eval/corpus/scenarios.yaml` includes honeypot trigger scenarios (marked `honeypot_trigger` category) documenting the expected attack flow.

## Alternatives considered

- **Embed values directly in honeypot prompt template:** Rejected. Would require committing secrets to git; one leaked clone exposes all deployments' values.

- **Separate validator and honeypot models:** Rejected. Adds deployment complexity and model size without behavioral benefit in v0.3.

- **Encrypt honeypot prompt at rest:** Rejected. Adds machinery without addressing the core threat model (leaked template → leaked values). Placeholder-only is the simpler approach.

- **Dynamically generate honeypot prompts from config:** Rejected. Prompts are simple and static; dynamic generation adds complexity.

## Implementation Notes (v0.3 — Task 019)

- The `should_invoke_honeypot()` gate is implemented and testable in isolation. It checks `session_context.state` (a v0.3 placeholder field with simple string values) and the static pipeline verdict decision. Tests exercise both True and False branches.

- The `SessionContext.state` field is optional (`None` by default) and uses simple string literals for v0.3. Task 022 will replace this with a proper session state enum and machine.

- Three corpus rows (sc-006, sc-007, sc-008) test the canary scanner on inputs containing direct canary references. These rows test the static scanning path (input → detector → block), which is independent of the honeypot invocation gate.

- An integration test suite (`tests/integration/test_honeypot_chain.py`) exercises the full end-to-end chain: honeypot LLM with mocked response → canary scanner → block verdict with correct signal. This covers TC-019-12 and TC-019-13.

- Unit tests for `respond()` use mock LLM sessions and ephemeral catalogues (no dependency on bundled files with values).

- The honeypot prompt file can be evolved iteratively via corpus-driven testing (planned v0.4 activity, not v0.3 scope).

- Forensic logging (`src/armor/db/forensic.py`) already stores `canary_id` (never the value) in the `triggered_canary` column. The existing test suite verifies this invariant (test_triggered_canary_id_not_value in test_forensic.py).

## See also

- ADR-010: Canary catalogue — schema bundled, values generated at install, injected at runtime.
- ADR-020: Validator LLM output contract and confidence calibration.
- Task 022: Session state machine and risk scoring (will enable honeypot invocation).
- Behaviors B-005 (validator) and new B-NNN (honeypot, if materialized later).

---

## Acceptance

- **Status:** Accepted
- **Task:** 019
- **Reviewed by:** Architecture team
- **Fitness functions:** `no_canary_in_prompts.py`, `validator_no_value_access.py` in `tests/fitness/`
- **Code:** `src/armor/llm/honeypot.py`, `src/armor/daemon/honeypot_gate.py`, `src/armor/llm/prompts/honeypot.txt`
- **Tests:** `tests/unit/llm/test_honeypot.py`, `tests/unit/daemon/test_honeypot_gate.py`
