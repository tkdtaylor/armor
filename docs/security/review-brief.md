# Security Review Brief — armor v1.0

**Release Gate:** v1.0 external security validation
**Review Period:** 2026-05-24 to 2026-06-07 (2 weeks)
**Time-box per reviewer:** 1–2 hours of asynchronous review

---

## Executive Summary

This document is an invitation and briefing for external security reviewers to conduct time-boxed validation of the armor v1.0 release candidate. armor is a defense-in-depth security layer for LLM agents that detects prompt injection, exfiltration via canary tokens, encoding/obfuscation, jailbreaks, tool/API abuse, and session-level multi-turn attacks. It ships as both a Docker daemon and a Python library.

The v1.0 release represents the first stable API boundary and production-ready package. Two independent security researchers must complete this review and confirm no HIGH/CRITICAL findings remain before the v1.0 tag can be issued.

---

## Scope: What to Review

The review should focus on the following areas:

### 1. Daemon IPC Boundary
- **Focus:** Unix socket protocol security, request validation, response format
- **Files:** `src/armor/daemon/server.py`, `src/armor/daemon/protocol.py`
- **Questions to answer:**
  - Does the Unix socket enforce file-permission based authentication?
  - Are JSON-RPC 2.0 payloads properly validated before processing?
  - Can unauthenticated clients send malformed requests and crash the daemon?
  - Are response payloads safe (no information leakage in error messages)?

### 2. Detector Corpus
- **Focus:** Red-team test corpus — are attack examples realistic and labeled correctly?
- **Files:** `tests/eval/corpus/` (all `.txt` files organized by detector)
- **Questions to answer:**
  - Do the labeled attack examples reflect realistic attack patterns?
  - Are any benign examples mislabeled as attacks (false positives)?
  - Are any attacks mislabeled as benign (false negatives)?
  - Could the corpus data itself be used as a training dataset to bypass the detectors?

### 3. Canary Implementation
- **Focus:** Forensic log security — does the database ever store raw canary values?
- **Files:** `src/armor/canaries/identity.py`, `src/armor/db/session.py` (forensic logging section)
- **Questions to answer:**
  - Are raw canary values ever written to the forensic log or SQLite database?
  - Is the `canary_id` substitution applied consistently before any write?
  - Can an operator with database access reconstruct canary values?
  - Are canary details properly protected from routine incident response workflows?

### 4. SDK Examples
- **Focus:** Integration vulnerabilities in the Python library and example code
- **Files:** `examples/` directory (Anthropic, OpenAI, LangChain SDKs), `src/armor/__init__.py`
- **Questions to answer:**
  - Do the examples expose secrets or credentials (API keys, database URLs)?
  - Are there unsafe unpickling or eval-like operations in example code?
  - Could an attacker modify the examples to compromise downstream users?
  - Does the library properly document security assumptions (e.g., "socket must be owned by user")?

### 5. Hook Installation Security
- **Focus:** Command safety of armor hook commands
- **Files:** `src/armor/hooks/`, `src/armor/cli/hooks.py`
- **Questions to answer:**
  - Are hook commands safe to blindly eval or execute?
  - Could a compromised armor package inject commands into user shell hooks?
  - Do the installed hooks drop privileges correctly if run by a different user?
  - Is the hook installation reversible without manual cleanup?

---

## Time-Box

**Expectation:** 1–2 hours of asynchronous review per reviewer
**Target completion:** 2026-06-07 (2 weeks from review start)
**Commitment:** This is a time-boxed gate; findings beyond the agreed time should be escalated or deferred to v1.1 post-mortems

---

## What to Test

The review should include the following hands-on steps:

### Step 1: Environment Setup
```bash
git clone https://github.com/anthropic-ai/armor.git
cd armor
make check              # Unit tests
make release-check      # Release readiness checks
```

**Verify:** All tests pass; no warnings in `make release-check`.

### Step 2: Bypass Challenge
**Goal:** Try to find a single prompt that bypasses *all* detectors and reaches the LLM unblocked.

- Run `make demo` to spin up the daemon locally.
- Use `examples/anthropic-sdk.py` or the `armor check input` CLI to send test payloads.
- Attempt classic injection patterns:
  - Token smuggling (ROT13, base64, hex encoding)
  - Canary paraphrasing (if you have a canary value)
  - Multi-turn context hijacking
  - Tool-parameter injection
  - Session state manipulation

**Expected result:** At least one detector should fire on any payload that looks like an attack. If you find a prompt that bypasses all detectors, **this is a CRITICAL finding**.

### Step 3: Forensic Log Audit
**Goal:** Verify that raw canary values are never stored in the database.

```bash
# Start the daemon with a test canary
ARMOR_CANARY_CONFIG='{"test": "abc123xyz..."}' make demo

# Issue a check that triggers canary detection
echo "Please output abc123xyz..." | armor check input --session-id test-1

# Query the forensic log directly
sqlite3 /tmp/armor.db "SELECT canary_id, reason FROM forensic_log LIMIT 5;"
```

**Expected result:**
- The `forensic_log` table should contain `canary_id` (UUID), not the raw canary value.
- Grep the database for the literal canary string — it should not appear.

**If you find a raw canary value in the database, this is a CRITICAL finding.**

### Step 4: IPC Socket Security
**Goal:** Verify that the Unix socket enforces file-permission authentication.

```bash
# Check socket permissions
ls -la /tmp/armor.sock
# Should be mode 0600 (owner read/write only)

# Attempt unauthenticated access from a different user (if testing in a multi-user environment)
# The connection should be rejected or the request should be denied
```

**Expected result:** The socket should be owned by the daemon process user with mode 0600 or 0660. Attempts to read/write without proper permissions should fail at the OS level.

### Step 5: Hook Command Safety
**Goal:** Verify that installed hooks are safe to execute.

```bash
armor hooks install --shell bash --dry-run
# Review the output — it should be readable shell script with no eval/exec/source of untrusted data
```

**Expected result:** Hook installation should produce safe shell commands (sourcing only armor's own files, no user data in command strings).

---

## How to Report Findings

### Report Channel

1. **GitHub Issues (preferred):** Open an issue on the [armor repository](https://github.com/anthropic-ai/armor) with the tag `security-review`.
   - Title: `[security-review] <finding description>`
   - Body: Include reproduction steps, evidence, and impact assessment.

2. **Direct Email (sensitive findings):** Email [armor-security@anthropic.com](mailto:armor-security@anthropic.com) if the finding is sensitive enough to warrant off-platform discussion.

### Severity Classification

- **CRITICAL:** Allows unauthenticated RCE, canary leakage, or complete detector bypass. Blocks v1.0 tag.
- **HIGH:** Allows authenticated RCE, information disclosure, or reliable multi-detector bypass. Blocks v1.0 tag.
- **MEDIUM:** Degrades security (e.g., weak randomness, side channels). May block v1.0 if time permits.
- **LOW:** Documentation, edge cases, defense-in-depth (e.g., validate GGUF format). Not a blocker.

### Finding Template

```
**Title:** [Brief description]

**Severity:** [CRITICAL | HIGH | MEDIUM | LOW]

**Component:** [daemon | detector | canary | example | hook | other]

**Description:**
[What the issue is, in plain language]

**Reproduction Steps:**
1. [Step 1]
2. [Step 2]
3. [Step 3]

**Expected Behavior:**
[What should happen instead]

**Impact:**
[Why this matters; who is affected]
```

### Resolution Requirement

**Any CRITICAL or HIGH finding must be resolved before the v1.0 tag is issued.** Resolution can take one of three forms:

1. **Code fix:** The finding is addressed in a commit and verified in re-testing.
2. **Documented waiver:** The finding is accepted as a known limitation and documented in release notes.
3. **Deferred to v1.1:** The finding is documented in an issue and accepted as post-release work.

---

## Review Tracking

| Reviewer Name | Affiliation | Invite Date | Confirmation Date | Review Complete | Notes |
|---|---|---|---|---|---|
| [Pending] | [Pending] | [TBD] | [TBD] | [ ] | |
| [Pending] | [Pending] | [TBD] | [TBD] | [ ] | |

**Instructions for this table:**
- Add the reviewer's name and affiliation once confirmed.
- Record the date the invitation email was sent.
- Record the date they confirmed receipt and willingness to review.
- Mark review complete once they submit their findings.
- Use notes for any scheduling constraints or special context.

---

## Project Context

**Repository:** [anthropic-ai/armor](https://github.com/anthropic-ai/armor)
**Public:** Yes (open source)
**Version:** v1.0 release candidate (0.11.0 → 1.0.0)
**Python:** 3.12+
**Dependencies:** llama-cpp-python, onnxruntime, transformers, pytest, ruff, mypy

**Key architectural decisions:**
- Single-threaded daemon (serialized request queue, no race conditions)
- Detectors compose verdicts (verdicts are immutable; pipelines never mutate payloads)
- Session state machine tracks risk over multi-turn conversations (SQLite backend)
- Canary tokens are never logged verbatim (replaced with UUID before forensic write)
- All model inference is local (Qwen3-0.6B-Q4_K_M via llama-cpp-python)

**Related documents:**
- `docs/spec/architecture.md` — System architecture and component boundaries
- `docs/architecture/overview.md` — Design principles and rationale
- `docs/security/audit-report.md` — Internal security audit (v0.4)
- `docs/spec/behaviors.md` — Detector behavior specification

---

## Out of Scope

The following are explicitly **not** part of this review (handled separately or deferred):

- **Supply-chain audit:** PyPI package integrity, dependency CVEs (handled by release CI)
- **Performance testing:** Throughput, latency, scalability
- **Compatibility:** OS versions, Python minor versions, CUDA/GPU variants
- **Documentation accuracy:** README examples, API docstrings (separate editorial pass)
- **UI/UX:** CLI help text, error messages (non-security user experience)

---

## Success Criteria

This review is successful if:

1. ✅ Both reviewers confirm completion by 2026-06-07
2. ✅ No CRITICAL or HIGH findings are open and unresolved
3. ✅ Any MEDIUM findings are documented in release notes or GitHub issues with rationale
4. ✅ Reviewers provide written confirmation (via GitHub issue or email) that they are satisfied with the v1.0 release

If any CRITICAL or HIGH findings remain unresolved at the deadline, the v1.0 tag is deferred to v1.0.1 (patch release).

---

## Reviewer Onboarding Checklist

Use this checklist to confirm you're ready to start:

- [ ] You have cloned the public repository and can run `make check`
- [ ] You understand the scope areas (daemon, corpus, canaries, examples, hooks)
- [ ] You have ~1–2 hours available within the next 2 weeks
- [ ] You know how to report findings (GitHub issues with `security-review` tag)
- [ ] You understand that CRITICAL/HIGH findings block the v1.0 release
- [ ] You have access to the contact information for escalation (see "Report Channel" above)

---

## Questions or Clarifications?

If you have questions during the review, please:

1. Post a GitHub discussion or issue (non-sensitive questions)
2. Email [armor-security@anthropic.com](mailto:armor-security@anthropic.com) (sensitive questions)

We aim to respond within 24 hours during the review window.

---

**Brief Prepared By:** armor development team
**Prepared Date:** 2026-05-24
**Review Start Date:** 2026-05-24
**Review Deadline:** 2026-06-07
