# ADR-042 — Adopt MITRE ATLAS taxonomy and OCSF output for interoperability

**Status:** Proposed
**Date:** 2026-06-03
**Deciders:** armor core team

## Context

armor is a defense-in-depth **LLM-guard**: it performs input pre-flight checks, output
post-flight checks, session-level multi-turn tracking, tool-call validation, and canary-honeypot
exfiltration detection, with an embedded validator LLM. It is **not** a process sandbox — it does
no namespace/seccomp/OCI isolation; it detects and blocks malicious content and behaviour.

armor is one block in a composable, security-first agent ecosystem (cross-block design in
the ecosystem's shared interface-contracts reference). A cross-cutting principle there:
**reuse existing interchange standards rather than invent new formats**, so each block is
interoperable and swappable.

Today armor classifies detections with internal category names and emits its own block/forensic
records. To interoperate with SIEMs, the agent's `audit-trail`, and the broader AI-security
tooling world, armor should speak two established standards: a **detection taxonomy** and an
**event-output schema**.

(For the record: an earlier ecosystem draft mislabelled armor as an "OCI runtime spec + seccomp"
sandbox. That was a transcript artefact — armor is a guard, not an isolation layer. OS-level
execution isolation is a separate sibling block.)

## Decision

1. **Detection taxonomy → MITRE ATLAS** (the standard adversarial-ML / AI-attack knowledge base),
   with a secondary mapping to **OWASP LLM Top 10** and **OWASP Agentic Top 10 (ASI)**. Each
   detector declares the ATLAS technique(s) it covers plus its OWASP category — e.g. prompt
   injection → `AML.T0051` (LLM Prompt Injection); jailbreak → `AML.T0054` (LLM Jailbreak);
   canary/credential exfiltration → the relevant ATLAS exfiltration technique. This makes armor's
   coverage expressible in a shared vocabulary and comparable to other tools.

2. **Event / finding output → OCSF** (Open Cybersecurity Schema Framework). Emit each
   detection/block as an OCSF event (e.g. the Detection Finding class) so a SIEM or the agent's
   `audit-trail` can ingest armor's output without bespoke parsing. armor's rich forensic capture
   (input + attempted output + intended destination) is preserved; OCSF is the interop envelope
   around it.

3. **Integration surfaces unchanged.** Claude Code hooks + the importable Python library remain
   the integration points — these are integration surfaces, not interchange standards.

4. **Explicitly not adopting OCI/seccomp.** armor is a content/behavioural guard; process
   isolation is out of scope and belongs to a separate execution-sandbox block.

## Consequences

- **+** Detections become portable and correlatable; armor speaks the same language as SIEMs and
  the agent's audit-trail. Coverage gaps are visible against a shared taxonomy.
- **+** Clarifies armor's scope (guard) versus an execution sandbox (isolation) — removing the
  long-standing naming confusion.
- **−** Mapping every detector to ATLAS/OWASP is upfront work and ongoing as ATLAS evolves.
- **−** OCSF has its own schema-versioning to track; the emitter must pin a schema version.

## References

- MITRE ATLAS — https://atlas.mitre.org
- OCSF — https://schema.ocsf.io
- OWASP Top 10 for LLM Applications; OWASP Top 10 for Agentic Applications
- Ecosystem standards table: the shared interface-contracts reference §1a
