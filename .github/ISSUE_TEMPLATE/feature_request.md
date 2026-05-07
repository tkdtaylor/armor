---
name: Feature request
about: Propose a new detector, a coverage extension, or a behavioral change
title: "[feat] "
labels: ["enhancement", "triage"]
---

## Problem

<!-- What gap or weakness does this address? Describe the input class, observed behavior, or operational pain point. -->

## Proposed change

<!-- What should armor do differently? Be specific about the surface (detector, pipeline, CLI, daemon API, config). -->

## Threat-model placement

Where does this sit in the layered defense?

- [ ] New detector — input-side
- [ ] New detector — tool / output-side
- [ ] Existing detector — extended coverage
- [ ] Pipeline / orchestration change
- [ ] Configuration / observability surface
- [ ] Eval corpus / test infrastructure
- [ ] Other: <describe>

If proposing a new detector, summarize the input class it targets. Avoid embedding live exploit payloads in the issue body — link to a corpus row or attach a redacted sample instead.

## Acceptance bar

How will we know it's done?

- [ ] Test spec drafted (`docs/tasks/test-specs/NNN-*-test-spec.md`)
- [ ] Red-team corpus row added (`tests/eval/`) for each new behavior
- [ ] Spec entry under `docs/spec/` rewritten to reflect the new behavior
- [ ] ADR drafted if a non-obvious design decision is involved
- [ ] No outbound network calls added to the daemon code path
- [ ] Verdicts remain immutable; pipeline composes, never mutates

## Alternatives considered

<!-- Brief: what else did you think about, and why is the proposed change the right shape? -->

## Additional context

<!-- Links to related ADRs, prior issues, upstream references, or background reading. -->
