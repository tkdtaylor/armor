# ADR-044 — Relicense armor from PolyForm Noncommercial 1.0.0 to Apache-2.0

**Date:** 2026-06-19
**Status:** Accepted
**Decision date:** 2026-06-19
**References:** CHANGELOG.md [Unreleased] "Changed" entry; `LICENSE`; `NOTICE`; `CONTRIBUTING.md`; `.github/workflows/dco.yml`.

## Context

armor shipped under **PolyForm Noncommercial 1.0.0** (a source-available, non-OSI license) from its initial public release through version 0.12.0. That license was chosen to protect against freerider SaaS deployments while the project was pre-v1 and the commercial model was unclear.

Two conditions changed:

1. **Ecosystem expectations.** Agents and security tooling being evaluated for production use are routinely filtered by legal / procurement teams on "OSI open source" criteria. PolyForm NC fails that filter regardless of the project's intent or practical openness. Several integration authors reported this as a blocker.

2. **Monetization clarity.** The project has settled on **enterprise support** (`tools@taylorguard.me`) and **GitHub Sponsors** (`tkdtaylor`) as its revenue path — not a dual-license model. A noncommercial gate no longer serves the monetization strategy and actively harms adoption that would generate enterprise-support revenue.

The combination means the noncommercial gate costs more than it earns.

## Decision

Relicense armor to **Apache-2.0** effective this commit, starting with the version after 0.12.0.

### What changes

| Artifact | Before | After |
|----------|--------|-------|
| `LICENSE` | PolyForm Noncommercial 1.0.0 | Apache-2.0 (canonical SPDX text) |
| `NOTICE` | (did not exist) | Added: attribution, trademark notice, security disclaimer |
| `pyproject.toml` `[project].license` | `{text = "PolyForm-NC-1.0.0"}` | `{text = "Apache-2.0"}` |
| PyPI classifier | PolyForm (non-standard) | `License :: OSI Approved :: Apache Software License` |
| README / README_PYPI | source-available badge | Apache-2.0 badge |
| `CONTRIBUTING.md` | PolyForm NC, no CLA info | Apache-2.0, DCO-based |
| Contribution CLA | implicit (no explicit path) | Developer Certificate of Origin (DCO) — no CLA server |
| Enterprise contact | `licensing@taylorguard.me` (now retired) | `tools@taylorguard.me` |

### DCO rationale (not CLA)

A Contributor License Agreement (CLA) requires contributors to sign before their first PR can be merged. For a project with no company legal entity yet, this adds process friction and tooling overhead (CLA bot, legal review) for minimal extra protection. Apache-2.0's patent-termination clause combined with the Developer Certificate of Origin (`CONTRIBUTING.md` §DCO) gives sufficient provenance coverage while keeping the contribution path frictionless. This decision can be revisited if a formal legal entity is established.

### Sub-decisions

**D1 — SPDX header scope.** Every first-party Python file under `src/armor/` and `tests/` receives `# SPDX-License-Identifier: Apache-2.0` as the first comment line. Generated/vendored files (none currently exist under these paths) would be excluded if they arise in the future.

**D2 — No licensing test retained.** The relicense is enforced by the `LICENSE`, `NOTICE`, and `pyproject.toml` files themselves. No pytest fitness test is added to assert their contents. Rationale: license posture is documentation and metadata, not runtime behavior; a test that only re-asserts static file contents adds maintenance drag without catching a real defect class. Per-file SPDX tripwires (asserting every `.py` contains the header) are likewise omitted — they would fire on legitimate new files before the developer adds the header. The previous PolyForm fitness tests (`test_license_polyform`, `test_tc_032_03`, `test_tc_032_06`, `test_readme_commercial_license_uses_new_licensing_email`) were deleted in commit `7569422` as part of the relicense sweep and are not replaced.

**D3 — No dedicated version bump.** The relicense ships under `[Unreleased]` in CHANGELOG and rides the next semantic-version bump. This avoids releasing a version whose only change is the license file and reduces churn for downstream users.

**D4 — Historical CHANGELOG entry.** The 0.12.0 "Canonical contact emails" entry that previously referenced the now-retired `licensing@taylorguard.me` commercial channel has been updated to remove the retired channel. Enterprise contact is now `tools@taylorguard.me` uniformly.

## One-way-door caveat

Relicensing is a one-way door for already-published versions. **Versions ≤ 0.12.0 were published under PolyForm Noncommercial 1.0.0 and remain available under that license.** Users who pinned those versions are bound by PolyForm NC. This ADR and the accompanying commit govern all releases from the version after 0.12.0 forward.

This is standard practice for open-source relicensing (e.g. MongoDB SSPL → AGPL, HashiCorp BSL → Apache-2.0) and is expected, documented, and accepted.

## Consequences

- **Positive:** armor is now OSI-certified open source. Commercial and proprietary integrations are permitted without a license exception. Ecosystem tooling (vulnerability scanners, license-compliance tools, package repositories) will treat armor correctly.
- **Positive:** Removes legal review burden for would-be enterprise users evaluating armor for production deployment.
- **Positive:** Apache-2.0 patent-retaliation clause provides downstream users with an explicit patent grant, which PolyForm NC did not.
- **Neutral:** GitHub Sponsors / enterprise support remain the monetization path; this ADR removes the license gate but does not create a new revenue mechanism.
- **Negative (accepted):** Already-released versions (≤ 0.12.0) are permanently under PolyForm NC; dual-version legal questions may arise in rare corner cases. The one-way-door note in this ADR is the mitigation.
