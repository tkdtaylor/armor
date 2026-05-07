# ADR-030 — Release Versioning and Cadence

**Date:** 2026-05-06
**Status:** Accepted

## Context

armor reaches v0.4 with core detection (P0–P3) complete. The project now needs a public release infrastructure (PyPI package, container image, GitHub Releases) that users can depend on. This requires versioning policy clarity: what changes trigger major/minor/patch increments, what gets semantic versioning guarantees, and what cadence we target.

Current state:
- Package metadata lives in `pyproject.toml` with `version = "0.0.0"` (tag-based override at build time).
- The CLI reads this via `importlib.metadata.version()` and displays it with `--version`.
- No formal versioning policy exists; decisions are ad-hoc per release.

## Decision

### Scope of Semantic Versioning

armor ships three semver-bound surfaces:

1. **SDK API** (public classes/functions in `armor.sdk` and `armor.types`): input signatures, output types, exceptions, context managers. Governed by semver.
2. **CLI interface** (commands, flags, exit codes, stdout format): governed by semver.
3. **IPC schema** (daemon request/response format over the Unix socket): governed by semver.

The following are **NOT** semver-bound:

- **Detector implementation internals** (how a detector scores a payload, its internal state shape) — a detector can change scoring logic in a minor release.
- **Corpus content** (the red-team test cases in `tests/eval/corpus/`) — corpus rows can be added, removed, or refined in any release without breaking semver.
- **ADRs and architecture documentation** — documenting a past decision in new ADRs does not break semver.
- **Incident forensic schema** (internal structure of SQLite incidents table) — may change in a minor release, though we aim for backward-compatible schema evolution when feasible.

### Versioning Scheme

Version format: `MAJOR.MINOR.PATCH[-PRERELEASE]` (PEP 440 compliant, per standard Python packaging).

- **MAJOR:** Backward-incompatible change to SDK, CLI, or IPC.
- **MINOR:** New detector, new SDK method, new CLI flag (backward-compatible).
- **PATCH:** Bug fix, performance improvement, detector tuning, incident table refinements.
- **Prerelease:** `v0.5.0-rc1` (release candidate), `v0.5.0-alpha1` (experimental). PyPI normalizes to PEP 440 format (`0.5.0rc1`, `0.5.0a1`).

### Release Cadence

No fixed cadence; releases are **milestone-driven**. A release ships when:

- A **v1.0 milestone** (like v0.4 just now) closes with all its tasks done and tests passing.
- Or, an **urgent hotfix** for a critical security or reliability issue lands (rare).

Typical expectation: 1–2 releases per quarter after v1.0 stabilizes. No commitment to faster or slower.

### Versioning at Build Time

Version is derived from the **git tag** at build time:

- Tag `v1.2.3` → package version `1.2.3`.
- Tag `v1.2.3-rc1` → package version `1.2.3rc1` (normalized by PEP 440 / wheel metadata).
- No tag → package version `0.0.0` (development; never published).

The build system uses `importlib.metadata.version("armor")` to read this from the wheel metadata; there is no hardcoded version string in the source.

### Pre-release Label Conventions

- `-rc` (release candidate): feature-complete, entering final integration testing.
- `-alpha` or `-a` (alpha): early experimental; limited API stability.
- `-beta` or `-b`: in between; indicates "broadly tested, minor fixes expected."

GitHub Releases and PyPI both expose the pre-release flag, signaling that upgrading to a pre-release is opt-in.

## Consequences

- **Dependency clarity:** Teams using armor know exactly what they're committing to (SDK + CLI + IPC are stable; detectors and corpus are opaque).
- **Release predictability:** Releases happen when work is done, not on a calendar. Users can plan around quarterly milestones.
- **Tag-driven builds:** No version bumps in `pyproject.toml` between releases; git tags are the source of truth.
- **Prerelease adoption:** Early users can test `-rc` builds; CI/CD systems can safely ignore them if desired.
- **Documentation:** Every public API change needs a corresponding CLI or SDK change entry in CHANGELOG.md and (if semver-breaking) a post-release post.

## Related ADRs

- [ADR-028 — SDK Surface Stability](028-sdk-surface-stability.md) — defines the public SDK surface.
- [ADR-029 — Structured Log Schema](029-structured-log-schema.md) — documents forensic incident structure (may evolve in minor releases).
