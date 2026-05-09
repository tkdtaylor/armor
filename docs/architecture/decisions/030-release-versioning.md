# ADR-030 — Release Versioning and Cadence

**Date:** 2026-05-06
**Status:** Accepted

## Context

armor reaches v0.4 with core detection (P0–P3) complete. The project now needs a public release infrastructure (PyPI package, container image, GitHub Releases) that users can depend on. This requires versioning policy clarity: what changes trigger major/minor/patch increments, what gets semantic versioning guarantees, and what cadence we target.

Current state:
- Package metadata lives in `pyproject.toml` under the reserved PyPI distribution name `armor-ai`.
- `pyproject.toml` carries the release version used by the wheel metadata; the git tag used for publication must match that version.
- The import package remains `armor`. The CLI reads `importlib.metadata.version("armor-ai")` via `armor.__version__` and displays it with `--version`.

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
- **Prerelease:** `v0.9.0-rc1` (release candidate), `v0.9.0-alpha1` (experimental). PyPI normalizes to PEP 440 format (`0.9.0rc1`, `0.9.0a1`).

### Release Cadence

No fixed cadence; releases are **milestone-driven**. A release ships when:

- A **v1.0 milestone** (like v0.4 just now) closes with all its tasks done and tests passing.
- Or, an **urgent hotfix** for a critical security or reliability issue lands (rare).

Typical expectation: 1–2 releases per quarter after v1.0 stabilizes. No commitment to faster or slower.

### Versioning and Build Metadata

The Python package version is the `version` field in `pyproject.toml`; the
release tag must match that version:

- `pyproject.toml` version `1.2.3` is released from tag `v1.2.3`.
- `pyproject.toml` version `1.2.3rc1` is released from tag `v1.2.3-rc1` or `v1.2.3rc1`, following PEP 440 normalization.
- Untagged local builds use the checked-out `pyproject.toml` version and are not published.

At runtime, `armor.__version__` reads `importlib.metadata.version("armor-ai")`
from the installed distribution metadata. The source package falls back to
`0.0.0+unknown` only when the distribution metadata is unavailable, such as a
direct source-tree import outside an installed environment.

### Pre-release Label Conventions

- `-rc` (release candidate): feature-complete, entering final integration testing.
- `-alpha` or `-a` (alpha): early experimental; limited API stability.
- `-beta` or `-b`: in between; indicates "broadly tested, minor fixes expected."

GitHub Releases and PyPI both expose the pre-release flag, signaling that upgrading to a pre-release is opt-in.

## Consequences

- **Dependency clarity:** Teams using armor know exactly what they're committing to (SDK + CLI + IPC are stable; detectors and corpus are opaque).
- **Release predictability:** Releases happen when work is done, not on a calendar. Users can plan around quarterly milestones.
- **Version alignment:** Release tags, `pyproject.toml`, CHANGELOG entries, and published PyPI/GHCR artifacts must name the same version.
- **Prerelease adoption:** Early users can test `-rc` builds; CI/CD systems can safely ignore them if desired.
- **Documentation:** Every public API change needs a corresponding CLI or SDK change entry in CHANGELOG.md and (if semver-breaking) a post-release post.

## Related ADRs

- [ADR-028 — SDK Surface Stability](028-sdk-surface-stability.md) — defines the public SDK surface.
- [ADR-029 — Structured Log Schema](029-structured-log-schema.md) — documents forensic incident structure (may evolve in minor releases).
