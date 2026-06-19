# Contributing to armor

Thank you for considering a contribution. Before opening a PR, please read this short guide — armor uses a deliberate, test-spec-first workflow that affects what's accepted.

## License posture

armor ships under the [Apache License 2.0](LICENSE) — free to use, modify, and distribute, including in commercial and proprietary products. By contributing, you agree your contributions are licensed under Apache-2.0. Under Apache-2.0 §5, contributions are inbound=outbound — they become part of the project and usable by everyone, including commercially. **No CLA is required.**

We use the [Developer Certificate of Origin (DCO)](https://developercertificate.org/) instead of a CLA. Certify you wrote (or have the right to submit) the code by signing off every commit:

```bash
git commit -s -m "your message"
```

This appends `Signed-off-by: Your Name <you@example.com>` (must match your git identity). A CI check enforces it on every PR. To fix a commit you forgot to sign off: `git commit --amend -s --no-edit`.

## Workflow

armor is built using a deliberate maintainer workflow. You don't need to use the same tooling, but the conventions still apply:

1. **Test spec first.** Every change that touches behavior, an interface, or the data model needs a paired test spec — a short markdown describing the test cases (TC-NNN-XX) the change must satisfy, written before the implementation. The maintainer keeps these specs in an operator-private directory, but for an external PR a `tests/<feature>-test-spec.md` alongside the new tests is sufficient. The format mirrors the spec markers already cited in [`docs/spec/fitness-functions.md`](docs/spec/fitness-functions.md).
2. **One task, one commit.** Don't batch unrelated changes. If a fix and a refactor are both warranted, two commits, please.
3. **Spec moves with code.** If your change alters externally-visible behavior, the data model, an interface, or configuration, the matching `docs/spec/` file is updated **in the same commit** as the source change. Stale spec entries are rewritten in place — never appended to. The ADR carries the history; the spec carries the current truth.
4. **ADR for non-obvious decisions.** Significant design decisions (model choice, IPC protocol changes, detector-trait additions) get an ADR under `docs/architecture/decisions/`. Number sequentially.
5. **Detector + corpus go together.** A new detector is not done without a corresponding red-team test row in `tests/eval/`.

## Project invariants

These are non-negotiable and enforced by CI / hooks:

- **No outbound network calls in the daemon code path.** All telemetry is opt-in and lives in a separate module. `requests`/`httpx` imports inside `src/armor/daemon/` will fail CI.
- **Verdicts are immutable.** Pipelines compose verdicts, never mutate them. Detectors return a fresh `Verdict`; the pipeline aggregates.
- **The forensic log never stores canary values verbatim.** Always reference `canary_id`. The log itself must not become an exfiltration channel.
- **No `git commit --no-verify`.** The pre-commit hook is the second-to-last line of defense.

## Local setup

```bash
# Install uv (https://docs.astral.sh/uv/) then:
uv sync
uv run pre-commit install

# Standard development loop
make check          # lint + typecheck + unit tests + eval corpus
make demo           # end-to-end smoke
make release-check  # full pre-tag verification (check + fitness + demo + offline-smoke examples)
```

Maintainers run `make release-check` before tagging any release. See [RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md) for the full process.

Running the daemon locally:

```bash
uv run armor daemon --socket /tmp/armor.sock --db /tmp/armor.db --model /path/to/model.gguf
```

## Continuous integration

Every PR runs the [`ci.yml`](.github/workflows/ci.yml) workflow (lint, format, mypy, unit, eval, fitness — each as a separate check row). **CI must pass before a PR is merged.** A failing job is a blocking comment, not a suggestion.

The heavier [`release-check.yml`](.github/workflows/release-check.yml) workflow runs `make release-check` on every push to `main`; its badge in the README shows whether the branch is currently shippable. Both workflows pin their dependency tree via `uv sync --frozen`.

## Filing issues

- **Bugs:** use the bug-report template; include reproduction steps, environment, and which test-corpus row (`TC-NNN-XX`) the issue maps to (if known).
- **Feature requests:** use the feature-request template; describe the attack vector / detector class and threat-model placement.
- **Security vulnerabilities:** **DO NOT** file public issues. See [`SECURITY.md`](SECURITY.md) for the private disclosure channel.

## PR checklist

The PR template walks you through this, but to summarize:

- [ ] Test spec exists for the change and references real `TC-NNN-XX` markers
- [ ] Tests added/updated; `make check` passes locally
- [ ] `docs/spec/` updated in the same commit if behavior/interface/data-model/config changed
- [ ] ADR added under `docs/architecture/decisions/` if a non-obvious design decision was made
- [ ] `CHANGELOG.md` updated under `[Unreleased]` (or `skip-changelog` label applied for docs-only changes)
- [ ] No canary values in test fixtures (use `{canary:<id>}` template references — see `tests/eval/corpus/README.md`)

## What gets reviewed

Maintainers check, in order:

1. Test spec adherence — does the code actually satisfy the asserted behaviors?
2. Project invariants — no daemon-path network calls, no canary leakage, immutable verdicts.
3. Spec/ADR/CHANGELOG alignment — same-commit rule.
4. Code quality — `mypy --strict`, ruff lint/format, idiomatic Python.

If a CRITICAL security finding is uncovered during review, it will be raised as a blocking comment, not a suggestion.

## Communication

For now, use GitHub Issues for everything except security reports. Discussions may open later.
