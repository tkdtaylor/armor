<!--
This template encodes the project milestone rules from CONTRIBUTING.md. Do not
delete sections — leave the unchecked checkboxes as a record of what does not
apply, and explain why in a brief note.
-->

## Summary

<!-- One or two sentences on what this PR changes and why. -->

## Linked task or context

If this PR comes from a maintainer-tracked task, reference the task title and the test spec section it satisfies. External contributors: a paragraph of context describing what attack class the change defends against (or what bug it fixes) is fine — the maintainer keeps the per-task spec/scope docs operator-private.

## Checklist

- [ ] Test spec written **before** any implementation code (a markdown alongside the new tests in `tests/<feature>-test-spec.md` is sufficient for external PRs)
- [ ] Each new TC marker in the spec is referenced by at least one test (`spec-coverage-check.py` passes)
- [ ] Eval corpus entry added for any new detector or behavioral change
- [ ] `docs/spec/` updated in the same commit when externally-visible behavior, the data model, an interface, or configuration changed
- [ ] `docs/architecture/diagrams.md` updated when a component boundary moved or a runtime flow changed
- [ ] ADR added under `docs/architecture/decisions/` when a non-obvious design decision was made
- [ ] `CHANGELOG.md` updated if user-visible behavior changed
- [ ] `make check` passes locally (`ruff`, `mypy --strict`, `pytest`, eval corpus)
- [ ] `make fitness` passes locally (architecture invariants — no daemon-path network, no canary leakage, P95 budgets, etc.)
- [ ] No outbound network calls added to the daemon code path
- [ ] No literal canary values written to the forensic log (use `canary_id`)

## Test plan

<!--
What did you run? What did you observe? Include relevant excerpts of:
  uv run pytest tests/unit/
  uv run pytest tests/eval/
  uv run pytest tests/fitness/   (if fitness tests exist for this area)
-->

## Risk and rollout

<!--
Anything reviewers should know about blast radius, migrations, or rollback.
For a security tool, "what could a regression here let through?" is a
useful framing.
-->
