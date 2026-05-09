# Fitness Functions

**Project:** armor
**Last updated:** 2026-05-09

Executable architectural invariants. Every check is a pytest test under
[tests/fitness/](../../tests/fitness/); discovery is the single source of
truth. The runner ([scripts/fitness.sh](../../scripts/fitness.sh)) is just a
thin wrapper around `pytest tests/fitness/`, and the rules table below maps 1:1
onto the file inventory. Drift in either direction is itself a fitness
violation, asserted by
[test_fitness_spec_correspondence.py](../../tests/fitness/test_fitness_spec_correspondence.py).

## Entry points

| Target | Selector | When to use |
|--------|----------|-------------|
| `make fitness` | `-m "not slow"` (default) | Default CI gate. Skips the slow corpus + LLM full-corpus runs; everything else fires. |
| `make fitness-smoke` | `-m smoke` | Pre-push hook. Pure-function checks only; intentionally excludes anything that loads a model or shells out to a long-running test suite. Designed to complete in seconds. |
| `make fitness-full` | (no selector) | Nightly / release gate. Runs every check, including `@pytest.mark.slow` and `@pytest.mark.requires_llm`. |

Maintainer-local hook harnesses may run `make fitness` at the end of an agent
turn and surface failures to the agent. That local automation is advisory, not
blocking; CI remains the public source of truth.

## Marker conventions

Markers are registered in [pyproject.toml](../../pyproject.toml) under
`[tool.pytest.ini_options].markers`:

- `smoke` — fast checks (well under a second each). Run by `make fitness-smoke`.
- `slow` — long-running checks (full corpus runs, encryption round-trip).
  Excluded from the default `make fitness` to keep CI snappy.
- `requires_llm` — needs model weights present (Qwen3-0.6B GGUF). Cleanly
  skips when `ARMOR_DISABLE_LLM=true` or weights are missing.

A test may carry more than one marker (e.g. the full LLM P95 run is both
`slow` and `requires_llm`).

---

## Implemented rules — runner-wired

Every row corresponds to exactly one file under [tests/fitness/](../../tests/fitness/),
and every file there corresponds to exactly one row.

### Structural — module boundaries

| Invariant | Why | Test |
|-----------|-----|------|
| `src/armor/daemon/` makes no outbound network calls | Top-level invariant in `SPEC.md`; defends the no-network promise. Imports of `requests`, `httpx`, `urllib3`, `http.client`, `socket`, or `urllib` under the daemon tree fail this check. | [test_no_outbound_network.py](../../tests/fitness/test_no_outbound_network.py) |
| Validator LLM has no canary value access | Per ADR-021, `src/armor/llm/validator.py` must not call `catalogue.values()` or read `entry.value` / `canary.value`. Values flow only through the honeypot path. | [test_validator_no_value_access.py](../../tests/fitness/test_validator_no_value_access.py) |
| Daemon IPC ops assign correct `Payload.source` defaults | Per ADR-041 §1, `check.input → USER_INPUT`, `check.output → MODEL_OUTPUT`, `check.tool → TOOL_PARAMS`, `check.fetched → TOOL_RESULT_UNTRUSTED`. | [test_payload_source_propagation.py](../../tests/fitness/test_payload_source_propagation.py) |

### Performance / footprint

| Invariant | Why | Test |
|-----------|-----|------|
| Daemon cold-start under 5,000 ms | Hooks block on the first request; long startup blocks the agent. Measured with `ARMOR_DISABLE_LLM=true` so the budget reflects import + socket bind, not model load. | [test_cold_start_budget.py](../../tests/fitness/test_cold_start_budget.py) |
| Validator P95 latency under 500 ms (smoke + full) | Validator is on the user-facing path; must fit the SLA. ≥20 corpus rows in smoke variant, ≥100 in full. Empirical baseline: 486 ms per ADR-018. | [test_llm_p95_latency.py](../../tests/fitness/test_llm_p95_latency.py) |
| Honeypot P95 latency under 16,000 ms (smoke + full) | Honeypot generates longer responses; separate budget from validator. ≥5 corpus rows in smoke, ≥30 in full. Per ADR-023 amendment (task 043). | [test_llm_p95_latency.py](../../tests/fitness/test_llm_p95_latency.py) |
| Topic-coherence P95 latency under 50 ms | Embedding inference is on the user-facing path; must not block LLM calls. ≥30 representative inputs; tolerance 20% per ADR-026. | [test_topic_coherence_latency.py](../../tests/fitness/test_topic_coherence_latency.py) |

### Coverage

| Invariant | Why | Test |
|-----------|-----|------|
| Static detectors suffice for P0/P1 attacks | LLM is advisory; if it fails, static-only detection should still catch all P0/P1 blocks. Re-runs the eval corpus with `ARMOR_DISABLE_LLM=true`. (`@pytest.mark.slow`.) | [test_corpus_static_only.py](../../tests/fitness/test_corpus_static_only.py) |
| Validator soft-fails to `advisory(confidence=0)` on timeout | Timeouts must not block; must not escalate session state. Re-runs the soft-fail unit suite as a subprocess. | [test_validator_soft_fail.py](../../tests/fitness/test_validator_soft_fail.py) |
| Every session state machine transition is exercised by ≥1 multi-turn corpus row | Determinism requires comprehensive edge coverage; transitions must be verifiable not just in unit tests but against realistic multi-turn scenarios. | [test_transition_coverage.py](../../tests/fitness/test_transition_coverage.py) |
| Jailbreak corpus carries required TP/TN counts per family | Detector relies on broad family coverage. ≥30 TPs, ≥15 TNs overall; ≥3 TPs and ≥1 TN per known family (DAN, developer-mode, fictional-framing, gradual-escalation). | [test_jailbreak_counts.py](../../tests/fitness/test_jailbreak_counts.py) |
| Canary kinds in catalogue match ADR-031 §3 recipe table | Catalogue / recipe-table sync per ADR-032 Q5; LLM-provider services carry `false_positive_risk=high`; each kind has ≥3 active entries (≥5 for LLM providers). | [test_canary_kinds_match_recipe_table.py](../../tests/fitness/test_canary_kinds_match_recipe_table.py) |
| Canary values are consistent across activation/deactivation cycles | Per ADR-038, canary values must not regenerate mid-session; activation rule re-evaluation returns the same value. | [test_canary_activation_consistency.py](../../tests/fitness/test_canary_activation_consistency.py) |
| Fitness modules are discoverable by pytest's default glob | Rename pins from tasks 040 + 041 plus a generalised scan: any `*.py` under `tests/` containing pytest-style definitions but failing the `test_*.py` glob is silently uncollected. | [test_fitness_module_discovery.py](../../tests/fitness/test_fitness_module_discovery.py) |
| `CHANGELOG.md` is updated when user-visible source changes | Every PR touching CLI / SDK / daemon / detectors / public types / examples / docs must add an `[Unreleased]` entry, unless gated by `SKIP_CHANGELOG=1` or the `skip-changelog` PR label. | [test_changelog_updated.py](../../tests/fitness/test_changelog_updated.py) |
| Spec ↔ file 1:1 correspondence | Adding a fitness rule requires both the test and the spec row; either side missing fails CI. Closes the discovery gap permanently. | [test_fitness_spec_correspondence.py](../../tests/fitness/test_fitness_spec_correspondence.py) |

### Security

| Invariant | Why | Test |
|-----------|-----|------|
| No `value` field in any committed `*.json` under `src/armor/canaries/` | Per ADR-010, values are generated at install time and never committed. The schema is committed; values are not. Replaces the inline `git ls-files \| xargs grep` check that used to live in `scripts/fitness.sh`. | [test_no_canary_values_in_committed_json.py](../../tests/fitness/test_no_canary_values_in_committed_json.py) |
| No literal canary value in prompt templates | Per ADR-021, prompt templates contain only `{{canary:id}}` placeholders, never actual values. Prevents accidental commit of credentials. | [test_no_canary_in_prompts.py](../../tests/fitness/test_no_canary_in_prompts.py) |
| Quarantine table is not greppable for canary values | Per ADR-011, payloads written to the quarantine table must be encrypted at rest so an operator with raw SQLite access cannot recover plaintext canary values. (`@pytest.mark.slow`.) | [test_quarantine_at_rest.py](../../tests/fitness/test_quarantine_at_rest.py) |

### CI / release-process

| Invariant | Why | Test |
|-----------|-----|------|
| `.github/workflows/ci.yml` `make-fitness` job exists, invokes the entry point, is blocking, and `scripts/fitness.sh` is executable | Tasks 042 + 043 wired the job and promoted it from advisory to blocking after the honeypot P95 latency regression closed. | [test_ci_make_fitness.py](../../tests/fitness/test_ci_make_fitness.py) |
| CI workflow surface (lint / typecheck / unit / eval / fitness jobs split, README badges present) | Per task 058, the CI matrix must split `make check`'s components into separate jobs and the README must surface their status. | [test_ci_workflows.py](../../tests/fitness/test_ci_workflows.py) |
| `make release-check` target + `RELEASE_CHECKLIST.md` invariants | Per task 054, the pre-tag verification sequence runs in stages, the checklist is committed, and the targets it references exist. | [test_release_check.py](../../tests/fitness/test_release_check.py) |
| `.github/` infrastructure (issue templates, PR template, CODEOWNERS) | Per task 060, the `.github/` directory carries the standard issue/PR templates and ownership rules for a public release. | [test_github_infra.py](../../tests/fitness/test_github_infra.py) |

### Public-release surface

| Invariant | Why | Test |
|-----------|-----|------|
| README is structurally and substantively truthful | Per task 057, the README must contain the structural and content elements that make it honest about what the project does and does not do. | [test_readme_truthfulness.py](../../tests/fitness/test_readme_truthfulness.py) |
| Public-release readiness (SECURITY.md matchers, project-status badges, etc.) | Post-rewrite verification of release-readiness invariants. | [test_public_release.py](../../tests/fitness/test_public_release.py) |
| SDK type-strictness, docstring coverage, ADR requirements | The SDK surface is type-strict, every public symbol has a docstring, and the SDK's invariants are pinned. | [test_sdk_polish.py](../../tests/fitness/test_sdk_polish.py) |
| Daemon emits structured-log JSON with required fields | Per TC-028-08, all logs from the daemon must be valid JSON with required fields (`ts`, `level`, `event`). | [test_structured_logs.py](../../tests/fitness/test_structured_logs.py) |
| Project email rebrand consistency | Every shipped contact-info file and the canonical-email matcher reference the rebrand target. | [test_email_rebrand.py](../../tests/fitness/test_email_rebrand.py) |
| `docs/architecture/diagrams.md` describes the operator-clear flow | The diagrams file must describe the operator-clear quarantine-release flow. | [test_diagrams_operator_clear.py](../../tests/fitness/test_diagrams_operator_clear.py) |
| `examples/claude_code/` integration example fitness | The Claude Code SDK example structure, README references, and offline-smoke contract are pinned. | [test_claude_code_example.py](../../tests/fitness/test_claude_code_example.py) |
| `examples/custom_agent.py` fitness | The custom-agent example structure and offline-smoke contract are pinned. | [test_custom_agent_example.py](../../tests/fitness/test_custom_agent_example.py) |
| Demo recording artifact pins | The demo recording artifact's path, format, and README references are pinned. | [test_demo_recording.py](../../tests/fitness/test_demo_recording.py) |
| v1.0 readiness gate is concrete (detection floor, perf gates, integration gates, external-validation plan) | Per task 099, `docs/v1-readiness.md` must carry the five required sections with concrete (non-aspirational) gates and a dated external-validation plan; closes the readiness-drift gap before tagging. | [test_v1_readiness.py](../../tests/fitness/test_v1_readiness.py) |

### Spec-drift audits (post-audit pins)

These nine modules pin specific spec-drift fixes from a cluster of
post-launch audits. They prevent the same drift from recurring silently.

| Invariant | Why | Test |
|-----------|-----|------|
| AWS-shape canary fixture replacement | Pins the AWS-shaped canary replacement audit so the fixture cannot regress. | [test_audit_045.py](../../tests/fitness/test_audit_045.py) |
| Single canonical `honeypot_budget_ms` value | Reconciliation pin: code, ADR, spec, config, and helpers all reference the same value. | [test_audit_046.py](../../tests/fitness/test_audit_046.py) |
| `docs/spec/architecture.md` component table accuracy | Pins the architecture spec audit so the component table cannot drift from reality. | [test_audit_047.py](../../tests/fitness/test_audit_047.py) |
| Spec drift cluster fixes | Pins a cluster of small spec/code mismatches so they cannot return. | [test_audit_048.py](../../tests/fitness/test_audit_048.py) |
| `incidents export` spec/code alignment | The spec documents `incidents export` if and only if the code implements it. | [test_audit_049.py](../../tests/fitness/test_audit_049.py) |
| `armor.toml` post-FSM rewrite pins | Spec audit checks for the FSM-aware `armor.toml`. | [test_audit_050.py](../../tests/fitness/test_audit_050.py) |
| README + public-doc doc-fix pins | Pins the doc fixes so the same paragraph drift cannot return. | [test_audit_051.py](../../tests/fitness/test_audit_051.py) |
| `docs/architecture/diagrams.md` refresh pins | Pins the diagrams refresh so the diagrams cannot fall out of sync silently. | [test_audit_052.py](../../tests/fitness/test_audit_052.py) |
| Code and doc tidy-up pins | Pins the cleanup so the tidy-up cannot regress. | [test_audit_053.py](../../tests/fitness/test_audit_053.py) |

---

## Eval-tier checks (run under `make eval`, not `make fitness`)

These checks are part of the evaluation corpus suite, not the fitness gate.
Listed here so the project's "what does armor enforce?" answer is
self-contained.

| Invariant | Why | Test |
|-----------|-----|------|
| Documented corpus-covered detector families have rows | Per project conventions, shipped detector families that claim eval-corpus coverage land with corpus rows. Enforces the required detector/family coverage map, including ADR-037 context-window families and explicit metadata for detector signals masked by later pipeline blocks. | [tests/eval/test_corpus.py](../../tests/eval/test_corpus.py) |
| P95 corpus latency under per-detector budget | Catches latency regressions before they impact users. Microbenchmarks `tests/eval/corpus/` rows; fail if P95 > 50 ms (static detectors) or 500 ms (LLM detectors). | [tests/eval/test_corpus.py](../../tests/eval/test_corpus.py) |

---

## Candidate rules (not yet wired)

These remain as candidate invariants. Promote a row to *implemented* by
landing the test under `tests/fitness/test_<name>.py` and moving its row
into the implemented section above (the meta-fitness check enforces the
mapping).

### Structural

| Invariant | Why | Candidate check |
|-----------|-----|-----------------|
| Detectors do not import each other | `pipeline` composes; detectors are leaves. | AST scan over `src/armor/detectors/*.py` for `import armor.detectors.*`. |
| `db.forensic` writers always substitute `canary_id` for the canary value | The forensic log must not leak. | Unit test (already required by `behaviors.md`) plus a grep that no `forensic.write*` call site receives a payload still containing a known catalogue value. |
| `types` has no project-internal imports | Vocabulary module must stay leaf. | AST scan: `src/armor/types.py` imports only stdlib + typing. |

### Coverage

| Invariant | Why | Candidate check |
|-----------|-----|-----------------|
| Every spec `B-NNN` behavior has a test referencing it | Spec coverage should be mechanically verifiable. | Grep `behaviors.md` for `B-\d+` markers, then grep `tests/` for the same. |
| Every tool in `tool_schemas.json` has at least one TP and one TN corpus row | Schema coverage should be testable; unknown tools should be observable. | For each tool in `src/armor/detectors/tool_schemas.json`, check `tests/eval/corpus/tool_abuse.yaml` has rows with both verdicts. |

### Security

| Invariant | Why | Candidate check |
|-----------|-----|-----------------|
| Quarantine key handling stays in `db.quarantine` | Key reads should funnel through one module. | AST scan: only `db.quarantine` may open `<db_dir>/.key` or accept `--quarantine-key-path`. |

### Complexity

| Invariant | Why | Candidate check |
|-----------|-----|-----------------|
| Cyclomatic complexity per function under threshold | Catches silent bloat in pipeline / server. | `radon cc -s -n C src/` (or equivalent). |
| Pipeline file under N lines | Composition logic should stay scannable. | `wc -l src/armor/pipeline.py` against budget. |

---

## How this file is maintained

- **Add a row when an invariant is proposed.** The `architect` agent in
  fitness-function-proposal mode is the typical author.
- **Move a row from candidate → implemented when its test lands.** The
  spec ↔ file correspondence check (`test_fitness_spec_correspondence.py`)
  fails CI if either side is missing.
- **Remove a row only with an ADR.** A fitness function is a load-bearing
  assertion; deleting one is a deliberate architectural concession.
