# v1.0 Readiness Criteria

This document defines the gate for calling armor `v1.0`. Until every gate below
is met, public releases should remain preview releases such as `v0.9.x`.

## Detection Floor

Each defended attack family must have at least **100 labeled evaluation rows**.
The README may claim coverage for an attack family only when:

- true-positive rate is **>= 90%**;
- Wilson 95% confidence interval lower bound is **>= 80%**;
- false-positive rate on paired benign rows is **<= 5%**;
- the corpus includes at least **25 rows** from an external reviewer or a
  dogfood deployment, not only maintainer-written examples.

Families below this floor may still ship, but the README must call them
experimental or under-tested.

## Performance Gates

All performance gates are measured on the release hardware envelope documented
in the README. For the current preview that is Linux x86_64, Intel Core Ultra 9
185H, 62 GiB RAM, `llama.cpp` CPU inference, `n_threads=1`, and
`n_gpu_layers=0`.

Before a `v1.0` tag:

- `make fitness-smoke` passes **5 of 5** fresh runs.
- Validator P95 is **<= 500 ms** on **5 of 5** fresh runs of
  `tests/fitness/test_llm_p95_latency.py::test_llm_p95_under_budget_smoke`, or
  the budget, README, and ADR-023 are updated together to a reproducible number.
- Honeypot P95 is **<= 16,000 ms** on **3 of 3** fresh runs.
- Daemon cold start is **<= 5,000 ms** on **3 of 3** fresh runs of
  `tests/fitness/test_cold_start_budget.py`.

If a slower hardware class is supported, it must get its own documented budget
instead of weakening the default claim.

## Integration Gates

The following must pass from a fresh checkout before `v1.0`:

- Task 092: validator P95 latency reconciliation.
- Task 093: fresh-clone `make demo` verification.
- Task 094: Docker build end-to-end verification, including model download.
- Task 095: SDK examples against real Anthropic/OpenAI/LangChain APIs.
- Task 096: Claude Code real-session hook verification.
- Task 097: health endpoint metrics implemented or descoped so no placeholder
  metrics are returned.
- Task 098: README measured-performance claims include sample sizes, Wilson
  intervals, hardware envelope, date, and source procedure.
- Task 100: Claude Code manual lifecycle validation for `PreToolUse`,
  read-tool `PostToolUse`, and `Stop`.

`make release-check` must pass in the fresh clone after those task gates are
done. Any skipped fitness test needs a written reason in the release notes.

## External Validation

The `v1.0` validation plan is a combination of reviewer validation and dogfood:

- Invite **2 security reviewers** to run a time-boxed review of the public tree,
  detector corpus, daemon IPC boundary, and examples.
- Run armor in a dogfood agent workflow for **14 calendar days** or **200 guarded
  checks**, whichever comes first.
- Target completion condition: both reviews complete and the dogfood run has no
  unresolved HIGH/CRITICAL findings.

If this plan changes, update this document before tagging rather than changing
the bar after the fact.

## Pre-Tag Runbook Gate

Before bumping from preview to `v1.0`, the release runbook must verify:

- all detection-floor numbers are current and reflected in the README;
- every performance gate above has fresh evidence;
- integration Tasks 092-098 and Task 100 are complete;
- external validation is complete or explicitly waived in release notes;
- a fresh clone passes `make release-check`.

The version may move to `1.0.0` only after those checks are true.
