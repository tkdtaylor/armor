# ADR-017: Eval corpus as load-bearing CI gate

**Status:** Accepted
**Date:** 2026-05-05
**Context:** Task 014 — Eval harness + CI gate for P0/P1 attacks
**Stakeholders:** Maintainers, CI/CD

## Problem

The evaluation corpus (`tests/eval/corpus/*.yaml`) was initially a regression sanity check — rows were run through the pipeline to confirm detectors still worked, but failures didn't block CI. As more detectors landed in v0.2, the corpus became the primary evidence that the system detects what it claims to detect. Without a load-bearing CI gate, regressions (a detector that silently stops working, or a corpus row that gets out of sync with the detector) could land undetected.

Additionally, there was no visibility into per-detector coverage (how many TP and TN rows exist for each detector) or latency trends. A detector could degrade in coverage or speed without anyone noticing.

## Decision

1. **The eval corpus is now authoritative.** Failures in `pytest tests/eval/` are treated as release-blocking, equal to lint/typecheck failures. `make check` invokes `make eval`; CI fails if any corpus test fails.

2. **Corpus verdict is the contract.** A corpus row's `expected_verdict` and `expected_signal_id` are the spec of what that detector should do on that input. If the detector changes behavior, either:
   - The detector is wrong → fix the detector code
   - The test case is wrong → fix the corpus row (with an explanation in the commit message)
   - Never silence/skip a corpus row; never set its expected_verdict to "advisory" to hide a behavior change

3. **Latency is measured and gated.** Each corpus row is timed. Test fails if P95 latency across all rows exceeds the configured budget (`LATENCY_BUDGET_MS` in `test_corpus.py`). This catches performance regressions before they impact users.
   - v0.2 budget: **50 ms P95** for static detectors (regex, canary scanner, entropy, exfil extractors, command injection, parameter schema).
   - v0.3+ will upgrade this to ~500 ms when the validator LLM is added.
   - Relative-vs-baseline tracking (detecting regression of N% since the last release) is deferred to v0.3; v0.2 uses absolute thresholds.

4. **Per-detector coverage is visible.** After every eval test run, a report prints to stdout showing each detector and its TP/TN count (e.g., "regex.instruction_override: 5 TP, 12 TN"). Operators can spot when coverage drops (a detector loses rows) or when a detector isn't being tested at all. This report is also captured by CI logs for historical trends.

5. **Regression testing is gated off by default.** A separate test file (`tests/eval/test_regressions.py`) verifies that the CI gate would catch:
   - A detector regression (mock a detector to always return `pass`; assert test fails)
   - A corpus mismatch (mock a row to have the wrong expected_verdict; assert test fails)

   These tests are marked `skipif ARMOR_TEST_REGRESSION_GATE != "1"` so they don't add noise to the normal test run. A developer can run `ARMOR_TEST_REGRESSION_GATE=1 pytest tests/eval/test_regressions.py` to verify the gate works. This is documentation + automated verification that the gate is real; it's not meant to run in CI every time.

## Composite-scenario schema

A new file `tests/eval/corpus/scenarios.yaml` contains 3–5 rows that chain multiple detectors. Examples:
- Input asks for base64 encoding → detector triggers at input (encoding_request), returns `block`.
- Input contains a roleplay hijack → output would have high entropy + canary → multiple detectors could trigger, but the first one in pipeline order wins.
- Bash tool call with `/etc/shadow` read → command-injection denylist triggers, returns `block`.

**Row schema:** Each scenario row uses the existing `CorpusRow` schema:
```yaml
- id: "sc-001"
  input: "scenario description / input payload"
  attack_category: "composite_scenario"  # or the specific attack type
  expected_verdict: "block"
  expected_signal_id: "detector.name:signal-id"
  notes: "What's being tested and why"
```

No new row fields are added in v0.2. The row captures a single `input` that (if needed to test output exfil) includes a reference to a canary via `{canary:<id>}` syntax. The `tool` and `tool_params` fields are optional and work as they do for tool_abuse rows.

**Why not sequential verdicts?** Scenarios could be extended to test an input, then an output, then a tool call in sequence, each with separate verdicts. That's a v0.3+ feature when multi-turn scenarios are needed. For v0.2, a single verdict per scenario is sufficient — the scenario documents what attack is being tested, and the expected verdict is the first detector to trigger in that chain.

## Rationale for latency budget

- **50 ms per row** (P95 across corpus): Static detectors are fast; this is achievable without optimization work. Regex and canary scanning are O(n) on input size; entropy calculation is O(n). Even with a few detectors in the pipeline, processing should be sub-50ms for typical payloads (KB-sized inputs).
- **No relative-vs-baseline tracking yet:** Tracking "regression > N% vs. last release" requires maintaining a baseline file and updating it per release. That's v0.3+ when we have a release cadence and historical data. For now, absolute thresholds work: if P95 ever exceeds 50 ms, there's a clear performance problem that needs investigation.

## Risks and mitigations

| Risk | Mitigation |
|------|-----------|
| Corpus becomes a bottleneck to iteration (can't add a row without fixing the detector) | Corpus ownership is clear: detectors are the ground truth. A row must be correct by definition; if it's wrong, it's a documentation bug. |
| Latency budget is too strict and causes false positives | v0.2 runs on local test hardware; budget is absolute, not pegged to CI runner specs. If the budget fails on CI but not locally, adjust the budget in the same PR that adds the row. Latency budget is a *guidance* flag, not a blocking check — if it fails, the response is "investigate why," not "skip the test." |
| Regression tests add maintenance burden | Regression tests use mocks; they're not tied to specific detector code. If a detector is renamed/removed, the regression test still works (it mocks at the Pipeline level, not at the detector). |

## Implementation notes

- `test_corpus.py` is expanded with timing + coverage stats collection via a session-scoped fixture.
- `test_regressions.py` uses `unittest.mock.patch` to simulate detector failures without modifying source.
- `make eval` is a standalone target, runnable before the full `make check` for quick feedback during development.
- CI workflow (`.github/workflows/ci.yml`) continues to run `make check`, which now includes `make eval`.

## Future work (v0.3+)

- Relative-vs-baseline latency regression detection (track a baseline file, fail if P95 > baseline * 1.1).
- Multi-turn scenario support (sequential verdicts for input → output → tool chains).
- Corpus contribution guidelines (governance for external submissions).
- Latency profiling dashboard (historical P50/P95 trends per detector).
