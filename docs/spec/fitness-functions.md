# Fitness Functions

**Project:** armor
**Last updated:** 2026-05-05

Executable architectural invariants. Each fitness function is a check that runs uniformly under one entry point (preferred: `make fitness`; fallback: `./scripts/fitness.sh`) and either passes silently or fails with a description of the violation.

The Stop hook [`check-fitness.py`](../../.claude/scripts/check-fitness.py) runs this entry point at the end of each turn under the `strict` hook profile and surfaces failures to the agent. It is advisory, not blocking — fitness violations may be intentional during a refactor, but they are visible.

The architect agent proposes fitness functions in *fitness-function proposal* mode against the rest of the spec; the implementations live in `tests/fitness/` (or equivalent) and are wired into the entry point.

---

## Categories

The following categories cover what the spec asserts and what experience has shown to drift silently. Each category lists the candidate invariants for armor; a row moves from "candidate" to "implemented" once a check exists in the runner.

### Structural — module boundaries

| Invariant | Why | Candidate check | Status |
|-----------|-----|-----------------|--------|
| `src/armor/daemon/` makes no outbound network calls | Top-level invariant in `SPEC.md`; defends the no-network promise | Static import scan: forbid `requests`, `httpx`, `urllib3`, `socket.socket(AF_INET, …)` outside `armor.client` (which only opens the AF_UNIX socket) | candidate |
| Detectors do not import each other | `pipeline` composes; detectors are leaves | AST scan over `src/armor/detectors/*.py` for `import armor.detectors.*` | candidate |
| `db.forensic` writers always substitute `canary_id` for the canary value | The forensic log must not leak | Unit test (already required by `behaviors.md`) plus a grep that no `forensic.write*` call site receives a payload still containing a known catalogue value | candidate |
| `types` has no project-internal imports | Vocabulary module must stay leaf | AST scan: `src/armor/types.py` imports only stdlib + typing | candidate |

### Performance / footprint

| Invariant | Why | Candidate check | Status |
|-----------|-----|-----------------|--------|
| Daemon cold-start under N seconds (target TBD) | Hooks block on the first request; long startup blocks the agent | Time `armor daemon` to first-accept on the socket, fail if > budget | candidate |
| P95 corpus latency under per-detector budget | Catches latency regressions before they impact users; enables early warning of performance degradation | Microbenchmark `tests/eval/corpus/` rows; fail if P95 > 50 ms (v0.2 static detectors) or 500 ms (v0.3+ with LLM) | implemented (`tests/eval/test_corpus.py`) |

### Coverage

| Invariant | Why | Candidate check | Status |
|-----------|-----|-----------------|--------|
| Every detector has a row in `tests/eval/` | "New detectors land as their own task with a corpus entry" — CLAUDE.md | Compare detector class names in `src/armor/detectors/` against eval-corpus IDs; report per-detector TP/TN coverage | implemented (`tests/eval/test_corpus.py`) |
| Every spec `B-NNN` behavior has a test referencing it | Spec coverage should be mechanically verifiable | Grep `behaviors.md` for `B-\d+` markers, then grep `tests/` for the same | candidate |
| Every tool in `tool_schemas.json` has at least one TP and one TN corpus row | Schema coverage should be testable; unknown tools should be observable | For each tool in `src/armor/detectors/tool_schemas.json`, check that `tests/eval/corpus/tool_abuse.yaml` has rows with `tool: <tool_name>` and both `expected_verdict: "block"` (TP) and `expected_verdict: "pass"` (TN) | candidate |

### Security

| Invariant | Why | Candidate check | Status |
|-----------|-----|-----------------|--------|
| No `value` field in any committed `*.json` under `src/armor/canaries/` | Per ADR-010, values are generated at install time and never committed. The schema is committed; values are not. | Check: `! git ls-files 'src/armor/canaries/*.json' \| xargs grep -l '"value":'` (succeeds when no matches found) | implemented (`scripts/fitness.sh`) |
| `ARMOR_QUARANTINE_KEY` is never read outside `db.quarantine` | Key reads should funnel through one module | AST scan for `os.environ` reads of the key name | candidate |

### Complexity

| Invariant | Why | Candidate check | Status |
|-----------|-----|-----------------|--------|
| Cyclomatic complexity per function under threshold | Catches silent bloat in pipeline / server | `radon cc -s -n C src/` (or equivalent) | candidate |
| Pipeline file under N lines | Composition logic should stay scannable | `wc -l src/armor/pipeline.py` against budget | candidate |

---

## Runner

When the first invariant lands, add a `make fitness` target (or an executable `scripts/fitness.sh`) that runs every implemented check and exits non-zero on the first failure. The Stop hook then picks it up automatically — no per-check wiring.

Until then, this file lists candidates only and the hook stays silent (it exits 0 when no runner exists).

## How this file is maintained

- **Add a row when an invariant is proposed.** `architect` agent in fitness-function-proposal mode is the typical author.
- **Move a row from candidate → implemented when its check exists in the runner.** Reference the file path of the implementation.
- **Remove a row only with an ADR.** A fitness function is a load-bearing assertion; deleting one is a deliberate architectural concession.
