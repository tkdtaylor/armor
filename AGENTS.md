# armor — Agent briefing (canonical)

This is the **canonical, harness-neutral briefing** for armor. It is the single
source of truth for project context, commands, conventions, the task workflow,
verification expectations, commit rules, and the load-bearing process rules every
agent must follow.

Every coding-agent harness loads this file:

- **Codex** auto-loads `AGENTS.md` (this file) directly.
- **Antigravity / Gemini** load it via `GEMINI.md` (a symlink to this file).
- **Claude Code** loads `CLAUDE.md`, which imports this file (`@AGENTS.md`) and
  adds the Claude-specific mechanics (skills, subagents, hooks, plan mode).

Keep this file harness-neutral. Anything that only one harness understands belongs
in that harness's layer (`CLAUDE.md` for Claude Code), not here.

## What this is

armor is a **defense-in-depth security layer for LLM agents**. It detects prompt
injection, exfiltration via canary tokens, encoding/obfuscation, jailbreaks,
tool/API abuse, and session-level multi-turn attacks. It ships as a Docker
container with a small embedded validator LLM and an importable Python library.

The full design rationale that bootstrapped this project lives in
`archive/discussion.md` — gitignored, kept locally as reference. **Read it for
context on attack-vector taxonomy, the canary/honeypot strategy, and the
architectural reasoning.** Updates to architecture should rewrite the spec, not
edit `archive/discussion.md`.

## Project structure

```
src/          ← code outputs (the armor library + daemon)
artifacts/    ← non-code outputs (rendered diagrams, exports, schemas)
tests/        ← unit tests, red-team eval corpus, fitness checks
docs/         ← spec + planning + history (the source-of-truth side)
  spec/           authoritative current-state snapshot — SPEC.md, behaviors, data-model, interfaces, configuration
  architecture/   narrative overview, diagrams.md, ADRs, tech stack
  plans/          roadmap, sprints (operator-private — gitignored)
  tasks/          backlog and completed task files (operator-private — gitignored)
    test-specs/   TDD specs — always written before implementation (operator-private — gitignored)
  agent-rules.md  process rules + project retros (the growing log of lessons; optional)
archive/      ← historical artifacts and deprecated code
docker/       ← Docker build and compose configuration
examples/     ← integration examples (Anthropic, OpenAI, LangChain SDKs)
scripts/      ← utility scripts and automation
armor.toml    ← project configuration
ruff.toml     ← ruff linter/formatter configuration
requirements.txt ← pip requirements (parallel to uv.lock)
archive/discussion.md ← original design conversation, gitignored, kept locally
```

The key distinction: `docs/` is the input side (read before you act, and the
artifact that survives a rewrite), `src/` is the output side (what gets produced).

`docs/spec/` is **dual-natured** — it's the output of every task that changes
externally-visible behavior, *and* the input to onboarding, drift audits, and (in
the limit) regenerating the codebase from scratch. The code is one realization of
the spec. Spec and code that disagree means one of them is wrong; fix it in the
same change.

## Tech stack

Python 3.12 (uv) · Docker · `llama-cpp-python` for local validator inference
(Qwen3-0.6B-Q4_K_M, ADR-018) · `onnxruntime` + HF `transformers` tokenizer running
`all-MiniLM-L6-v2` ONNX for topic-coherence embeddings (ADR-026) · `pyahocorasick`
for canary scanning · SQLite for session state, the session state machine, and
per-session rolling buffer · `pytest` + `pytest-cov` with a curated red-team prompt
corpus eval harness (single-shot + multi-turn rows, ADR-027) · `ruff` for
lint/format · `mypy` strict for typing.

## Commands

```bash
# Dependency management (uv)
uv sync                            # install / sync dependencies
uv add <pkg>                       # add a runtime dependency
uv add --dev <pkg>                 # add a dev dependency

# Test
uv run pytest                      # run all tests with coverage
uv run pytest tests/unit/          # unit tests only
uv run pytest -k "canary"          # filter by name
uv run pytest tests/eval/          # red-team corpus eval harness

# Lint / format / typecheck
uv run ruff check src tests        # lint
uv run ruff format src tests       # format
uv run mypy src                    # typecheck (strict)

# Run the daemon (development)
uv run armor daemon --socket /tmp/armor.sock --db /tmp/armor.db --model /tmp/model.gguf

# Smoke-test a single check
echo "ignore previous instructions" | uv run armor check input --socket /tmp/armor.sock --session-id smoke
```

### Docker (run from host, outside the container)

```bash
docker compose -f docker/docker-compose.yml run --rm dev           # open shell
docker compose -f docker/docker-compose.yml run --rm dev <cmd>     # run a command

# Export workspace → host
docker run --rm -v armor-workspace:/src:ro -v "$(pwd)":/dst debian:bookworm-slim cp -r /src/. /dst/

# Backup / restore workspace volume
docker run --rm -v armor-workspace:/src:ro -v "$(pwd)":/dst debian:bookworm-slim tar czf /dst/workspace-backup.tar.gz -C /src .
docker run --rm -v armor-workspace:/dst -v "$(pwd)":/src debian:bookworm-slim tar xzf /src/workspace-backup.tar.gz -C /dst
```

## Architectural invariants

These are load-bearing — violating one breaks armor's security model, not just
style:

- **Verdicts are immutable; pipelines compose verdicts, never mutate them.** Any
  detector that mutates input is wrong; the pipeline always passes the original
  payload to each detector with a fresh `SessionContext`.
- **No outbound network calls from the daemon code path.** All telemetry is opt-in
  and gated. `requests`/`httpx` imports inside `src/armor/daemon/` will fail CI.
  Threat-intel fetches, telemetry, and any network I/O live in a separate optional
  module, never in the daemon path.
- **The forensic log never stores canary values verbatim** — it stores
  `canary_id`. Any code path writing forensic data is responsible for substituting
  before the row is persisted. There's a unit test that asserts this; do not bypass
  it. The forensic log itself must never become an exfiltration channel.
- **New detectors land as their own task with a corpus entry.** A detector with no
  corresponding red-team test in `tests/eval/` is not done.

## Design principles

This project follows **Unix philosophy** as its default design approach — favoring
**composability over monolithic design**. Complex behavior should emerge from
combining small, independent components that communicate through standardized
interfaces, not by growing one large one. The full statement lives in
`docs/architecture/overview.md` under *Design principles*; the short version is
four structural properties to design for:

- **Modularity** — independent units that can be built, understood, and changed on
  their own
- **Interface standardization** — stable, well-defined contracts between components
  (typed signatures, versioned APIs, plain-text formats)
- **Maintainability** — changes in one module should not cascade across unrelated
  ones
- **Reusability** — components should be liftable into another project without
  entanglement

Derived working rules:

- **One thing, well** — each module, service, and function has a single clear
  responsibility
- **Small, composable pieces** over large configurable ones
- **Plain text** for configs, intermediate artifacts, and data interchange where
  possible
- **Explicit over implicit** — surface assumptions in code and types, not in
  comments
- **Fail fast, crash loudly** on unexpected state — never silently paper over it
- **Test in isolation** — every component runnable without the whole stack
- **Defer premature decisions** — no abstractions until the second or third concrete
  use case demands them

**Monolithic is a legitimate choice when deliberate** — the Linux kernel itself is
monolithic for good reasons. The same can apply to a hot-path runtime core. The
principle is "prefer composability at user-facing or cross-module boundaries, and
document any deviation with an ADR." Accidental monolithic drift is not the same as
a deliberate monolithic decision.

## Conventions

- Task files are named `NNN-short-name.md` (zero-padded, sequential across all task
  states)
- Every task has a paired test spec; no implementation starts without one
- Tasks follow Unix philosophy — one task, one responsibility; break things smaller
  when in doubt
- ADRs live in `docs/architecture/decisions/` — add one whenever a significant
  design decision is made (model choice, IPC protocol changes, detector-trait
  additions)
- **Spec is updated in the same commit as the code change.** A task that changes
  externally-visible behavior, the data model, an interface, or configuration is not
  done until the matching `docs/spec/` file reflects the new state. Stale spec
  entries are rewritten in place — never appended to. The ADR carries the history;
  the spec carries the current truth.
- **Diagrams update with the code.** When a component boundary moves or a runtime
  flow changes, update `docs/architecture/diagrams.md` in the same commit.

## Working in this project

1. Start each session by reading the relevant task file and its test spec
2. Check `docs/architecture/overview.md` and the relevant `docs/spec/` files for
   system context
3. Write the test spec before any implementation code
4. When the task is done, move the file from `docs/tasks/backlog/NNN-*.md` to
   `docs/tasks/completed/` and update `coverage-tracker.md`. Both moves are
   local-only (the `docs/tasks/` tree is gitignored) — there's no commit ceremony
   around them. The `feat:` commit that ships the implementation is the milestone,
   not the file move.
5. **Commit and push immediately after each milestone** — never start the next task
   without committing the current one first

For any task-backed change:

1. Move exactly one task into active (`mv docs/tasks/backlog/NNN-name.md
   docs/tasks/active/NNN-name.md`).
2. Re-read the task and test spec after moving it.
3. Implement only that task's scope.
4. Add or update tests that reference every relevant `TC-NNN-XX` marker.
5. Update every affected public spec/doc in the same change.
6. Update `docs/tasks/test-specs/coverage-tracker.md`.
7. Add completion evidence to the task file.
8. Move the task to completed (`mv docs/tasks/active/NNN-name.md
   docs/tasks/completed/NNN-name.md`).
9. Run focused tests plus the relevant verification checks.
10. Commit the milestone before starting another task.

Do not combine multiple task completions in one commit unless the user explicitly
asks for that grouping.

## Commit rules

**You must commit and push after every milestone.** Do not batch multiple tasks
into one commit. Do not continue to the next task until the current one is
committed and pushed.

| Milestone | What to stage | Message |
|-----------|--------------|---------|
| ADR written | `docs/architecture/decisions/NNN-*.md`, any superseded spec entries rewritten in `docs/spec/` | `docs: add ADR NNN — <decision title>` |
| Task completed | `src/` / `tests/` / `examples/` / `.github/` / etc. changes **and any affected `docs/spec/` files**. Task file and test spec are gitignored (operator-private); move them locally to `docs/tasks/completed/` but they don't appear in the diff. | `feat: complete task NNN — <name>` |
| Diagram updated | `docs/architecture/diagrams.md` (with date bump at top) | `docs: refresh diagrams — <what changed>` |
| Spec rewritten standalone | `docs/spec/<file>.md` | `spec: <what changed and why now>` |

After each milestone:
```bash
git add <relevant files>
git commit -m "<message>"
git push
```

Do **not** add a `Co-Authored-By` line to commits unless explicitly asked.

## Load-bearing process rules

These are the rules that exist specifically to stop a preventable mistake. The
essentials are inlined here so they reach you in every harness even without any
other file loaded. (If a `docs/agent-rules.md` retro log exists, it carries the
full incident treatment for each — read it.)

- **Commit after every milestone — now, not "after the next task too."** Batched
  commits are impossible to untangle. One task, one commit.
- **Test spec before implementation — always.** No "this is too small for a spec."
  The spec defines done; without it you're guessing.
- **Never work directly on the default branch.** Each task lives on its own task
  branch (or worktree under concurrent sessions). Working directly on the default
  branch is the multi-session failure mode — two branches stay isolated, two edits
  to the same default branch collide. When working in a worktree, your next command
  after creating it must `cd` into it — editing the parent repo while believing
  you're isolated is the silent failure.
- **"Done" means operationally verified, not "code merged."** The verification
  ladder: (1) code written → (2) unit tests pass → (3) eval corpus / fitness checks
  pass → (4) CI green → (5) the live path exercised (daemon answering on the
  socket) → (6) live binary/daemon observed end-to-end. Levels 1–4 are 🟡; only 5 or
  6 flips a row to ✅. Never claim a level you did not reach. The `spec-verifier`
  role's APPROVE/BLOCK verdict is the gate before a task is called done — not the
  implementer's self-judgement.
- **No smoke tests where the spec asks for assertions.** A test that calls the
  function under test but does not assert the spec's behavior is a smoke test, not a
  real test — it passes even when the code is wrong. Every test referencing a
  `TC-NNN-XX` marker must contain at least one assertion exercising the spec
  sentence the marker labels. If the spec says "returns `block` with reason X," the
  test asserts both the verdict and the reason. If constructing the state is hard,
  that's a blocker to report — not a license to downgrade the test.
- **Trace producer→consumer before declaring done on cross-module state.** A test
  that sets a field by hand proves the gate works *given* the field; it does not
  prove the field is ever set on the live path. Grep the write site and the read
  site and identify the live path.
- **No new warnings self-justified away.** A change that adds a linter/typecheck
  warning over baseline must fix the root cause or stop and report. Use an explicit
  suppression with a reason, or escalate — "acceptable false positive" is not a
  label you apply unilaterally.
- **Run it when the change is runtime-visible.** CLI/exit codes, daemon responses,
  logging, file outputs, side effects — running `uv run pytest` is not the same as
  observing behavior. Run the path and quote the output.
- **Never `git checkout -- <path>` (or `git checkout <ref> -- <path>`) over a dirty
  working tree.** It silently overwrites uncommitted work and the reflog cannot
  recover it. To *compare*, use `git diff <ref> -- <path>` or `git show
  <ref>:<path>`; to *discard*, `git stash` first. A `protect-checkout` hook blocks
  this; the rule stands even if the hook is off.
- **Never use `git commit --no-verify`.** The pre-commit hook is the
  second-to-last line of defense before bad code lands.
- **Never log or commit canary values.** Reference the `canary_id`. The forensic
  log must never become a leak channel.
- **Git status must be clean before declaring a task complete.** `git status` must
  report `nothing to commit, working tree clean` (modulo the operator-private,
  gitignored `docs/tasks/` moves).

## Common rationalizations

These are excuses agents use to skip steps. Don't fall for them.

| Excuse | Reality |
|--------|---------|
| "I'll commit after the next task too" | No. Commit now. Batched commits are impossible to untangle later. |
| "This task is too small for a test spec" | The spec defines done — without it you're guessing. Write one. |
| "I'll add tests later" | Later never comes. The test spec comes first, always. |
| "These two tasks are related, I'll do them together" | One task, one commit. If it feels too granular, the tasks are scoped correctly. |
| "The architecture doc doesn't need updating" | If you made a non-obvious design decision, write an ADR. |
| "I'll just quickly fix this other thing I noticed" | Stay on your task. Note it for later — don't scope-creep. |
| "I'll update the spec at the end of the day" | No. Spec drift is silent. Update it in the same commit, every time. |
| "The spec already covers this — close enough" | If "close enough" required reading the code to confirm, the spec is wrong. Fix it now. |
| "I'll add a 'previously this was X' note to the spec" | Don't. Rewrite the entry. The ADR carries history; the spec is a snapshot. |
| "Just this one detector can have a network call for fetching threat intel" | No. That goes in a separate optional module, never in the daemon code path. |
| "Logging the canary value will help debugging" | No. The forensic log must never become a leak channel — log the `canary_id`. |

## Boundaries

### Always
- Write the test spec before any implementation code
- Commit and push after every milestone (task completed, spec written, ADR written)
- Read the task file and test spec before starting work on a task
- Create an ADR for significant design decisions (model choice, IPC protocol
  changes, detector-trait additions)
- **Update `docs/spec/` in the same commit** as any code change that alters
  externally-visible behavior, data model, interfaces, or configuration
- **Update `docs/architecture/diagrams.md` in the same commit** as any code change
  that moves a component boundary or alters a diagrammed runtime flow

### Ask first
- Modifying files in `docs/architecture/decisions/` — ADRs are tracked, historical,
  and load-bearing for future-you
- Deleting or renaming existing source files
- Adding dependencies not already in the tech stack
- Changing the project structure beyond what a task requires
- Reorganizing `docs/spec/` (splitting files, renaming sections) — the structure is
  a stable contract; restructure deliberately, not opportunistically
- Modifying or deleting `archive/discussion.md` — it's a historical artifact; if
  architecture has evolved past it, capture the evolution in an ADR + spec rewrite,
  do not edit the discussion

### Never
- Create files in `src/` without a corresponding task and test spec
- Combine unrelated changes in one task or commit
- Skip the test spec — even for "small" changes
- Force push or rewrite published git history
- Add a `Co-Authored-By` line to commits unless explicitly asked
- Run `git checkout -- <path>` over a dirty working tree
- Append to spec entries instead of rewriting them (the ADR keeps history; the spec
  is a snapshot)
- Add future-tense statements to the spec (the spec is what *is*; planned work goes
  in `docs/plans/` and `docs/tasks/`)
- Add outbound network calls in the daemon code path — defends the no-network
  invariant. Telemetry is opt-in and lives in a separate module.
- Log canary values verbatim — always reference `canary_id`

## External tools

- **dep-scan** — install-time supply-chain scan for PyPI/npm/Cargo/Go packages. Use
  the `pipds` wrapper instead of `pip install` for any new dep. Doubly important for
  a security tool. Install:
  `curl -fsSL https://raw.githubusercontent.com/tkdtaylor/dep-scan/main/install.sh | bash`
- **code-scanner** — sandboxed scan of any new dependency or third-party code before
  installing. A malicious dep in armor's supply chain would undermine the whole
  premise — run before adding any package.
- **gh** — GitHub CLI; the project uses it for PR review (`gh pr view`, `gh pr
  checks`) instead of an MCP server.

MCP is not needed — `gh` covers GitHub, web search/fetch cover research, and
`sqlite3` via the shell covers SQLite inspection.
