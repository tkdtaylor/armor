# Interfaces

**Project:** armor
**Last updated:** 2026-05-05

The system's contact surface — everything that calls into the system, everything the system calls out to, and the public boundaries within the system. Each interface is a stable contract.

---

## Inbound interfaces

### CLI

```
armor <subcommand> [flags] [args]

Subcommands:
  daemon              Start the long-lived guardrail daemon
  check input         Check a user-input payload for injection signals
  check output        Check a model-output payload for exfiltration signals
  check tool          Check a tool-call (name + params) against the command denylist
  session close       Mark a session ended; flush state
  canary list         List the active canary catalogue (IDs + kinds, never values)
  canary regenerate   Regenerate the canary catalogue
  incidents tail      Stream recent incidents from the forensic log
  incidents export    Export incidents as NDJSON
  health              Daemon liveness check; exits 0 if responsive, 1 otherwise

Global flags:
  --socket <path>    Daemon socket path (default: /var/run/armor.sock)
  --session-id <id>  Session ID for stateful checks (default: derived from env)
  --json             Machine-readable output
```

| Subcommand / flag | Type | Default | Effect |
|-------------------|------|---------|--------|
| `daemon --socket` | path | `/var/run/armor.sock` | Where to bind the IPC socket |
| `daemon --model` | path | `/models/<chosen>.gguf` | Validator LLM weights file |
| `daemon --db` | path | `/var/lib/armor/armor.db` | SQLite file path |
| `check input <text>` | string (stdin OK) | — | Payload to evaluate |
| `check output <text>` | string (stdin OK) | — | Payload to evaluate |
| `check tool --name <n> --params <json>` | strings | — | Tool name + params blob |
| `--session-id <id>` | string | `$ARMOR_SESSION_ID` | Cross-call session correlation |

**Exit codes:**
- `0` — pass (allowed)
- `1` — internal error (daemon unreachable, IPC failed)
- `2` — usage error (bad flags)
- `78` — daemon configuration error (e.g. model not found at startup)
- `100` — block (the check returned `block`)
- `101` — advisory (returned `advisory`; caller decides whether to allow)

The split between exit codes 0 and 100 is intentional — Claude Code hooks use exit code 2 to signal "block and show stderr to the model" (per the hook contract). The `armor check` wrapper translates verdicts to that convention via the `--hook-mode` flag.

### Daemon IPC (Unix socket)

See `data-model.md` § *Wire / interchange formats* for the request/response schema. Newline-delimited JSON. One request, one response, then the connection may be reused or closed.

### Python SDK

```python
from armor import Guard, Verdict

guard = Guard(socket="/var/run/armor.sock", session_id="my-app-session")

v: Verdict = guard.check_input("user said this")
if v.blocked:
    return safe_response()

response = anthropic_client.messages.create(...)
v = guard.check_output(response.content[0].text)
if v.blocked:
    return safe_response()
```

The SDK is a thin client over the IPC. It does not run detectors locally.

---

## Outbound interfaces

| Dependency | What we call | Library / version | Failure mode |
|------------|-------------|-------------------|--------------|
| Local file system | Read model weights, read/write SQLite, read/write socket | stdlib | Daemon refuses to start if any required path is unwritable |
| `llama.cpp` (via `llama-cpp-python`) | Inference on the validator/honeypot model | Pinned in `pyproject.toml` | LLM unavailable → checks degrade to static-only with `advisory` confidence=0 |

armor makes **no outbound network calls by default.** Telemetry/upload is gated behind `ARMOR_ENABLE_TELEMETRY=1` (off by default; see configuration.md) and would land as a separate optional outbound interface.

---

## Internal public surface

### Trait: `Detector`

```python
from typing import Protocol

class Detector(Protocol):
    id: str                # e.g. "regex.instruction_override"
    category: str          # taxonomy bucket from ADR-007 (e.g. "direct_injection")
    cost_tier: str         # "static" | "semantic"  — semantic = needs the LLM

    def check(self, payload: Payload, ctx: SessionContext) -> Verdict: ...
```

- **Implementors:** Every concrete detector module under `src/armor/detectors/`.
- **Consumers:** The daemon's `Pipeline` only.
- **Stability:** The signature is stable across minor versions. Adding fields is a breaking change.
- **Required behavior:**
  - Must be deterministic given `(payload, ctx)`.
  - Must not raise — must catch internal errors and return `Verdict.error(reason)`.
  - Must not perform I/O outside the daemon (no network, no filesystem writes).
  - Must complete within the configured per-detector budget (default 100 ms; LLM detectors get 500 ms).

### Trait: `Verdict`

```python
@dataclass(frozen=True)
class Verdict:
    decision: Literal["pass", "block", "advisory", "error"]
    signal_id: str | None       # which rule fired
    severity: Literal["low", "medium", "high", "critical"]
    message: str                # human-readable reason
    details: dict               # detector-specific structured details
```

Verdicts compose in the pipeline by aggregation: any `block` short-circuits to `block`; otherwise the highest severity `advisory` propagates and feeds the session risk score.

---

## Extension points

- **New detectors** are added by dropping a module under `src/armor/detectors/` that registers via the entry-point `armor.detectors`. The pipeline auto-discovers at boot. No core changes needed.
- **New canary types** are added by editing the canary generator script and re-running `armor canary regenerate` (which writes a new catalogue snapshot).
- **Custom hook clients** (e.g. for non-Claude-Code agents) speak the IPC directly — see `data-model.md` for the protocol.

armor does **not** support runtime detector hot-loading in v1. Reload = daemon restart.
