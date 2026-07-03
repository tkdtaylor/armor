# Detection categories

armor provides runtime detection across seven attack families. This document outlines
what each detector looks for and how the detection pipeline works.

## Input-side detectors

These run on user input before the agent sees it.

### Direct injection

- System prompt extraction attempts (e.g., "reveal your system prompt")
- Instruction override patterns (e.g., "ignore previous instructions")
- SSRF probes and sensitive file access patterns
- Code injection attempts

### Jailbreak templates

Regex matching against a curated corpus of known jailbreak prompts (direct and indirect).
See the red-team corpus in `tests/eval/corpus/` for the full taxonomy.

### Encoding requests

Keywords indicating encoding/obfuscation requests (base64, ROT13, hex, URL encode).
When matched, the detector flags the request as suspicious and the downstream pipeline
decodes and re-scans the payload.

## Output-side detectors

These run on model output before it reaches the user.

### Canary scanning

Detects emitted canary values (fake credentials, PII records, webhook URLs) seeded via
`armor canary seed`. Uses `pyahocorasick` for multi-pattern matching. Canary matches
are never stored verbatim in the forensic log — only the `canary_id` is recorded, so
the log itself cannot become an exfiltration channel.

Three canary surfaces:
- **Filesystem credentials:** AWS-key-shaped, GitHub token-shaped canaries written to `.env`
- **PII records:** Fake name, email, date of birth, address, SIN records in the system prompt
- **Webhook honeypots:** Fake internal webhook URLs, IP addresses, and API keys

### Entropy analysis

Rolling per-session output entropy analysis. Compares current output against historical
entropy for the session to detect anomalously high-entropy payloads (indicator of encoding
or exfiltration).

### URL / IP / email extraction

Extracts URLs, IP addresses, and email addresses from model output and checks them
against user-configured exfiltration domains. By default checks for outbound to
unexpected cloud storage, credential services, and suspicious paste bins.

## Tool-side detectors

These run on tool parameters before execution.

### Parameter schema validation

Validates tool parameters against declared JSON schemas to ensure type and value safety.

### Dangerous bash patterns

Denylists shell commands that could be destructive:
- `rm -rf /`, `dd if=/dev/zero`, `/dev/random`
- Reads of `/etc/shadow`, `/etc/passwd`
- Container escape patterns
- Attempts to modify system files

## Session-level detectors

These track state across multiple turns.

### Multi-turn rolling buffer

Per-session rolling output buffer (default 8 KB / 20 turns, tunable). Detectors re-run
against the concatenated output to catch chunked exfiltration attempts that look benign
individually but malicious in aggregate.

### Risk escalation state machine

Five-state finite state machine (Normal → Watching → Elevated → High → Blocked) tracks
session risk. Escalates on:
- Repeated injection attempts (↑ confidence threshold)
- Partial canary matches (≥ 12 character prefix match)
- Output entropy spikes
- Dangerous tool calls

Linear-decay cooldown allows recovery. See [ADR-024](architecture/decisions/024-multi-turn-state-machine.md).

### Topic-coherence advisory

Embedding-based similarity check using `all-MiniLM-L6-v2` ONNX model. Computes per-session
exponential moving average of output cosine distance to benign queries. Flags when
output diverges from expected topic (advisory only — feeds the FSM but never blocks
unilaterally).

## Validator LLM (optional)

An optional quantized local LLM (Qwen3-0.6B) runs final semantic validation on both
input and output. Used when the risk level warrants it (gates the cost tier). When the
LLM times out (P95 budget breached), the request passes rather than blocks
(fail-open by design; see [ADR-023](architecture/decisions/023-llm-budget-soft-fail.md)).

## Pipeline composition

The full pipeline flows as:

1. **Input check** → static filters (encoding requests, instruction overrides, jailbreak templates) → LLM validator (optional, risk-gated) → pass/block
2. **Tool-call check** → parameter validation + dangerous bash patterns → pass/block
3. **Output check** → static filters (URLs, IPs, emails) + canary scan + entropy analysis → rolling-buffer re-run → LLM validator (optional) → pass/block + forensic incident
4. **Session escalation** → rolling buffer + topic coherence feed the FSM; FSM gates LLM cost tier

See [docs/spec/behaviors.md](spec/behaviors.md) for the authoritative behavioral spec.
