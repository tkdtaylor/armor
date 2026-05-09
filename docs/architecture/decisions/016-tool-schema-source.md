# ADR-016: Tool-parameter schema source and governance

**Status:** Accepted
**Date:** 2026-05-05
**Decider:** Architecture review

## Context

Task 013 implements a detector (`tool_param_schema`) that validates tool-call parameters against per-tool schemas and enforces risk rules for dangerous file paths, encoding patterns, and other attacks that hide in parameter values rather than tool names.

The detector needs a source of truth for:
1. **Parameter schemas** — what fields each tool accepts, their types, and whether they're required/optional.
2. **Risk rules** — content-based validation rules (e.g., "block reads of `/etc/shadow`", "block writes to `/etc/*`").

Multiple strategies exist:

1. **Hand-curated JSON in the repo** — Schemas and risk rules are maintained as data files under `src/armor/detectors/tool_schemas.json`. Changes are reviewed as code (pull request).

2. **Runtime fetch from Anthropic API** — The detector fetches schemas from a stable Anthropic endpoint at daemon boot. Requires network access, violates the no-network invariant. Deferred indefinitely.

3. **Inline Python dict** — Schemas hardcoded as Python dictionaries in the detector module. No external data files; schemas evolve with code reviews. Reduces maintainability and makes the schema harder to extend without code changes.

4. **Separate schema + risk-rules files** — Two YAML/JSON files: one for shape schemas, one for risk rules. Keeps concerns separate. Adds maintenance burden of coordinating two files across tool updates.

## Decision

Use **hand-curated JSON data files** bundled in the repo at `src/armor/detectors/tool_schemas.json` (single file, unified governance). Schemas and risk rules for all supported tools live in the same file.

**Rationale for each choice:**

- **Not runtime-fetched from Anthropic**: Armor is designed to work air-gapped. Outbound network calls from the daemon are forbidden by the project invariants. Anthropic does not publish a stable, versioned schema endpoint; the documented tool contract is in the human docs. Encoding schemas in the repo is acceptable churn (tool-surface changes are rare and visible).

- **Not inline Python dict**: Data-driven formats (JSON, YAML) are easier to extend, review, and audit than code. Contributors can understand the schema structure without reading Python. Separating data from logic reduces cognitive load.

- **Not separate files**: One file per tool update is simpler than updating two (schema + risk rules). When a tool's surface changes (e.g., a new param in `Write`), both the shape and any new risk rules for that param evolve in the same PR. Unified governance = one review gate.

- **JSON over YAML**: Both are valid; JSON is chosen because:
  - It is strictly typed (no type ambiguity like YAML's implicit typing).
  - Schema validation libraries (should we need them later) have first-class JSON Schema support.
  - No comments, but the file is small enough that docstrings in the code (the loader) carry the intent.

**Schema structure:**

```json
{
  "tools": {
    "Bash": {
      "params_schema": {
        "command": {"type": "string", "required": true}
      },
      "risk_rules": [
        {
          "id": "bash-absolute-path-system",
          "description": "Block reads of system-critical files via Bash command patterns",
          "type": "command_pattern",
          "patterns": [
            "cat /etc/shadow",
            "cat ~/.ssh/id_rsa"
          ]
        }
      ]
    },
    "Read": {
      "params_schema": {
        "file_path": {"type": "string", "required": true},
        "offset": {"type": "integer", "required": false},
        "limit": {"type": "integer", "required": false}
      },
      "risk_rules": [
        {
          "id": "read-dangerous-file",
          "description": "Block reads of sensitive system files",
          "type": "path_pattern",
          "patterns": [
            "/etc/shadow",
            "~/.ssh/id_*",
            "/proc/*/environ"
          ]
        }
      ]
    },
    ...
  }
}
```

**Validation approach:** Hand-rolled, minimal shape checker (no external `jsonschema` dependency). The loader validates:
- Required fields are present
- Optional fields (when present) have the correct type
- No extra fields are allowed

**Risk rules encoding:** Each rule is an object with:
- `id`: Unique rule ID (e.g., `read-dangerous-file`).
- `description`: Human-readable explanation.
- `type`: Rule category (`path_pattern`, `path_regex`, etc.) — determines how the rule is matched.
- `patterns`: Array of literal strings or regex patterns to match against the relevant parameter.

The detector applies risk rules in order; first match wins (fails closed — blocks on first match).

**Governance:**

- Schemas and risk rules are reviewed alongside code changes (PR process).
- Tool surface changes (new tool, new param, new risk rule) require schema updates in the same PR.
- Schemas are loaded once at detector init and frozen for the daemon's lifetime (no hot-reload, consistent with canary catalogue and pipeline).
- If the schema file is missing or malformed at daemon boot, the detector logs an error and continues with an empty schema dict (fail-open per detector). All subsequent checks on unknown tools return `pass`; checks on known tools with schema errors return `error`.

## Consequences

**Positive:**
- Data-driven, easy to extend and maintain without code changes.
- Single file = single PR per update = clear governance.
- No external dependencies or network calls.
- Schemas are reviewable, versionable, and auditable as part of the codebase.
- Schema structure is self-documenting.

**Negative:**
- Manual maintenance burden: when Claude Code adds a new tool, the schema must be added to this file (if we want to validate it). Until then, the detector silently passes unknown tools.
- Schema encoding is hand-rolled validation; no standard JSON Schema validator. This is acceptable for the current scope (7 tools, simple shapes), but would need revisiting if schemas become complex.
- Requires daemon restart to pick up schema changes (no hot-reload).

## Notes

The schema file is bundled with the package and can be accessed via package resources at runtime. The detector loads it once at `__init__` and stores it as frozen instance state.

The `tool_param_schema.py` detector serves both shape validation (via the schema) and risk rules (via per-tool risk_rules arrays). Both are part of the same governance model.

If a tool name appears in an incoming request but not in `tool_schemas.json`, the detector returns `pass` with `details={"unknown_tool": True}` — making it observable (so operators can audit "what tools are flying through that we don't have schemas for?") without blocking.

## Related ADRs

- **ADR-009**: Detector discovery — each detector is independent and composable; the registry loads the tool-param-schema detector at boot.
- **ADR-001**: Foundational stack — daemon architecture; configuration (and now schemas) are frozen at boot, not re-read.
- **ADR-010**: Canary invariants; data invariants matter. This ADR is about parameter validation, but the principle is similar — be explicit about what's immutable and when it's frozen.
