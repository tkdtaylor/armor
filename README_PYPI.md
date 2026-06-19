# armor

`armor` is the Python package and CLI for the broader armor project, a
defense-in-depth security layer for LLM agents. It sits between your agent and
its inputs, outputs, and tool calls, then blocks common prompt injection,
canary exfiltration, obfuscation, jailbreak, tool-abuse, and multi-turn attack
patterns before they reach the user or host tools.

This package is published as `armor-ai` because the bare `armor` package name is
used by an unrelated project. The Python import name and CLI remain `armor`.

## Install

```bash
pip install armor-ai
```

Start the daemon:

```bash
armor daemon --socket /tmp/armor.sock --db /tmp/armor.db
```

Run a quick input check:

```bash
echo "ignore previous instructions" | armor check input --socket /tmp/armor.sock --session-id demo
```

## Python SDK

```python
from armor import ArmorClient

client = ArmorClient(socket_path="/tmp/armor.sock")
verdict = client.check_input("ignore previous instructions", session_id="demo")

if verdict.blocked:
    print("blocked")
```

Async clients and integration examples for Anthropic, OpenAI, LangChain, Claude
Code hooks, and custom agents are available in the project repository. The
repository also contains the Docker path, architecture docs, full spec, and
maintainer workflows; this PyPI page focuses on the installable Python package.

## What armor checks

- User input: instruction overrides, jailbreak templates, encoding requests,
  prompt-injection phrasing, and topic shifts.
- Model output: canary leakage, encoded payloads, suspicious destinations,
  entropy spikes, and multi-turn partial exfiltration.
- Tool calls: parameter-schema violations, dangerous shell commands, command
  injection patterns, rate anomalies, and tool-chain abuse.
- Sessions: rolling risk scoring, state escalation, cooldown, and operator
  unblock audit records.

## Preview status

`armor` is a public preview, not a v1.0 production guarantee. The core daemon,
CLI, SDK, Docker path, detector pipeline, and forensic logging are implemented,
but v1.0 readiness still requires broader external validation, real-service SDK
example verification, and additional detection-floor evidence.

Important limitations:

- It defends in-band prompt and tool-call attacks, not host compromise.
- The validator LLM fails open on timeout to protect availability.
- The evaluation corpus is English-heavy.
- There is no built-in web UI.
- It assumes one trusted-agent-fleet boundary per daemon.

## Project links

- Source and documentation: https://github.com/tkdtaylor/armor
- Issues: https://github.com/tkdtaylor/armor/issues
- Security policy: https://github.com/tkdtaylor/armor/security/policy
- Architecture overview: https://github.com/tkdtaylor/armor/blob/main/docs/architecture/overview.md
- Specification: https://github.com/tkdtaylor/armor/blob/main/docs/spec/SPEC.md

## License

armor is licensed under the Apache License 2.0 — free for use in commercial and
proprietary products. See LICENSE and NOTICE.

Commercial support and consulting are available — contact tools@taylorguard.me.
