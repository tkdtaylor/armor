# armor vs NVIDIA OpenShell

**Last updated:** 2026-05-09

This page compares `armor` with [NVIDIA OpenShell](https://github.com/NVIDIA/OpenShell). The projects are adjacent, not substitutes. OpenShell is a safe runtime for autonomous agents: sandboxes, filesystem/network/process policy, provider credential handling, and inference routing. armor is a guard layer for agent prompts, model outputs, fetched content, tool-call parameters, canary exfiltration, session risk, and forensic logging.

## Source Materials

- [NVIDIA/OpenShell](https://github.com/NVIDIA/OpenShell)
- [NVIDIA OpenShell documentation](https://docs.nvidia.com/openshell/)
- [armor architecture overview](overview.md)
- [armor threat model](threat-model.md)
- [armor authoritative spec](../spec/SPEC.md)

## Executive Summary

OpenShell and armor address different parts of the agent-risk stack.

**OpenShell** protects the execution environment around an autonomous agent. Its public docs describe sandboxed execution environments, declarative YAML policies, controlled outbound network access, filesystem/process restrictions, provider credential handling, and privacy-aware inference routing. It is strongest when the question is: "What can this agent process access, execute, or send over the network?"

**armor** protects the semantic and tool-call boundary around an agent loop. It checks prompts, model outputs, fetched content, and tool calls for prompt injection, jailbreaks, canary exfiltration, encoding/obfuscation, dangerous shell patterns, and multi-turn attack buildup. It is strongest when the question is: "Is this prompt/output/tool call part of an attack chain?"

The best composition is layered: OpenShell contains the agent's operating environment; armor inspects the agent's LLM-facing and tool-facing traffic inside that environment.

## Comparison Matrix

| Dimension | armor | OpenShell |
| --- | --- | --- |
| Primary goal | LLM-agent security checks and forensic verdicts | Safe, private runtime for autonomous agents |
| Best fit | Prompt/output/tool-call inspection around an existing agent loop | Sandboxing agent execution and constraining filesystem, network, process, and inference access |
| Runtime placement | Long-lived daemon called by hooks, CLI, or SDK | Gateway plus sandbox runtime around the agent process |
| Policy surface | Detector thresholds, canaries, hook profiles, tool schemas, session risk | Declarative YAML policies for sandbox access and runtime controls |
| Filesystem controls | Out of scope except path/provenance signals in fetched-content checks | Core capability: sandbox filesystem boundaries and allowed paths |
| Network controls | Daemon makes no outbound network calls by default; detects exfil destinations in content | Core capability: policy-enforced egress routing and network deny/allow behavior |
| Process controls | Detects dangerous tool calls before execution; does not sandbox the OS process | Core capability: process and sandbox constraints |
| Inference routing | Local validator/honeypot inference for verdict support | Routes model API calls to controlled backends and manages inference policy |
| Credential handling | Canary values are fake secrets used as exfiltration tripwires; forensic log stores `canary_id` only | Provider credentials are injected for agents and kept out of sandbox filesystems |
| Prompt-injection detection | Core capability: input, output, fetched-content, and multi-turn detectors | Not the central abstraction; OpenShell constrains what compromised behavior can access or send |
| Tool-call validation | Core capability before execution | Environment policy can still deny unauthorized execution, network, or filesystem effects |
| Forensics/observability | SQLite incidents, session state, block reasons, canary IDs | Sandbox/gateway logs, terminal UI, OCSF-style observability in docs |

## Where OpenShell Is Stronger

OpenShell is the stronger choice when the problem is environment containment. It can limit what the agent process can read, write, execute, and contact even if the model is compromised by a prompt injection.

It is especially well suited for:

- **Sandboxed agent execution.** OpenShell gives autonomous agents their own constrained runtime rather than running them directly on the host.
- **Filesystem and process policy.** armor can detect risky tool calls, but OpenShell can enforce OS/runtime boundaries.
- **Network egress control.** OpenShell can block outbound connections unless policy allows them, including method/path-level network policy in documented examples.
- **Credential provider isolation.** OpenShell focuses on getting agent credentials into the runtime without leaving them as ordinary files in the sandbox.
- **Inference routing.** OpenShell can route model calls through controlled backends and keep inference traffic inside configured pathways.
- **Runtime observability.** Its gateway/sandbox model includes logs and a terminal UI for monitoring the environment.

## Where armor Is Stronger Or More Focused

armor is stronger when the problem is interpreting whether the agent's text, tool call, or fetched content is part of an LLM attack.

It is especially well suited for:

- **Prompt and output attack detection.** armor inspects user prompts, model output, and fetched tool content for injection, jailbreak, obfuscation, and exfiltration signals.
- **Canary exfiltration traps.** The honeypot/canary loop detects successful exfiltration attempts and records only `canary_id`, never the canary value.
- **Pre-execution tool-call verdicts.** armor can block a dangerous shell command before it is handed to the runtime.
- **Multi-turn semantic tracking.** armor maintains session state and rolling buffers to catch attacks that accumulate across turns.
- **Agent-framework neutrality.** armor can wrap existing Claude Code hooks or custom SDK loops without owning the whole sandbox.

## How They Can Work Together

A useful layered model is:

```text
Host
  -> OpenShell gateway
  -> OpenShell sandbox
  -> Agent process
  -> armor input / fetched / tool / output checks
  -> Sandbox filesystem, network, process, and inference policies
  -> External systems only when OpenShell policy allows
```

In that arrangement, armor asks "should this agent action be attempted?" and OpenShell asks "even if attempted, is the runtime allowed to do it?" Those are different failure modes and both are valuable.

For example, if an attacker prompts an agent to leak a credential to an external endpoint:

1. armor may block the prompt, tool call, fetched indirect injection, or final output before execution or user delivery.
2. If the compromised agent still attempts a network call, OpenShell's egress policy can deny the outbound request.
3. armor's forensic log can record the LLM-level attack evidence, while OpenShell's logs can record the sandbox-level policy denial.

## Decision Guide

Choose **OpenShell** when:

- You need a safe execution environment for autonomous agents.
- You care most about filesystem, network, process, credential, and inference-routing boundaries.
- You want sandbox-level policy enforcement even when the agent behaves badly.
- You need to run agents such as Claude Code, Codex, OpenCode, or Copilot in a constrained runtime.

Choose **armor** when:

- You need prompt-injection, jailbreak, exfiltration, and tool-call attack detection.
- You want canary/honeypot tripwires and forensic records.
- You already have an agent runtime and want security checks around its LLM-facing boundaries.
- You want to inspect tool calls before the runtime gets a chance to execute them.

Use **both** when:

- You want defense in depth: semantic attack detection plus sandbox containment.
- The agent has useful tool/network access, but you want strict control over what reaches those tools.
- You need both LLM-level incident evidence and environment-level policy enforcement.

## Caveats

- This comparison is based on public OpenShell documentation and the armor repository state as of 2026-05-09.
- It is qualitative, not a security benchmark or formal threat-model proof.
- OpenShell and armor are complementary layers: sandboxing does not replace prompt/output/tool-call inspection, and prompt inspection does not replace OS/runtime containment.
- armor is not a sandbox and should be paired with runtime controls when an agent can affect valuable host or network resources.
