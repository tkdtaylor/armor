# armor vs NVIDIA NeMo Guardrails

**Last updated:** 2026-05-09

This page compares `armor` with [NVIDIA NeMo Guardrails](https://github.com/NVIDIA-NeMo/Guardrails). It is not a benchmark and it does not claim one project replaces the other. The short version: NeMo Guardrails is a broad programmable guardrails framework for conversational and RAG applications; armor is a local security layer focused on runtime interception, canary exfiltration detection, tool-call validation, session risk, and forensic logging around existing agent loops.

## Source Materials

- [NVIDIA-NeMo/Guardrails](https://github.com/NVIDIA-NeMo/Guardrails)
- [NVIDIA NeMo Guardrails documentation](https://docs.nvidia.com/nemo/guardrails/latest/)
- [NeMo Guardrails: How It Works](https://docs.nvidia.com/nemo/guardrails/latest/about/how-it-works.html)
- [armor architecture overview](overview.md)
- [armor threat model](threat-model.md)
- [armor authoritative spec](../spec/SPEC.md)

## Executive Summary

Both projects sit in the guardrails/security space, but they optimize for different layers.

**NeMo Guardrails** is an application guardrails framework. Its public docs describe programmable rails around LLM conversations, including input, dialog, retrieval, execution, and output rails. It is a good fit when the application needs controlled conversation flows, topical boundaries, RAG chunk filtering, model-response shaping, or a framework-level layer that developers call instead of calling the model directly.

**armor** is a security-focused perimeter around an agent runtime. It does not try to become the conversation framework. It runs as a daemon, receives checks from hooks or an SDK, and makes pass/block/advisory decisions for user input, model output, fetched tool results, and tool calls. Its distinctive mechanisms are canary/honeypot exfiltration detection, deterministic tool-call validation, multi-turn session risk, and forensic records that never store canary values verbatim.

The two can be complementary: NeMo Guardrails can shape and constrain the LLM application internally, while armor can sit outside the agent loop as a local tripwire and forensic layer.

## Comparison Matrix

| Dimension | armor | NeMo Guardrails |
| --- | --- | --- |
| Primary goal | Security perimeter for LLM agents | Programmable guardrails framework for LLM applications |
| Best fit | Existing agent loops, local developer agents, hook-driven enforcement, tool-call security, canary exfiltration detection | Conversational assistants, RAG apps, model endpoint wrappers, workflow/dialog control |
| Runtime placement | Separate long-lived daemon called by hooks, CLI, or SDK | In-process Python API or guardrails server called by the application |
| Integration style | Intercept checks at input, fetched content, tool-call, and output boundaries | Route model calls through configured rails and `LLMRails` / server APIs |
| Configuration model | `armor.toml`, detector thresholds, hook profiles, canary values, daemon paths | Guardrails configuration folders with YAML, Colang flows, Python actions, and model settings |
| Conversation design | Out of scope except security signals | Core capability: dialog rails, predefined flows, topic handling, response shaping |
| RAG/retrieval controls | Indirect-injection scanning for fetched tool results; no full RAG orchestration | Retrieval rails can reject or alter retrieved chunks before they reach the model |
| Tool controls | Tool-call validation before execution; dangerous shell patterns and schema checks | Execution rails apply around custom actions/tools inside the application flow |
| Exfiltration canaries | First-class canary catalogue, honeypot prompt, output scanning, rolling buffers | Public docs emphasize programmable rails; canary-trip forensics are not the central architecture |
| Forensics | SQLite incident log, session state, canary IDs only, no canary values stored | Application/framework oriented; incident storage strategy is application-dependent |
| Network posture | Daemon makes no outbound network calls by default; local inference path | Supports multiple LLM providers and deployment styles; network use depends on configured models/services |
| Failure semantics | Deterministic pass/block/advisory verdicts; validator LLM soft-fails open, pipeline-level failures block | Depends on rail configuration and application integration |
| Project scope | Narrower, security-specific, preview package and Docker image | Broader, mature framework with extensive docs, examples, and integrations |

## Where NeMo Guardrails Is Stronger

NeMo Guardrails is the stronger choice when the application needs a programmable conversation framework. Its rails model gives developers explicit places to define how users, assistants, retrieval chunks, and custom actions should behave.

It is especially well suited for:

- **Dialog policy and flow control.** If the application needs standard operating procedures, topic steering, escalation flows, or scripted interaction patterns, NeMo's dialog rails and Colang model directly target that problem.
- **RAG application shaping.** Retrieval rails are a natural fit for filtering or altering retrieved chunks before they are sent into the model context.
- **Application-level response shaping.** NeMo can reject, alter, or steer responses as part of the normal model-call path.
- **Provider and framework integration.** NeMo is designed to sit between application code and the LLM provider or framework, with documented support for multiple LLM backends and LangChain-style use cases.
- **Policy guardrails beyond security.** NeMo's examples and docs cover broader "trustworthy assistant" behavior, including topical restrictions and conversational style, not just adversarial-prompt security.

## Where armor Is Stronger Or More Focused

armor is deliberately narrower. It is strongest when the goal is to add a local, security-oriented layer around an agent without replacing the agent framework.

It is especially well suited for:

- **Hook-level runtime enforcement.** armor can protect an existing tool-using agent through input, output, fetched-content, and tool-call checks without making the agent call a new conversation framework.
- **Canary exfiltration detection.** The honeypot/canary loop turns successful prompt-injection exfiltration into a deterministic string-match event. The forensic log stores `canary_id`, not the secret-like value.
- **Tool-call validation before execution.** armor treats tool calls as a first-class security boundary, including shell-command risk patterns and declared schema checks.
- **Multi-turn attack tracking.** Session state, rolling output buffers, topic-coherence signals, and partial-canary detection let armor treat a suspicious sequence differently from an isolated benign turn.
- **Local/no-network daemon posture.** The daemon path is designed to work without outbound network calls by default, so the guard layer is not itself an exfiltration route.
- **Forensic audit trail.** armor records block decisions, session state, and incident evidence in SQLite for later inspection.

## How They Can Work Together

The clean composition is layered:

```text
User
  -> NeMo Guardrails input/dialog/retrieval rails
  -> Agent or application logic
  -> armor tool-call check before tool execution
  -> Tools / retrieval / shell
  -> armor fetched-content or output check
  -> NeMo output rails, if the app uses them
  -> User
```

In that arrangement, NeMo owns the application behavior contract: what the assistant should talk about, how it should flow through tasks, and how retrieved context is shaped. armor owns the local runtime security tripwires: whether a prompt, fetched result, tool call, or output looks like injection, tool abuse, canary leakage, or multi-turn exfiltration.

This is defense in depth, not duplication. If NeMo prevents the unsafe behavior, armor never fires. If an injection or tool-abuse attempt gets past the application-level rails, armor still has an independent runtime check and an audit record.

## Decision Guide

Choose **NeMo Guardrails** when:

- You are building a conversational application and want a framework for rails, flows, and response shaping.
- You need RAG-specific retrieval rails or topic/dialog control.
- Your guardrail logic should live inside the application's model-call path.
- You want a broad ecosystem of documented examples and integrations.

Choose **armor** when:

- You have an existing agent loop and want security checks around it without replacing the orchestration layer.
- You care about canary exfiltration detection and forensic records.
- You need to validate tool calls before execution.
- You want a local daemon with no outbound network calls on the default verdict path.
- You are protecting a developer-agent workflow such as Claude Code hooks or a custom SDK loop.

Use **both** when:

- The app needs rich conversation/RAG policy and also needs independent runtime security tripwires.
- You want NeMo to reduce unsafe behavior inside the app, and armor to catch exfiltration or tool abuse at the boundaries.
- You want an application guardrail framework plus a separate forensic layer.

## Caveats

- This comparison is based on public NeMo Guardrails documentation and the armor repository state as of 2026-05-09.
- It is qualitative, not a latency, accuracy, or vulnerability-coverage benchmark.
- NeMo Guardrails is a larger and more mature framework; armor is intentionally narrower and security-specific.
- armor is not a replacement for model-side safety training, application policy, sandboxing, dependency scanning, or host security.
