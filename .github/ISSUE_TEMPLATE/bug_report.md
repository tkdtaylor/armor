---
name: Bug report
about: Report unexpected behavior in armor (the daemon, the CLI, a detector, the eval harness, or the build)
title: "[bug] "
labels: ["bug", "triage"]
---

## Summary

<!-- One-sentence description of what is broken. -->

## Reproduction

Steps to reproduce, ideally minimal:

1. ...
2. ...
3. ...

If the bug surfaces only via a specific input prompt or session shape, paste the input verbatim in a fenced block so triage can replay it.

```text
<input that triggers the bug>
```

## Expected vs. actual

- **Expected:** <what should have happened>
- **Actual:** <what did happen — include exit code, verdict, log line, traceback>

## Environment

- armor version / commit SHA: `git rev-parse --short HEAD` →
- Python: `python --version` →
- OS: <distro / kernel>
- Container or host: <docker compose / native uv>
- Validator model: <gguf path or `none`>

## Eval-corpus impact

Does this bug affect a known test case?

- [ ] Yes — TC reference: `TC-NNN-XX` (link to the test spec or eval row)
- [ ] No — this is a new failure mode not covered by the corpus

## Logs / forensic context

Paste relevant log excerpts. **Redact any literal canary value** before pasting; the forensic log normally references `canary_id` only — if you see a literal value in your paste, that itself is a separate bug worth flagging.

```text
<logs>
```
