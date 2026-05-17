"""Detector for Python code injection attacks via agent code execution tools.

Catches instructions that embed executable Python code designed to exfiltrate
data or execute shell commands. Covers both the user-instruction vector
(attacker tells the agent to run injected code) and the tool-parameter vector
(injected code appears inside a code tool's 'code' or 'input' parameter).

Detected patterns:
  - __import__('subprocess')  — dynamic subprocess import to bypass static analysis
  - subprocess.run/call/Popen + network tool  — shell-out with data exfiltration
  - os.system() + network tool  — direct shell execution with network activity
"""

import re

from armor.types import Payload, SessionContext, Verdict

_CODE_INJECTION_PATTERNS: list[tuple[str, str]] = [
    # __import__('subprocess') — canonical code injection bypass technique
    (r"__import__\s*\(\s*['\"]subprocess['\"]", "python-subprocess-import"),
    # subprocess module + network exfiltration tool in the same expression
    (
        r"subprocess\s*\.\s*(?:run|call|Popen|check_output)\s*\(.{0,300}?"
        r"(?:curl|wget|nc\b|ncat\b|requests\.(?:get|post|put)|http\.request)",
        "python-subprocess-net",
    ),
    # os.system() paired with a network tool
    (
        r"\bos\s*\.\s*system\s*\(.{0,200}?(?:curl|wget|nc\b|ncat\b)",
        "python-os-system-net",
    ),
]


class RegexCodeInjection:
    """Detects Python code injection patterns targeting agent code execution tools.

    Scans both input text (the user instruction) and code tool parameters
    (the code argument itself) for injected subprocess or shell-escape patterns.

    All patterns are cost_tier 'static' (pure regex, no LLM).
    """

    id: str = "regex.code_injection"
    category: str = "tool_abuse"
    cost_tier: str = "static"

    _patterns: list[tuple[re.Pattern[str], str]] | None = None

    def __init__(self) -> None:
        if RegexCodeInjection._patterns is None:
            compiled: list[tuple[re.Pattern[str], str]] = []
            for pat_str, sig in _CODE_INJECTION_PATTERNS:
                compiled.append((re.compile(pat_str, re.IGNORECASE | re.DOTALL), sig))
            RegexCodeInjection._patterns = compiled
        self.patterns = RegexCodeInjection._patterns

    def check(self, payload: Payload, ctx: SessionContext) -> Verdict:
        try:
            text = payload.text or ""
            code_param = ""
            if payload.params:
                code_param = str(payload.params.get("code", "") or payload.params.get("input", "") or "")

            combined = text + ("\n" + code_param if code_param else "")
            if not combined.strip():
                return Verdict.pass_verdict()

            for pattern, sig in self.patterns:
                match = pattern.search(combined)
                if match:
                    return Verdict.block_verdict(
                        signal_id=f"{self.id}:{sig}",
                        message="Input blocked by armor.",
                        severity="critical",
                        details={
                            "matched_pattern": sig,
                            "matched_offset": match.start(),
                            "matched_length": match.end() - match.start(),
                        },
                    )

            return Verdict.pass_verdict()

        except Exception as e:
            return Verdict.error_verdict(
                reason=f"Detector error: {e!s}",
                details={"detector_id": self.id, "error": str(e)},
            )
