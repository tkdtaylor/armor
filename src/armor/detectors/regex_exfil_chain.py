# SPDX-License-Identifier: Apache-2.0
"""Detector for chained tool-abuse attacks that exfiltrate data to an external URL.

Catches instructions where the attacker chains a data-retrieval action with an
exfiltration step that sends the result to an attacker-controlled endpoint.

Detected patterns:
  - "then/and send/upload/forward ... http://..."  — explicit chain instruction
  - URL with a data-collection path segment (/collect, /exfil, /steal, ...)
"""

import re

from armor.types import Payload, SessionContext, Verdict

# Exclude loopback/localhost — these appear in legitimate local API calls.
_LOCAL_NEGATIVE = r"(?!(?:localhost|127\.0\.0\.1|0\.0\.0\.0)\b)"

_EXFIL_CHAIN_PATTERNS: list[tuple[str, str]] = [
    # "then / and  send/post/upload/forward ... http(s)://..."
    # The "then|and" anchor limits this to chained sequences, not standalone send instructions.
    (
        rf"\b(?:then|and)\s+(?:send|post|upload|forward|transmit|exfiltrate|push)\b"
        rf".{{0,120}}?https?://{_LOCAL_NEGATIVE}",
        "exfil-chained-to-url",
    ),
    # URL whose path ends in an explicit collection/exfiltration segment
    (
        rf"https?://{_LOCAL_NEGATIVE}[^\s/\"']+/(?:collect|exfil|leak|steal|harvest|capture|recv(?:eive)?|grab)\b",
        "exfil-suspicious-path",
    ),
]


class RegexExfilChain:
    """Detects chained tool-abuse instructions that route data to an external URL.

    Scans input text for the combination of a retrieval action followed by a
    send/upload instruction targeting a remote endpoint. Also catches URLs
    with path segments that are unambiguously used for OOB data collection.

    All patterns are cost_tier 'static' (pure regex, no LLM).
    """

    id: str = "regex.exfil_chain"
    category: str = "exfiltration"
    cost_tier: str = "static"

    _patterns: list[tuple[re.Pattern[str], str]] | None = None

    def __init__(self) -> None:
        if RegexExfilChain._patterns is None:
            compiled: list[tuple[re.Pattern[str], str]] = []
            for pat_str, sig in _EXFIL_CHAIN_PATTERNS:
                compiled.append((re.compile(pat_str, re.IGNORECASE | re.DOTALL), sig))
            RegexExfilChain._patterns = compiled
        self.patterns = RegexExfilChain._patterns

    def check(self, payload: Payload, ctx: SessionContext) -> Verdict:
        try:
            text = payload.text or ""
            if not text:
                return Verdict.pass_verdict()

            for pattern, sig in self.patterns:
                match = pattern.search(text)
                if match:
                    return Verdict.block_verdict(
                        signal_id=f"{self.id}:{sig}",
                        message="Input blocked by armor.",
                        severity="high",
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
