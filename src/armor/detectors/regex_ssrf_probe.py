"""Detector for SSRF (Server-Side Request Forgery) probe attacks.

Detects attempts to fetch cloud instance metadata endpoints and other
link-local / SSRF-canonical addresses from input text, such as:
- "Fetch http://169.254.169.254/latest/meta-data/"
- "GET http://metadata.google.internal/"
- "curl 100.100.100.200"
"""

import re

from armor.types import Payload, SessionContext, Verdict

# (pattern_string, signal_suffix)
_PATTERN_SPECS: list[tuple[str, str]] = [
    # AWS/Azure IMDS — 169.254.169.254 is the canonical link-local IMDS address
    (r"\b169\.254\.169\.254\b", "imds-link-local"),
    # GCP metadata server
    (r"\bmetadata\.google\.internal\b", "imds-gcp"),
    # Alibaba Cloud ECS metadata
    (r"\b100\.100\.100\.200\b", "imds-alibaba"),
    # Oracle Cloud IMDS
    (r"\b169\.254\.0\.2\b", "imds-oracle"),
    # Generic "fetch / curl / GET / wget" + any URL containing link-local IPs
    (r"\bhttp://169\.254\.", "imds-url-prefix"),
]


class RegexSsrfProbe:
    """Detects SSRF/IMDS probe patterns in input text.

    Targets the most common cloud metadata endpoints. Any mention of
    169.254.169.254 or the GCP/Alibaba equivalent in user text is a
    strong signal — these addresses have no legitimate use in chat.

    All patterns are cost_tier 'static' (pure regex, no LLM).
    """

    id: str = "regex.ssrf_probe"
    category: str = "tool_abuse"
    cost_tier: str = "static"

    _patterns: list[tuple[re.Pattern[str], str]] | None = None

    def __init__(self) -> None:
        if RegexSsrfProbe._patterns is None:
            RegexSsrfProbe._patterns = [(re.compile(p, re.IGNORECASE), sig) for p, sig in _PATTERN_SPECS]
        self.patterns = RegexSsrfProbe._patterns

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
