"""Detector for encoding-request injection patterns.

Detects requests asking the model to encode, encrypt, or obfuscate output,
which are precursors to canary-leak attempts. Examples:
- "encode this as base64"
- "use rot13 to obfuscate"
- "encrypt with AES"
- "spell the answer backwards"
- "use morse code"
- "represent as JSON-escaped"
"""

import re

from armor.types import Payload, SessionContext, Verdict


class RegexEncodingRequest:
    """Detects encoding-request injection patterns.

    Uses static regex patterns to identify requests for encoding, encryption,
    or obfuscation of output. Most matches return advisory verdicts (to feed
    session risk score), with block reserved for high-confidence attack
    patterns (e.g., "encode ... as base64 and put in URL").

    All patterns are case-insensitive.
    """

    id: str = "regex.encoding_request"
    category: str = "obfuscation"
    cost_tier: str = "static"

    # Compiled patterns — shared across all instances
    _patterns: list[tuple[re.Pattern[str], str]] | None = None

    def __init__(self) -> None:
        """Initialize the detector."""
        # Lazy-compile patterns on first instantiation
        if RegexEncodingRequest._patterns is None:
            RegexEncodingRequest._patterns = self._compile_patterns()
        self.patterns = RegexEncodingRequest._patterns

    @staticmethod
    def _compile_patterns() -> list[tuple[re.Pattern[str], str]]:
        """Compile all detection patterns.

        Returns:
            List of tuples (compiled regex pattern, verdict_type).
            verdict_type is "advisory" for soft signals or "block" for high-confidence.
        """
        # Patterns return advisory verdicts (feeds risk score, doesn't block alone)
        advisory_patterns = [
            # Base64 encoding — various formulations
            r"\bencode\s+.*?\s+as\s+base64\b",
            r"\bconvert\s+.*?\s+(?:to\s+)?base64\b",
            r"\bin\s+base64\b",
            # Hex encoding
            r"\bencode\s+.*?\s+as\s+hex\b",
            r"\bconvert\s+.*?\s+(?:to\s+)?hex\b",
            r"\bin\s+hex\b",
            # ROT13 / ROT-N cipher
            r"\brot13\b",
            r"\brot\s*-?\s*\d+\b",
            r"\bapply\s+.*?rot\b",
            # Encrypt/decrypt — various contexts
            r"\bencrypt\b",
            r"\bdecrypt\b",
            r"\bencryption\b",
            r"\bdecryption\b",
            # Atbash cipher
            r"\batbash\b",
            # Leetspeak
            r"\bleetspeak\b",
            r"\bl33t(?:speak|code)\b",
            # Morse code
            r"\bmorse\s+code\b",
            r"\bas\s+morse\b",
            # JSON escaping
            r"\bjson\s*-?\s*escaped\b",
            r"\brepresent\s+.*?\s+json\s*-?\s*escaped\b",
            # Generic "encode the following" pattern
            r"\bencode\s+the\s+(?:following|text|message|data|output)\b",
            # "Spell out" / "spell backwards"
            r"\bspell\s+(?:out|backwards)\b",
            # ASCII encoding
            r"\bascii\s+encod\b",
        ]

        # High-confidence attack patterns that trigger block
        block_patterns = [
            # Encode and exfiltrate via URL / endpoint
            r"\bencode.*?(?:as\s+base64|hex)\s+(?:and\s+)?(?:put|send|add|include).*?(?:url|parameter|endpoint|header)\b",
            r"\b(?:base64|hex)\s+(?:encode|encoding).*?(?:and\s+)?(?:put|send|leak|exfil|extract).*?(?:url|endpoint|destination|attacker|domain)\b",
            # Encrypt and send to external destination
            r"\bencrypt.*?(?:and\s+)?(?:send|transmit|leak).*?(?:endpoint|server|domain|attacker)\b",
        ]

        patterns: list[tuple[re.Pattern[str], str]] = []

        # Compile advisory patterns
        for pattern_str in advisory_patterns:
            try:
                pattern = re.compile(pattern_str, re.IGNORECASE)
                patterns.append((pattern, "advisory"))
            except re.error:
                # Skip malformed patterns; this is a deployment-time check
                pass

        # Compile block patterns (check these first so they take priority)
        for pattern_str in block_patterns:
            try:
                pattern = re.compile(pattern_str, re.IGNORECASE)
                patterns.append((pattern, "block"))
            except re.error:
                pass

        # Return block patterns first (priority) then advisory
        block_pats = [p for p in patterns if p[1] == "block"]
        advisory_pats = [p for p in patterns if p[1] == "advisory"]
        return block_pats + advisory_pats

    def check(self, payload: Payload, ctx: SessionContext) -> Verdict:
        """Check payload for encoding-request patterns.

        Args:
            payload: The payload being checked.
            ctx: Session context (unused for regex detector).

        Returns:
            Block or advisory verdict if pattern matches, pass verdict otherwise.
        """
        try:
            if not payload.text:
                return Verdict.pass_verdict()

            # Check each pattern in priority order (block patterns first)
            for idx, (pattern, verdict_type) in enumerate(self.patterns):
                match = pattern.search(payload.text)
                if match:
                    # First pattern match wins
                    signal_id = f"{self.id}:encoding-{idx + 1:03d}"

                    if verdict_type == "block":
                        return Verdict.block_verdict(
                            signal_id=signal_id,
                            message="Input flagged.",
                            severity="high",
                            details={
                                "matched_pattern_index": idx,
                                "matched_offset": match.start(),
                                "matched_length": match.end() - match.start(),
                                "pattern_type": "block",
                            },
                        )
                    else:  # advisory
                        return Verdict.advisory_verdict(
                            signal_id=signal_id,
                            severity="medium",
                            message="Input flagged.",
                            details={
                                "matched_pattern_index": idx,
                                "matched_offset": match.start(),
                                "matched_length": match.end() - match.start(),
                                "pattern_type": "advisory",
                            },
                        )

            return Verdict.pass_verdict()

        except Exception as e:
            return Verdict.error_verdict(
                reason=f"Detector error: {e!s}",
                details={"detector_id": self.id, "error": str(e)},
            )
