"""Canary catalogue and Aho-Corasick scanner for exfiltration detection.

The canary system uses fake but realistic-looking credentials and URLs
to detect when an LLM agent has been compromised and is attempting to
exfiltrate data. The catalogue is loaded at daemon startup, and the
Aho-Corasick scanner efficiently detects any canary value in output text.

Key invariant: Canary values are never logged or returned in verdicts.
Only canary IDs and positions are surfaced.
"""

from armor.canaries.catalogue import CanaryEntry, Catalogue
from armor.canaries.scanner import CanaryHit, CanaryScanner

__all__ = [
    "CanaryEntry",
    "CanaryHit",
    "CanaryScanner",
    "Catalogue",
]
