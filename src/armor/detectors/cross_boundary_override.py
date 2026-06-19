# SPDX-License-Identifier: Apache-2.0
"""Cross-boundary override detector (ADR-043 §3).

A provenance-gated tripwire: fires when external-origin content
(``TOOL_RESULT_UNTRUSTED`` or ``TOOL_RESULT_TRUSTED``) contains agent-directed
override / jailbreak language. Legitimate untrusted content — a wiki page, a Jira
ticket, a fetched HTML body — has no business issuing "ignore previous
instructions", "you are now …", or system-prompt-extraction language *to the
agent*. When that language appears inside a span labelled as a tool result, it is
a far stronger injection signal than the identical text in ``USER_INPUT``.

Provenance gating:
- ``USER_INPUT`` / ``MODEL_OUTPUT`` / ``TOOL_PARAMS`` → early ``pass`` (the
  ``regex.instruction_override`` family already owns user-side override
  detection; this detector is the provenance-qualified variant, not a duplicate).
- ``TOOL_RESULT_UNTRUSTED`` / ``TOOL_RESULT_TRUSTED`` → scan at full confidence
  (1.0). The detector fires at full confidence on trusted sources deliberately:
  the operator's trust allowlist vouches for a source's *integrity*, not for its
  *right to issue agent-directed overrides* (ADR-043 §3). It is carved out of the
  pipeline's trusted-source skip set (see ``Pipeline._TRUSTED_SOURCE_SKIP_SET``).

Sentinel forgery (ADR-043 §4): if an untrusted span already contains the base
spotlight sentinel string (a boundary-escape / pre-close attempt), that is itself
the highest-priority attack signal — checked *before* the override pattern scan.

Pattern reuse (no duplication): the override / jailbreak corpus is imported from
each detector's authoritative ``get_compiled_patterns()`` export rather than
copied (the only cross-detector import the modularity fitness check permits —
see ``tests/fitness/test_detector_no_cross_import.py``):
- ``regex_instruction_override.get_compiled_patterns()``
- ``regex_system_prompt_extraction.get_compiled_patterns()``
- ``regex_roleplay_hijack.get_compiled_patterns()`` (covers "you are now DAN", etc.)
- ``regex_authority_impersonation.get_compiled_patterns()`` (block-tier rules only)

The verdict feeds ``apply_signal`` in the server pipeline like the rest of the
``indirect_injection.*`` family once the right ``signal_id`` namespace is emitted.
"""

import re

from armor.detectors.regex_authority_impersonation import (
    get_compiled_patterns as get_authority_patterns,
)
from armor.detectors.regex_instruction_override import (
    get_compiled_patterns as get_override_patterns,
)
from armor.detectors.regex_roleplay_hijack import (
    get_compiled_patterns as get_roleplay_patterns,
)
from armor.detectors.regex_system_prompt_extraction import (
    get_compiled_patterns as get_extraction_patterns,
)
from armor.types import Payload, SessionContext, Source, Verdict

# Attack category for this detector's family (ADR-043 §3).
ATTACK_CATEGORY = "indirect_injection.cross_boundary"

# Default base spotlight sentinel (ADR-043 §5). A per-render random suffix is
# appended by the annotator; the *base* string appearing inside untrusted content
# is a boundary-escape attempt.
DEFAULT_SENTINEL = "ARMOR-UNTRUSTED"

# Sources that get scanned (external-origin only). All others early-pass.
_SCANNED_SOURCES = frozenset({Source.TOOL_RESULT_UNTRUSTED, Source.TOOL_RESULT_TRUSTED})


def _build_rules() -> list[tuple[str, re.Pattern[str]]]:
    """Aggregate the reused override / jailbreak corpus as (rule_id, pattern) pairs.

    Rules are imported from their authoritative detector modules — never copied —
    and each is given a stable ``<rule>`` id used in the ``signal_id`` namespace
    ``cross_boundary_override:<rule>``. The id is lowercase / digit / ``-`` / ``_``
    only, matching the spec's ``signal_id`` namespace format.

    Returns:
        List of (rule_id, compiled_pattern) tuples, scanned in order.
    """
    rules: list[tuple[str, re.Pattern[str]]] = []

    # Instruction-override family (shared export).
    for idx, pat in enumerate(get_override_patterns()):
        rules.append((f"override-{idx + 1:03d}", pat))

    # System-prompt-extraction family (shared export).
    for idx, pat in enumerate(get_extraction_patterns()):
        rules.append((f"extraction-{idx + 1:03d}", pat))

    # Roleplay-hijack family (shared export; covers "you are now DAN", "pretend
    # you are", "act as if you have no restrictions", etc.).
    for idx, pat in enumerate(get_roleplay_patterns()):
        rules.append((f"roleplay-{idx + 1:03d}", pat))

    # Authority-impersonation family: reuse the block-tier rules only. Advisory
    # rules ("this is for a security audit") are plausibly benign content a
    # legitimate document might quote, so they are not promoted to a tripwire.
    for idx, (pat, tier) in enumerate(get_authority_patterns()):
        if tier == "block":
            rules.append((f"authority-{idx + 1:03d}", pat))

    return rules


class CrossBoundaryOverride:
    """Detects agent-directed override language inside tool-result content.

    Pure detector (no mutation, no network). Reuses the existing override /
    jailbreak pattern corpus and emits a distinct ``signal_id`` namespace and
    ``attack_category`` so the forensic log distinguishes "override language found
    *in untrusted content*" from "user typed override language".
    """

    id: str = "cross_boundary_override"
    category: str = ATTACK_CATEGORY
    cost_tier: str = "static"

    # Compiled rules — shared across all instances (lazy-built once).
    _rules: list[tuple[str, re.Pattern[str]]] | None = None

    def __init__(
        self,
        sentinel: str = DEFAULT_SENTINEL,
        block_threshold: float = 0.7,
    ) -> None:
        """Initialize the detector.

        Args:
            sentinel: Base spotlight sentinel string. Its appearance inside an
                untrusted span is treated as a boundary-escape attempt and raises
                ``cross_boundary_override:sentinel_forgery``. Default
                ``"ARMOR-UNTRUSTED"`` (ADR-043 §5).
            block_threshold: Confidence at/above which the verdict is a block
                rather than an advisory. The detector always scans at confidence
                1.0, so any value ≤ 1.0 (default 0.7) means a match blocks.
        """
        self.sentinel = sentinel
        self.block_threshold = block_threshold
        if CrossBoundaryOverride._rules is None:
            CrossBoundaryOverride._rules = _build_rules()
        self.rules = CrossBoundaryOverride._rules

    def _verdict_for(self, signal_id: str, matched_rule: str, source: Source) -> Verdict:
        """Build a block/advisory verdict at full confidence for a fired rule.

        Confidence is always 1.0 (raw, before the pipeline source multiplier).
        Whether that materializes as a block or advisory is governed by
        ``block_threshold``.
        """
        details: dict[str, object] = {
            "attack_category": ATTACK_CATEGORY,
            "confidence": 1.0,
            "matched_rule": matched_rule,
            "source": source.value,
        }
        if self.block_threshold <= 1.0:
            return Verdict.block_verdict(
                signal_id=signal_id,
                message="Tool-result content contained agent-directed override language.",
                severity="high",
                details=details,
            )
        return Verdict.advisory_verdict(
            signal_id=signal_id,
            severity="medium",
            message="Tool-result content contained agent-directed override language.",
            details=details,
        )

    def check(self, payload: Payload, ctx: SessionContext) -> Verdict:
        """Check a payload for cross-boundary override language.

        Args:
            payload: The payload being checked.
            ctx: Session context (unused — this detector is stateless).

        Returns:
            ``pass`` for non-external sources or benign external content; a
            block/advisory verdict otherwise. Never raises.
        """
        try:
            # Provenance gate: only external-origin content is scanned.
            if payload.source not in _SCANNED_SOURCES:
                return Verdict.pass_verdict()

            text = payload.text
            if not text:
                return Verdict.pass_verdict()

            # Sentinel forgery takes priority over every pattern rule (ADR-043 §4).
            if self.sentinel in text:
                return self._verdict_for(
                    signal_id="cross_boundary_override:sentinel_forgery",
                    matched_rule="sentinel_forgery",
                    source=payload.source,
                )

            # Override / jailbreak corpus scan; first match wins.
            for rule_id, pattern in self.rules:
                if pattern.search(text):
                    return self._verdict_for(
                        signal_id=f"cross_boundary_override:{rule_id}",
                        matched_rule=rule_id,
                        source=payload.source,
                    )

            return Verdict.pass_verdict()

        except Exception as e:  # pragma: no cover - defensive; detectors must not raise
            return Verdict.error_verdict(
                reason=f"Detector error: {e!s}",
                details={"detector_id": self.id, "error": str(e)},
            )
