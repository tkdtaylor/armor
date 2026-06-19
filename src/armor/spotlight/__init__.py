"""armor.spotlight — provenance annotation for LLM context windows.

A pure, importable library transform that annotates a context window with
provenance delimiters, enabling downstream LLMs to treat marked content as
data, never as instructions. Specified in ADR-043 §2 and §4.

This package has NO imports of armor.pipeline, armor.daemon, or armor.detectors.
It is a stand-alone transform meant to be called by the agent author when
assembling a context window, before handing it to the downstream LLM.

Public API (ADR-028 stable surface — additive on minor versions):

    from armor.spotlight import annotate, Span, SentinelForgeryError
    from armor.types import Source

    marked_text, boundary_instruction = annotate(
        [
            Span(text=system_prompt, source=Source.USER_INPUT),
            Span(text=web_page_body, source=Source.TOOL_RESULT_UNTRUSTED),
            Span(text=user_msg, source=Source.USER_INPUT),
        ],
        strategy="delimit",          # default; see ADR-043 §4
    )
    # Prepend boundary_instruction to your system prompt.
    # Pass marked_text as the context to the downstream LLM.

Strategies:
    delimit  (default): Wraps each marked span in randomized sentinel delimiters.
    datamark (opt-in):  Interleaves sentinel tokens between word groups.
    encode   (deferred): Raises NotImplementedError — see ADR-043 §4.
"""

from armor.spotlight._annotate import annotate
from armor.spotlight._errors import SentinelForgeryError
from armor.spotlight._span import Span

__all__ = [
    "SentinelForgeryError",
    "Span",
    "annotate",
]
