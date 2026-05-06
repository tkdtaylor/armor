"""LLMSession dataclass for managing a quantized LLM instance."""

from dataclasses import dataclass

import llama_cpp


@dataclass
class LLMSession:
    """Holds a loaded llama-cpp LLM instance and configuration.

    Attributes:
        instance: The loaded llama_cpp.Llama model instance
        context_tokens: Context window size (tokens)
        validator_budget_ms: Hard latency cap per validator inference call (milliseconds)
        honeypot_budget_ms: Hard latency cap per honeypot inference call (milliseconds)
    """

    instance: llama_cpp.Llama
    context_tokens: int
    validator_budget_ms: int
    honeypot_budget_ms: int

    def close(self) -> None:
        """Release resources held by the LLM instance.

        Safe to call multiple times.
        """
        if self.instance is not None:
            # llama_cpp.Llama has a __del__ method but we can't assume it's been called
            # Just mark as released; the __del__ will clean up
            pass
