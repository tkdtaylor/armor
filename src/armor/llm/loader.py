# SPDX-License-Identifier: Apache-2.0
"""LLM loader: validates and instantiates the quantized model."""

import logging
import sys
from pathlib import Path

import llama_cpp

from armor.llm.session import LLMSession

logger = logging.getLogger(__name__)


def load_llm(
    model_path: str,
    context_tokens: int = 2048,
    validator_budget_ms: int = 500,
    honeypot_budget_ms: int = 16000,
) -> LLMSession:
    """Load a quantized LLM model and validate it.

    Args:
        model_path: Path to the GGUF model file
        context_tokens: Context window size (default 2048)
        validator_budget_ms: Hard latency cap per validator inference call in ms (default 500)
        honeypot_budget_ms: Hard latency cap per honeypot inference call in ms (default 16000)

    Returns:
        LLMSession with the loaded model instance

    Raises:
        SystemExit: Exits with code 78 if validation fails:
            - File does not exist
            - Model instantiation fails
            - Self-test forward pass fails
    """
    model_file = Path(model_path)

    # Validate file exists
    if not model_file.exists():
        logger.error(f"Model file not found: {model_path}")
        sys.exit(78)

    if not model_file.is_file():
        logger.error(f"Model path is not a file: {model_path}")
        sys.exit(78)

    # Instantiate the Llama model
    try:
        logger.info(f"Loading model from {model_path}")
        instance = llama_cpp.Llama(
            model_path=str(model_file),
            n_threads=1,
            n_gpu_layers=0,
            verbose=False,
        )
        logger.info(
            f"Model loaded: context_tokens={context_tokens}, "
            f"validator_budget_ms={validator_budget_ms}, honeypot_budget_ms={honeypot_budget_ms}, "
            f"file={model_file.name}"
        )
    except Exception as e:
        logger.error(f"Failed to instantiate model: {e}")
        sys.exit(78)

    # Self-test forward pass
    try:
        test_input = "Say 'ok' in one word."
        response = instance.create_completion(
            test_input,
            max_tokens=10,
            temperature=0.0,
        )
        # Response is a dict with 'choices' key
        if not isinstance(response, dict) or "choices" not in response or not response.get("choices"):
            logger.error("Self-test forward pass returned empty response")
            sys.exit(78)
        logger.info("Model self-test passed")
    except Exception as e:
        logger.error(f"Model self-test failed: {e}")
        sys.exit(78)

    return LLMSession(
        instance=instance,
        context_tokens=context_tokens,
        validator_budget_ms=validator_budget_ms,
        honeypot_budget_ms=honeypot_budget_ms,
    )
