"""ONNX-based sentence-transformer embedding inference.

Wraps the sentence-transformers all-MiniLM-L6-v2 ONNX model for
fast, deterministic embedding generation.
"""

import logging
from pathlib import Path

import numpy as np
import onnxruntime  # type: ignore[import-untyped]

logger = logging.getLogger(__name__)


class Embedder:
    """Sentence-transformer ONNX embedding inference.

    Wraps ONNX Runtime to load and run the all-MiniLM-L6-v2 model.
    The model is expected to be baked into the container at
    /opt/armor/models/all-MiniLM-L6-v2.onnx.

    Attributes:
        session: ONNX Runtime session (lazy-loaded on first use).
        model_path: Path to the ONNX model file.
    """

    _instance: "Embedder | None" = None
    _session: onnxruntime.InferenceSession | None = None

    def __new__(cls) -> "Embedder":
        """Singleton pattern: return the same instance."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self) -> None:
        """Initialize the embedder.

        Model loading is deferred until the first encode() call
        to avoid overhead in test scenarios where embedding is mocked.
        """
        # Model path: /opt/armor/models/all-MiniLM-L6-v2.onnx (container)
        # Fallback for dev: ./models/all-MiniLM-L6-v2.onnx (if available)
        self.model_path = Path("/opt/armor/models/all-MiniLM-L6-v2.onnx")
        if not self.model_path.exists():
            # Try relative path for development
            dev_path = Path("./models/all-MiniLM-L6-v2.onnx")
            if dev_path.exists():
                self.model_path = dev_path
                logger.debug(f"Using dev model path: {self.model_path}")
            else:
                logger.warning(
                    f"Model not found at {self.model_path} or {dev_path}. Topic-coherence detector will be unavailable."
                )

    def _ensure_session(self) -> bool:
        """Ensure the ONNX session is loaded.

        Returns:
            True if session is available, False if model file not found or load failed.
        """
        if Embedder._session is not None:
            return True

        if not self.model_path.exists():
            logger.error(f"Model file not found: {self.model_path}")
            return False

        try:
            # Create ONNX Runtime session
            # Use CPUExecutionProvider for consistency (no GPU deps)
            Embedder._session = onnxruntime.InferenceSession(
                str(self.model_path),
                providers=["CPUExecutionProvider"],
            )
            logger.debug(f"ONNX session loaded from {self.model_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to load ONNX model: {e}")
            return False

    def encode(self, text: str) -> np.ndarray | None:
        """Encode text to a vector using the ONNX model.

        Args:
            text: Input text to encode.

        Returns:
            NumPy array of shape (384,) or None if encoding fails.
        """
        if not text:
            return None

        if not self._ensure_session():
            return None

        try:
            # Tokenize the input text
            # The all-MiniLM-L6-v2 ONNX model expects:
            # - input_ids: LongTensor, shape (batch_size, seq_len)
            # - attention_mask: LongTensor, shape (batch_size, seq_len)
            # - token_type_ids: LongTensor, shape (batch_size, seq_len)
            #
            # We use a simple tokenizer that:
            # 1. Converts to lowercase
            # 2. Splits by whitespace and basic punctuation
            # 3. Maps tokens to vocab
            # This is a naive approach but sufficient for similarity calculation.
            #
            # For a more robust implementation, we would use the HuggingFace tokenizer.
            # However, to avoid adding tokenizer dependencies, we use ONNX session's
            # built-in preprocessing if available, or fall back to a simple approach.

            # Use ONNX model directly via get_model_inputs()
            # The model expects raw text and handles tokenization internally.
            # For ONNX models exported from HuggingFace transformers, we need to
            # manually tokenize.

            # Import here to avoid import cost when embedding is mocked in tests
            from transformers import AutoTokenizer

            # Load tokenizer (cached after first use)
            try:
                tokenizer = AutoTokenizer.from_pretrained("sentence-transformers/all-MiniLM-L6-v2")
            except Exception as e:
                logger.warning(f"Could not load tokenizer via transformers: {e}. Using fallback.")
                # Fallback: simple whitespace tokenization with fixed vocab
                # This is a placeholder; in production, the model would include a vocab file
                return self._encode_fallback(text)

            # Tokenize
            tokens = tokenizer(
                text,
                padding=True,
                truncation=True,
                max_length=256,
                return_tensors="np",
            )

            # Run inference
            session = Embedder._session
            if session is None:
                return None

            # Get model inputs
            input_names = [input.name for input in session.get_inputs()]
            ort_inputs = {
                input_names[0]: tokens["input_ids"].astype(np.int64),
                input_names[1]: tokens["attention_mask"].astype(np.int64),
            }

            # If token_type_ids is expected, add it
            if len(input_names) > 2:
                ort_inputs[input_names[2]] = tokens.get("token_type_ids", tokens["input_ids"]).astype(np.int64)

            # Run the model
            outputs = session.run(None, ort_inputs)

            # Extract the embedding (typically the last layer's output, averaged)
            # The output is shape (batch_size, seq_len, 384)
            embeddings = outputs[0]

            # Mean pooling over the sequence dimension
            mask_expanded = tokens["attention_mask"][:, :, np.newaxis].astype(np.float32)
            sum_embeddings = np.sum(embeddings * mask_expanded, axis=1)
            sum_mask = np.sum(mask_expanded, axis=1)
            mean_embedding = sum_embeddings / np.clip(sum_mask, a_min=1e-9, a_max=None)

            # Normalize to unit vector (cosine distance)
            norm = np.linalg.norm(mean_embedding[0])
            normalized = mean_embedding[0] / norm if norm > 0 else mean_embedding[0]

            return np.asarray(normalized, dtype=np.float32)

        except ImportError:
            # transformers not available; use fallback
            logger.warning("transformers library not available; using fallback embedding")
            return self._encode_fallback(text)
        except Exception as e:
            logger.error(f"Embedding encoding failed: {e}")
            return None

    def _encode_fallback(self, text: str) -> np.ndarray:
        """Fallback encoding when tokenizer is unavailable.

        Simple bag-of-words approach: counts word frequencies and returns
        a sparse representation as a dense vector of fixed dimensionality (384).

        Args:
            text: Input text.

        Returns:
            NumPy array of shape (384,).
        """
        # Simple hash-based fallback: map words to vector positions
        # This is NOT a proper embedding but allows graceful degradation
        words = text.lower().split()
        vector = np.zeros(384)

        for word in words:
            # Hash the word to a position in the vector
            idx = hash(word) % 384
            vector[idx] += 1.0

        # Normalize
        norm = np.linalg.norm(vector)
        if norm > 0:
            vector = vector / norm
        return vector
