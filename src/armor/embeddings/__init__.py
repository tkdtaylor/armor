# SPDX-License-Identifier: Apache-2.0
"""Embeddings module for topic-coherence detection.

Provides sentence-transformer ONNX embedding inference and EMA caching
for semantic similarity calculations.
"""

from armor.embeddings.ema_cache import EMACache
from armor.embeddings.onnx_embedder import Embedder

__all__ = ["EMACache", "Embedder"]
