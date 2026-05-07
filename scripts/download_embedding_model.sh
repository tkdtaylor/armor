#!/bin/bash
# Download the sentence-transformer ONNX model for topic-coherence detection.
#
# This script fetches the pre-exported ONNX weights from Hugging Face and
# caches them locally. The Dockerfile copies this into the runtime image.
#
# Usage: ./scripts/download_embedding_model.sh [output-dir]
# Default output-dir: ./models

set -euo pipefail

MODEL_NAME="all-MiniLM-L6-v2"
HF_MODEL_ID="sentence-transformers/${MODEL_NAME}"
ONNX_FILENAME="${MODEL_NAME}.onnx"

# Output directory (default: ./models relative to script)
OUTPUT_DIR="${1:-.}/models"
mkdir -p "$OUTPUT_DIR"

echo "Downloading ONNX model: $HF_MODEL_ID"
echo "Output directory: $OUTPUT_DIR"

# Download the ONNX model from Hugging Face
# We use huggingface_hub if available, otherwise use curl
if command -v huggingface-cli &> /dev/null; then
    echo "Using huggingface-cli to download model..."
    huggingface-cli download "$HF_MODEL_ID" \
        --repo-type model \
        --revision main \
        --cache-dir "$OUTPUT_DIR" \
        "model.onnx"
elif command -v python3 &> /dev/null; then
    echo "Using Python huggingface_hub library..."
    python3 << 'PYTHON_SCRIPT'
import sys
import os
from pathlib import Path

try:
    from huggingface_hub import hf_hub_download
except ImportError:
    print("ERROR: huggingface_hub not installed. Install with: pip install huggingface-hub")
    sys.exit(1)

hf_model_id = "sentence-transformers/all-MiniLM-L6-v2"
output_dir = sys.argv[1] if len(sys.argv) > 1 else "./models"
os.makedirs(output_dir, exist_ok=True)

print(f"Downloading {hf_model_id} ONNX model...")
try:
    model_path = hf_hub_download(
        repo_id=hf_model_id,
        filename="model.onnx",
        cache_dir=output_dir,
        repo_type="model",
    )
    # Copy to expected location
    import shutil
    output_file = os.path.join(output_dir, "all-MiniLM-L6-v2.onnx")
    if model_path != output_file:
        shutil.copy(model_path, output_file)
    print(f"Downloaded to: {output_file}")
    print(f"Size: {os.path.getsize(output_file) / 1024 / 1024:.1f} MB")
except Exception as e:
    print(f"ERROR: Failed to download model: {e}", file=sys.stderr)
    sys.exit(1)
PYTHON_SCRIPT
else
    echo "ERROR: Neither huggingface-cli nor python3 found. Cannot download model."
    exit 1
fi

# Verify the downloaded file
if [ -f "$OUTPUT_DIR/$ONNX_FILENAME" ]; then
    SIZE_MB=$(du -m "$OUTPUT_DIR/$ONNX_FILENAME" | cut -f1)
    echo "SUCCESS: Downloaded $ONNX_FILENAME ($SIZE_MB MB)"
    exit 0
else
    echo "ERROR: Model file not found at $OUTPUT_DIR/$ONNX_FILENAME"
    exit 1
fi
