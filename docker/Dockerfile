# Multi-stage Docker image for armor daemon
# Stage 1: Builder — compiles dependencies
FROM python:3.12-slim as builder

WORKDIR /build

# Install build dependencies (needed to build llama-cpp-python from source)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    g++ \
    cmake \
    && rm -rf /var/lib/apt/lists/*

# Copy the source code
COPY . .

# Install the armor package and its dependencies (including llama-cpp-python)
RUN pip install --no-cache-dir --user .

# Download the embedding model for topic-coherence detection
RUN python3 -c "from huggingface_hub import hf_hub_download; import os; os.makedirs('/build/models', exist_ok=True); \
    model_path = hf_hub_download(repo_id='sentence-transformers/all-MiniLM-L6-v2', filename='model.onnx', cache_dir='/build/models', repo_type='model'); \
    import shutil; shutil.copy(model_path, '/build/models/all-MiniLM-L6-v2.onnx')"

# Stage 2: Runtime — minimal image with only the installed Python packages and model
FROM python:3.12-slim

WORKDIR /app

# Create directories for models
RUN mkdir -p /models /opt/armor/models

# Copy only the Python user install from builder (not source code or build tools)
COPY --from=builder /root/.local/ /root/.local/

# Set PATH to use local pip installs
ENV PATH=/root/.local/bin:$PATH

# Copy model file from docker/model.gguf (should be present at build time)
# The model file is ~462 MB for Qwen3-0.6B-Q4_K_M.gguf
COPY docker/model.gguf /models/active.gguf

# Copy embedding model from builder (all-MiniLM-L6-v2 ONNX, ~23 MB)
COPY --from=builder /build/models/all-MiniLM-L6-v2.onnx /opt/armor/models/all-MiniLM-L6-v2.onnx

# Create armor group and user for principle of least privilege
RUN groupadd -r armor && useradd -r -g armor -u 999 armor

# Make socket and state directories writable by armor user
RUN mkdir -p /var/run/armor && chown -R armor:armor /var/run/armor
RUN mkdir -p /var/lib/armor && chown -R armor:armor /var/lib/armor

USER armor

# Health check: verify daemon can start (this will fail initially until daemon starts listening)
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD test -S /var/run/armor.sock || exit 1

# Entry point: run the daemon with the baked model
ENTRYPOINT ["armor", "daemon", "--socket", "/var/run/armor.sock", "--db", "/var/lib/armor/armor.db", "--model", "/models/active.gguf"]
