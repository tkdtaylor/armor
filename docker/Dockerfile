# multi-stage Docker image for armor daemon
# Stage 1: Builder — compiles dependencies
FROM python:3.14-slim AS builder

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

# Install uv, then install dependencies using the frozen lock file so the
# Docker build always gets the exact same versions as the dev environment.
# pip install is used for the final --user install to keep the same /root/.local
# layout that the runtime stage copies from.
RUN pip install --no-cache-dir uv
RUN uv export --frozen --no-dev --no-emit-project -o /tmp/frozen-reqs.txt
RUN pip install --no-cache-dir --user -r /tmp/frozen-reqs.txt
RUN pip install --no-cache-dir --user --no-deps .

# Download the embedding model for topic-coherence detection
RUN python3 -c "from huggingface_hub import hf_hub_download; import os; os.makedirs('/build/models', exist_ok=True); \
    model_path = hf_hub_download(repo_id='sentence-transformers/all-MiniLM-L6-v2', filename='onnx/model.onnx', cache_dir='/build/models', repo_type='model'); \
    import shutil; shutil.copy(model_path, '/build/models/all-MiniLM-L6-v2.onnx')"

# Download the validator + honeypot LLM (Qwen3-0.6B-Q4_K_M, ~462 MB) per ADR-018
RUN python3 -c "from huggingface_hub import hf_hub_download; import os, shutil; \
    os.makedirs('/build/models', exist_ok=True); \
    gguf_path = hf_hub_download(repo_id='lmstudio-community/Qwen3-0.6B-GGUF', filename='Qwen3-0.6B-Q4_K_M.gguf', cache_dir='/build/models', repo_type='model'); \
    shutil.copy(gguf_path, '/build/models/active.gguf')"

# Stage 2: Runtime — minimal image with only the installed Python packages and model
FROM python:3.14-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    libgomp1 \
    && rm -rf /var/lib/apt/lists/*

# Create directories for models
RUN mkdir -p /models /opt/armor/models

# Copy only the Python user install from builder (not source code or build tools)
# into a location readable by the unprivileged runtime user.
COPY --from=builder /root/.local/ /usr/local/

# Copy validator+honeypot model from builder (Qwen3-0.6B-Q4_K_M.gguf, ~462 MB) per ADR-018
COPY --from=builder /build/models/active.gguf /models/active.gguf

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
    CMD test -S /var/run/armor/armor.sock || exit 1

# Entry point: run the daemon with the baked model
ENTRYPOINT ["armor", "daemon", "--socket", "/var/run/armor/armor.sock", "--db", "/var/lib/armor/armor.db", "--model", "/models/active.gguf"]
