# Docker

Build the local development image from the repository root:

```bash
docker compose -f docker/docker-compose.yml build dev
```

Run a one-off CLI command:

```bash
docker compose -f docker/docker-compose.yml run --rm dev armor --help
```

Start the daemon inside the container with the baked Qwen3 GGUF model:

```bash
docker compose -f docker/docker-compose.yml run --rm dev \
  armor daemon --socket /tmp/armor.sock --db /tmp/armor.db --model /models/active.gguf
```

The Dockerfile downloads both model artifacts during the builder stage:

- `lmstudio-community/Qwen3-0.6B-GGUF` / `Qwen3-0.6B-Q4_K_M.gguf`
- `sentence-transformers/all-MiniLM-L6-v2` / `onnx/model.onnx`

No Hugging Face token is required for these public models. Unauthenticated builds may print a rate-limit warning; set `HF_TOKEN` in the Docker build environment only if your network needs higher Hugging Face rate limits.

Last verified on 2026-05-09: `docker compose -f docker/docker-compose.yml build --no-cache dev` usually completes in under 3 minutes on the README benchmark host and produces `armor-dev` at about 990 MiB.
