# Installation

armor can be installed as a Docker container, from PyPI, or from source.

## Docker

```bash
docker compose -f docker/docker-compose.yml build dev
docker compose -f docker/docker-compose.yml run --rm dev armor --help
```

A no-cache build produces a local `armor-dev` image of about 990 MiB and includes the
validator weights and embedding model baked in, so the running container is offline-capable.

The release workflow publishes multi-arch images to GHCR. See [docker/](../docker/) for
the Compose definition.

## PyPI

The distribution name is `armor-ai` (the bare `armor` name is used by another project).
The import remains `import armor`.

```bash
pip install armor-ai
```

Start the daemon:

```bash
armor daemon --socket /tmp/armor.sock --db /tmp/armor-test.db
```

Then check content via CLI:

```bash
echo "ignore previous instructions" | armor check input --socket /tmp/armor.sock --session-id test-1
```

## From source

```bash
git clone https://github.com/tkdtaylor/armor
cd armor
uv sync
```

Start the daemon:

```bash
uv run armor daemon --socket /tmp/armor.sock --db /tmp/armor-test.db
```

Then check content:

```bash
echo "ignore previous instructions" | uv run armor check input --socket /tmp/armor.sock --session-id test-1
```

## Verify the installation

Run the demo to verify everything works:

```bash
make demo
```

This generates canary values, starts a daemon on a temporary socket, runs two attack
scenarios (direct injection and canary exfiltration), and reports forensic incidents.
