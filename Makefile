.PHONY: lint format typecheck test check eval sync demo fitness release-check help

sync:
	uv sync

lint:
	uv run ruff check src tests
	uv run ruff format --check src tests

format:
	uv run ruff format src tests
	uv run ruff check --fix src tests

typecheck:
	uv run mypy src

test:
	uv run pytest

eval:
	uv run pytest tests/eval/

check: lint typecheck test eval
	@echo "All checks passed."

fitness:
	@bash scripts/fitness.sh

demo:
	@bash scripts/demo.sh

# release-check runs the full pre-tag verification sequence in stages, fastest
# first. The Docker stage is gated on DOCKER=1 so the default invocation
# works on machines without Docker installed.
release-check:
	@echo "===> [1/4] make check (lint + typecheck + unit + eval)"
	@$(MAKE) check
	@echo "===> [2/4] make fitness (architecture invariants)"
	@$(MAKE) fitness
	@echo "===> [3/4] make demo (end-to-end on a real daemon)"
	@$(MAKE) demo
	@echo "===> [4/4] examples/*.py --offline-smoke"
	@uv run python examples/anthropic_sdk.py --offline-smoke
	@uv run python examples/openai_sdk.py --offline-smoke
	@uv run python examples/langchain.py --offline-smoke
	@uv run python examples/custom_agent.py --offline-smoke
	@bash examples/claude_code/demo.sh --offline-smoke
ifdef DOCKER
	@echo "===> [bonus] docker compose make demo (DOCKER=1)"
	@if ! docker image inspect armor-dev >/dev/null 2>&1; then \
		echo "Docker stage requested but armor-dev image not found; run 'docker compose -f docker/docker-compose.yml build dev' first." >&2; \
		exit 1; \
	fi
	@docker compose -f docker/docker-compose.yml run --rm dev make demo
endif
	@echo ""
	@echo "release-check: PASSED"

help:
	@echo "Available targets:"
	@echo "  sync           - Install/sync dependencies"
	@echo "  lint           - Run linter checks"
	@echo "  format         - Auto-format code"
	@echo "  typecheck      - Run type checker"
	@echo "  test           - Run tests"
	@echo "  eval           - Run eval corpus tests"
	@echo "  check          - Run lint + typecheck + test + eval"
	@echo "  fitness        - Run fitness checks (architecture invariants)"
	@echo "  demo           - Run end-to-end demo"
	@echo "  release-check  - Pre-tag verification: check + fitness + demo + offline-smoke examples (set DOCKER=1 to add the Docker stage)"
