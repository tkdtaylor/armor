.PHONY: lint format typecheck test check sync demo help

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

check: lint typecheck test
	@echo "All checks passed."

demo:
	@bash scripts/demo.sh

help:
	@echo "Available targets:"
	@echo "  sync       - Install/sync dependencies"
	@echo "  lint       - Run linter checks"
	@echo "  format     - Auto-format code"
	@echo "  typecheck  - Run type checker"
	@echo "  test       - Run tests"
	@echo "  check      - Run lint + typecheck + test"
	@echo "  demo       - Run end-to-end demo"
