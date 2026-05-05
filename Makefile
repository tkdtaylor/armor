.PHONY: lint format typecheck test check eval sync demo fitness help

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

help:
	@echo "Available targets:"
	@echo "  sync       - Install/sync dependencies"
	@echo "  lint       - Run linter checks"
	@echo "  format     - Auto-format code"
	@echo "  typecheck  - Run type checker"
	@echo "  test       - Run tests"
	@echo "  eval       - Run eval corpus tests"
	@echo "  check      - Run lint + typecheck + test + eval"
	@echo "  fitness    - Run fitness checks (architecture invariants)"
	@echo "  demo       - Run end-to-end demo"
