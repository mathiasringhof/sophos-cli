default:
  @just --list

# Run Ruff lint + Pyright type check
analyze:
  uv run ruff check src/sophos_cli tests
  uv run ruff format --check src/sophos_cli tests
  uv run pyright

# Auto-format code and fix linting errors
format:
  uv run ruff check --fix src/sophos_cli tests
  uv run ruff format src/sophos_cli tests

# Run unit tests
test *args:
	uv run pytest tests {{args}}

# Run tests with coverage
test-cov:
  uv run pytest tests --cov=src/sophos_cli --cov-report=term-missing
