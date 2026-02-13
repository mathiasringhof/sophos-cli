# Repository Guidelines

## Project Structure & Module Organization
This project uses a `src/` layout for a Python CLI package.

- `src/sophos_cli/cli.py`: root Typer app (`version`, `test-connection`, `get-tag`).
- `src/sophos_cli/commands/`: domain command groups (for example `dns.py`).
- `src/sophos_cli/services/`: reusable API/domain logic (for example `dns_service.py`).
- `src/sophos_cli/models/`: Pydantic request/validation models.
- `src/sophos_cli/io/`: input parsing helpers (for example bulk JSON/CSV).
- `src/sophos_cli/config.py`: environment-based settings (`SOPHOS_CLI_*`).
- `src/sophos_cli/sdk.py`: thin wrapper around `sophosfirewall-python` client creation.
- `src/sophos_cli/__main__.py`: module entrypoint for `python -m sophos_cli`.
- `tests/`: pytest suite (`test_*.py`, shared setup in `conftest.py`).
- `pyproject.toml`: dependencies, CLI script, lint/test configuration.

Keep command logic in `cli.py` lightweight; move reusable API logic into dedicated modules under `src/sophos_cli/`.

## Build, Test, and Development Commands
Use `uv` for environment and dependency management, and `just` for common workflows.

- `uv sync`: install project and dev dependencies from `pyproject.toml`/`uv.lock`.
- `uv run sophos-cli --help`: run the CLI entrypoint.
- `uv run python -m sophos_cli --help`: run as a Python module.
- `uv run pytest`: execute tests.
- `uv run ruff check .`: run lint checks.
- `just analyze`: run lint, format-check, and strict type checks on `src/sophos_cli`.
- `just format`: auto-fix lint issues and format `src/sophos_cli`.
- `just test [pytest args]`: run unit tests (pass-through args supported).
- `just test-cov`: run tests with coverage report.

If you add tooling, document the command here and in CI.

## Coding Style & Naming Conventions
- Follow PEP 8 with 4-space indentation.
- Use `snake_case` for functions/variables, `PascalCase` for classes.
- Prefer type hints on public functions.
- Keep functions focused and avoid embedding API logic directly in command handlers.
- Run `uv run ruff check .` before opening a PR.

## Testing Guidelines
Tests use `pytest`.

- Place tests under `tests/`.
- Use `test_<module>.py` filenames and `test_<behavior>()` function names.
- Cover command success paths and CLI error handling for missing/invalid input.
- For SDK-dependent behavior, prefer mocks over live firewall calls.

## Commit & Pull Request Guidelines
Adopt Conventional Commit style for consistency.

- Examples: `feat(cli): add raw get-tag command`, `fix(config): handle missing host`.
- Keep commits small and scoped to one concern.
- PRs should include: summary, test/lint evidence (`uv run pytest`, `uv run ruff check .`), and linked issue(s) when relevant.

## Security & Configuration Tips
Do not hardcode credentials. Use environment variables such as `SOPHOS_CLI_HOST`, `SOPHOS_CLI_USERNAME`, and `SOPHOS_CLI_PASSWORD`, or pass `--env-file` for local development.

## Coding Agent API Documentation
Use `docs/coding-agent/README.md` as the entrypoint for agent-focused API documentation.

- DNS host entry reference: `docs/coding-agent/domains/dns/dns_host_entry.md`
- Reusable template for new domains/resources: `docs/coding-agent/templates/domain_resource_template.md`
