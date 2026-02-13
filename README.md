## sophos-cli

Command-line tooling for Sophos Firewall automation, built on top of
[`sophosfirewall-python`](https://pypi.org/project/sophosfirewall-python/).

### Highlights

- Typer-based CLI (`sophos-cli`)
- Strict static typing (Pyright `strict`)
- Domain separation: models, services, command handlers
- JSON/CSV bulk DNS workflows

## Requirements

- Python `>=3.12`
- [`uv`](https://docs.astral.sh/uv/) for dependency management

## Install And Run

```bash
uv sync
uv run sophos-cli --help
uv run python -m sophos_cli --help
```

## Authentication And Configuration

Set credentials through environment variables:

```bash
export SOPHOS_CLI_HOST="firewall.example.com"
export SOPHOS_CLI_USERNAME="api-user"
export SOPHOS_CLI_PASSWORD="super-secret"
```

Optional settings:

- `SOPHOS_CLI_PORT` (default: `4444`)
- `SOPHOS_CLI_VERIFY_SSL` (default: `true`)

You can also provide an env file at runtime:

```bash
uv run sophos-cli --env-file .env test-connection
```

## Command Examples

Test connectivity:

```bash
uv run sophos-cli test-connection
```

List DNS host entries:

```bash
uv run sophos-cli dns list
uv run sophos-cli dns list --output json
```

Get one DNS host entry:

```bash
uv run sophos-cli dns get web-1.example.com
```

Add a DNS host entry:

```bash
uv run sophos-cli dns add web-1.example.com --ip-address 192.0.2.10
```

Update a DNS host entry:

```bash
uv run sophos-cli dns update web-1.example.com --ip-address 192.0.2.20
```

Bulk add/update from JSON or CSV:

```bash
uv run sophos-cli dns add-many --file entries.json
uv run sophos-cli dns update-many --file updates.csv
```

## Development Workflow

Preferred local commands (via `just`):

```bash
just analyze      # lint + format-check + type-check (src + tests)
just format       # auto-fix lint and format (src + tests)
just test         # run tests
just test-cov     # run tests with coverage report
```

Equivalent direct commands:

```bash
uv run ruff check src/sophos_cli tests
uv run ruff format --check src/sophos_cli tests
uv run pyright
uv run pytest
```

## Project Layout

```text
src/sophos_cli/
  cli.py                # root command app + generic commands
  commands/dns.py       # DNS command group
  models/dns.py         # pydantic request/validation models
  services/dns_service.py
  io/bulk_input.py      # JSON/CSV parsing for bulk flows
```

## Additional Docs

- Agent docs entrypoint: `docs/coding-agent/README.md`
- DNS resource reference: `docs/coding-agent/domains/dns/dns_host_entry.md`
