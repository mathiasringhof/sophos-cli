## sophos-cli

Command-line tooling for Sophos Firewall automation, built on top of
[`sophosfirewall-python`](https://pypi.org/project/sophosfirewall-python/).
The CLI now exposes explicit, discoverable command groups that are easier for
humans and LLMs to use than raw SDK calls alone.

### Highlights

- Typer-based CLI (`sophos-cli`) with an explicit command tree
- Strict static typing (Pyright `strict`)
- Domain separation: models, services, command handlers
- JSON-first behavior for non-interactive use
- JSON/CSV bulk DNS workflows
- Wave 1 network object support (`network ip-host`, `ip-network`, `ip-range`, and more)

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

Create a DNS host entry:

```bash
uv run sophos-cli dns create web-1.example.com --ip-address 192.0.2.10
```

Update a DNS host entry:

```bash
uv run sophos-cli dns update web-1.example.com --ip-address 192.0.2.20
```

Bulk add/update from JSON or CSV:

```bash
uv run sophos-cli dns create-many --file entries.json
uv run sophos-cli dns update-many --file updates.csv
```

Create and inspect network objects:

```bash
uv run sophos-cli network ip-host create branch-office --ip-address 192.0.2.44
uv run sophos-cli network ip-host get branch-office
uv run sophos-cli network ip-network create corp-net --ip-network 192.0.2.0 --mask 255.255.255.0
```

Use the raw fallback only when a resource is not yet explicitly modeled:

```bash
uv run sophos-cli raw get-tag DNSHostEntry
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
  cli.py                # root command app
  commands/dns.py       # DNS command group
  commands/network.py   # network object command groups
  commands/raw.py       # hidden raw XML fallback
  models/dns.py         # pydantic request/validation models
  models/network.py     # pydantic models for Wave 1 network objects
  services/dns_service.py
  services/network_service.py
  io/bulk_input.py      # JSON/CSV parsing for bulk flows
```

## Additional Docs

- Agent docs entrypoint: `docs/coding-agent/README.md`
- DNS resource reference: `docs/coding-agent/domains/dns/dns_host_entry.md`
- Command/resource support matrix: `docs/coding-agent/support_matrix.md`
- Sophos API Docs: `https://docs.sophos.com/nsg/sophos-firewall/22.0/api/index.html`
