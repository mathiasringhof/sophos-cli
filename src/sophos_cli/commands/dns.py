"""DNS command group implementation."""

from __future__ import annotations

from typing import Annotated, Any, Literal

import typer
from rich.console import Console
from rich.json import JSON
from rich.table import Table
from sophosfirewall_python.api_client import (
    SophosFirewallAPIError,
    SophosFirewallAuthFailure,
    SophosFirewallInvalidArgument,
)

from sophos_cli.config import Settings
from sophos_cli.connection import (
    HostOption,
    InsecureOption,
    PasswordOption,
    PortOption,
    UsernameOption,
    connection_params,
)
from sophos_cli.io.bulk_input import BulkInputFormat, load_dns_add_entries, load_dns_update_entries
from sophos_cli.models.dns import DnsHostAddress, DnsHostEntryCreate, DnsHostEntryUpdate
from sophos_cli.sdk import create_client
from sophos_cli.services.dns_service import DnsBulkMutationResult, DnsService

dns_app = typer.Typer(no_args_is_help=True, help="Manage DNSHostEntry records.")
console = Console()
API_EXCEPTIONS = (
    SophosFirewallAPIError,
    SophosFirewallAuthFailure,
    SophosFirewallInvalidArgument,
)

OutputFormat = Literal["table", "json"]


def _build_service(
    ctx: typer.Context,
    host: str | None,
    username: str | None,
    password: str | None,
    port: int | None,
    insecure: bool,
) -> DnsService:
    settings: Settings = ctx.obj["settings"]
    params = connection_params(settings, host, username, password, port, insecure)
    client = create_client(params)
    return DnsService(client)


def _render_entries(entries: list[DnsHostEntryCreate], output: OutputFormat) -> None:
    if output == "json":
        console.print(JSON.from_data([entry.model_dump() for entry in entries]))
        return

    table = Table(title="DNS Host Entries")
    table.add_column("HostName")
    table.add_column("Addresses")
    table.add_column("Reverse DNS")

    for entry in entries:
        address_values = ", ".join(
            f"{address.ip_family}:{address.ip_address}" for address in entry.addresses
        )
        table.add_row(
            entry.host_name,
            address_values,
            "Enable" if entry.add_reverse_dns_lookup else "Disable",
        )

    console.print(table)


def _render_bulk_summary(action: str, result: DnsBulkMutationResult) -> None:
    console.print(
        f"{action} summary: total={result.total} created={result.created} "
        f"updated={result.updated} failed={result.failed}"
    )
    for error in result.errors:
        console.print(f"- {error}", style="red")


def _handle_api_exception(exc: Exception) -> None:
    console.print(f"API request failed: {exc}", style="bold red")
    raise typer.Exit(code=1) from exc


@dns_app.command("list")
def dns_list(
    ctx: typer.Context,
    output: Annotated[
        OutputFormat,
        typer.Option("--output", help="Response format: table or json."),
    ] = "table",
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """List current DNS host entries."""

    entries: list[DnsHostEntryCreate] = []
    try:
        service = _build_service(ctx, host, username, password, port, insecure)
        entries = service.list_entries()
    except API_EXCEPTIONS as exc:
        _handle_api_exception(exc)

    _render_entries(entries, output)


@dns_app.command("get")
def dns_get(
    ctx: typer.Context,
    host_name: Annotated[str, typer.Argument(help="DNS host entry name (hostname or FQDN).")],
    output: Annotated[
        OutputFormat,
        typer.Option("--output", help="Response format: table or json."),
    ] = "table",
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """Get a specific DNS host entry."""

    entry: DnsHostEntryCreate | None = None
    try:
        service = _build_service(ctx, host, username, password, port, insecure)
        entry = service.get_entry(host_name)
    except API_EXCEPTIONS as exc:
        _handle_api_exception(exc)

    if entry is None:
        console.print(f"DNS entry '{host_name}' not found", style="bold red")
        raise typer.Exit(code=1)

    _render_entries([entry], output)


@dns_app.command("add")
def dns_add(
    ctx: typer.Context,
    host_name: Annotated[str, typer.Argument(help="DNS host entry name (hostname or FQDN).")],
    ip_address: Annotated[
        str,
        typer.Option("--ip-address", help="Mapped IP address or interface."),
    ],
    ip_family: Annotated[
        Literal["IPv4", "IPv6"],
        typer.Option("--ip-family", help="IP family for the mapped address."),
    ] = "IPv4",
    entry_type: Annotated[
        Literal["Manual", "InterfaceIP"],
        typer.Option("--entry-type", help="Address source type."),
    ] = "Manual",
    ttl: Annotated[
        int,
        typer.Option("--ttl", min=1, max=604800, help="Address TTL in seconds."),
    ] = 3600,
    weight: Annotated[int, typer.Option("--weight", min=0, max=255, help="Address weight.")] = 0,
    publish_on_wan: Annotated[
        Literal["Enable", "Disable"],
        typer.Option("--publish-on-wan", help="Publish record on WAN."),
    ] = "Disable",
    add_reverse_dns_lookup: Annotated[
        bool,
        typer.Option(
            "--add-reverse-dns-lookup/--no-add-reverse-dns-lookup",
            help="Enable or disable reverse DNS lookup.",
        ),
    ] = False,
    force: Annotated[
        bool,
        typer.Option(
            "--force",
            help="Update existing entry instead of failing if it already exists.",
        ),
    ] = False,
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """Add a DNS host entry."""

    action: str = ""
    response: dict[str, Any] = {}
    try:
        service = _build_service(ctx, host, username, password, port, insecure)
        entry = DnsHostEntryCreate(
            host_name=host_name,
            addresses=[
                DnsHostAddress(
                    entry_type=entry_type,
                    ip_family=ip_family,
                    ip_address=ip_address,
                    ttl=ttl,
                    weight=weight,
                    publish_on_wan=publish_on_wan,
                )
            ],
            add_reverse_dns_lookup=add_reverse_dns_lookup,
        )
        action, response = service.add_entry(entry, force=force)
    except ValueError as exc:
        console.print(str(exc), style="bold red")
        raise typer.Exit(code=1) from exc
    except API_EXCEPTIONS as exc:
        _handle_api_exception(exc)

    console.print(f"DNS entry '{host_name}' {action}")
    console.print(JSON.from_data(response))


@dns_app.command("update")
def dns_update(
    ctx: typer.Context,
    host_name: Annotated[str, typer.Argument(help="DNS host entry name (hostname or FQDN).")],
    ip_address: Annotated[
        str | None,
        typer.Option("--ip-address", help="New mapped IP address or interface."),
    ] = None,
    ip_family: Annotated[
        Literal["IPv4", "IPv6"] | None,
        typer.Option("--ip-family", help="IP family for --ip-address."),
    ] = None,
    entry_type: Annotated[
        Literal["Manual", "InterfaceIP"] | None,
        typer.Option("--entry-type", help="Address source type for --ip-address."),
    ] = None,
    ttl: Annotated[
        int | None,
        typer.Option("--ttl", min=1, max=604800, help="Address TTL for --ip-address."),
    ] = None,
    weight: Annotated[
        int | None,
        typer.Option("--weight", min=0, max=255, help="Address weight for --ip-address."),
    ] = None,
    publish_on_wan: Annotated[
        Literal["Enable", "Disable"] | None,
        typer.Option("--publish-on-wan", help="Publish mode for --ip-address."),
    ] = None,
    reverse_dns_lookup: Annotated[
        Literal["Enable", "Disable"] | None,
        typer.Option("--reverse-dns-lookup", help="Set reverse DNS lookup mode."),
    ] = None,
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """Update a DNS host entry."""

    if ip_address is None and any(
        option is not None for option in [ip_family, entry_type, ttl, weight, publish_on_wan]
    ):
        console.print(
            "Address options (--ip-family/--entry-type/--ttl/--weight/--publish-on-wan) "
            "require --ip-address.",
            style="bold red",
        )
        raise typer.Exit(code=1)

    addresses: list[DnsHostAddress] | None = None
    if ip_address is not None:
        addresses = [
            DnsHostAddress(
                entry_type=entry_type or "Manual",
                ip_family=ip_family or "IPv4",
                ip_address=ip_address,
                ttl=ttl if ttl is not None else 3600,
                weight=weight if weight is not None else 0,
                publish_on_wan=publish_on_wan or "Disable",
            )
        ]

    reverse_lookup_bool = None
    if reverse_dns_lookup is not None:
        reverse_lookup_bool = reverse_dns_lookup == "Enable"

    response: dict[str, Any] = {}
    try:
        update = DnsHostEntryUpdate(
            host_name=host_name,
            addresses=addresses,
            add_reverse_dns_lookup=reverse_lookup_bool,
        )
        service = _build_service(ctx, host, username, password, port, insecure)
        response = service.update_entry(update)
    except ValueError as exc:
        console.print(str(exc), style="bold red")
        raise typer.Exit(code=1) from exc
    except API_EXCEPTIONS as exc:
        _handle_api_exception(exc)

    console.print(f"DNS entry '{host_name}' updated")
    console.print(JSON.from_data(response))


@dns_app.command("add-many")
def dns_add_many(
    ctx: typer.Context,
    file_path: Annotated[
        str,
        typer.Option("--file", "-f", help="Path to JSON/CSV file, or '-' for stdin."),
    ],
    input_format: Annotated[
        BulkInputFormat,
        typer.Option("--format", help="Input format: auto, json, csv."),
    ] = "auto",
    force: Annotated[
        bool,
        typer.Option("--force", help="Update existing entries instead of failing on duplicates."),
    ] = False,
    continue_on_error: Annotated[
        bool,
        typer.Option("--continue-on-error", help="Continue processing after an entry error."),
    ] = False,
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """Add multiple DNS host entries from file/stdin.

    Input examples:

    JSON list:
    [
      {
        "host_name": "web-1.example.com",
        "ip_address": "192.0.2.10"
      },
      {
        "host_name": "api-1.example.com",
        "addresses": [
          {
            "entry_type": "Manual",
            "ip_family": "IPv4",
            "ip_address": "192.0.2.20",
            "ttl": 3600,
            "weight": 0,
            "publish_on_wan": "Disable"
          }
        ],
        "add_reverse_dns_lookup": false
      }
    ]

    CSV (one address per row):
    host_name,ip_address,ip_family,entry_type,ttl,weight,publish_on_wan,add_reverse_dns_lookup
    web-1.example.com,192.0.2.10,IPv4,Manual,3600,0,Disable,false
    api-1.example.com,192.0.2.20,IPv4,Manual,3600,0,Disable,true
    """

    result: DnsBulkMutationResult = DnsBulkMutationResult(total=0)
    try:
        entries = load_dns_add_entries(file_path, input_format=input_format)
        service = _build_service(ctx, host, username, password, port, insecure)
        result = service.add_many(entries, force=force, continue_on_error=continue_on_error)
    except (ValueError, OSError) as exc:
        console.print(f"Invalid input: {exc}", style="bold red")
        raise typer.Exit(code=1) from exc
    except API_EXCEPTIONS as exc:
        _handle_api_exception(exc)

    _render_bulk_summary("add-many", result)
    if result.failed > 0:
        raise typer.Exit(code=2)


@dns_app.command("update-many")
def dns_update_many(
    ctx: typer.Context,
    file_path: Annotated[
        str,
        typer.Option("--file", "-f", help="Path to JSON/CSV file, or '-' for stdin."),
    ],
    input_format: Annotated[
        BulkInputFormat,
        typer.Option("--format", help="Input format: auto, json, csv."),
    ] = "auto",
    continue_on_error: Annotated[
        bool,
        typer.Option("--continue-on-error", help="Continue processing after an entry error."),
    ] = False,
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """Update multiple DNS host entries from file/stdin.

    Input examples:

    JSON list:
    [
      {
        "host_name": "web-1.example.com",
        "ip_address": "192.0.2.30"
      },
      {
        "host_name": "api-1.example.com",
        "add_reverse_dns_lookup": true
      }
    ]

    CSV (one address per row; leave address fields empty for reverse-lookup-only updates):
    host_name,ip_address,ip_family,entry_type,ttl,weight,publish_on_wan,add_reverse_dns_lookup
    web-1.example.com,192.0.2.30,IPv4,Manual,3600,0,Disable,
    api-1.example.com,,,,,,,true
    """

    result: DnsBulkMutationResult = DnsBulkMutationResult(total=0)
    try:
        entries = load_dns_update_entries(file_path, input_format=input_format)
        service = _build_service(ctx, host, username, password, port, insecure)
        result = service.update_many(entries, continue_on_error=continue_on_error)
    except (ValueError, OSError) as exc:
        console.print(f"Invalid input: {exc}", style="bold red")
        raise typer.Exit(code=1) from exc
    except API_EXCEPTIONS as exc:
        _handle_api_exception(exc)

    _render_bulk_summary("update-many", result)
    if result.failed > 0:
        raise typer.Exit(code=2)
