"""Typer-based command line interface for Sophos Firewall automation."""

from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.json import JSON
from sophosfirewall_python.api_client import SophosFirewallAPIError, SophosFirewallAuthFailure

from sophos_cli import __version__
from sophos_cli.commands.dns import dns_app
from sophos_cli.config import Settings
from sophos_cli.connection import (
    HostOption,
    InsecureOption,
    PasswordOption,
    PortOption,
    UsernameOption,
    connection_params,
)
from sophos_cli.sdk import create_client

app = typer.Typer(
    no_args_is_help=True,
    help="CLI scaffold for Sophos Firewall automation via sophosfirewall-python.",
)
app.add_typer(dns_app, name="dns")
console = Console()


def _render(payload: Any) -> None:
    """Render API payloads in a readable JSON format."""

    console.print(JSON.from_data(payload))


@app.callback()
def common_options(
    ctx: typer.Context,
    env_file: Path | None = typer.Option(
        None,
        "--env-file",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
        help="Optional .env file with SOPHOS_CLI_* variables.",
    ),
) -> None:
    """Load shared configuration for all commands."""

    ctx.obj = {"settings": Settings.from_env_file(env_file)}


@app.command("version")
def show_version() -> None:
    """Show the installed sophos-cli version."""

    console.print(f"sophos-cli {__version__}")


@app.command("test-connection")
def test_connection(
    ctx: typer.Context,
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """Validate API authentication with a login call."""

    settings: Settings = ctx.obj["settings"]
    params = connection_params(settings, host, username, password, port, insecure)

    try:
        client = create_client(params)
        result = client.login(output_format="dict")
    except SophosFirewallAuthFailure as exc:
        console.print(f"Authentication failed: {exc}", style="bold red")
        raise typer.Exit(code=1) from exc
    except SophosFirewallAPIError as exc:
        console.print(f"API request failed: {exc}", style="bold red")
        raise typer.Exit(code=1) from exc

    _render(result)


@app.command("get-tag")
def get_tag(
    ctx: typer.Context,
    xml_tag: str = typer.Argument(..., help="XML tag to query from the firewall API."),
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
    key: str | None = typer.Option(None, help="Optional filter key."),
    value: str | None = typer.Option(None, help="Optional filter value."),
    operator: str = typer.Option("like", help="Filter operator: =, !=, like."),
    timeout: int = typer.Option(30, min=1, help="Request timeout in seconds."),
) -> None:
    """Run a generic get request against the Sophos XML API."""

    settings: Settings = ctx.obj["settings"]
    params = connection_params(settings, host, username, password, port, insecure)

    try:
        client = create_client(params)
        if key and value:
            result = client.get_tag_with_filter(
                xml_tag=xml_tag,
                key=key,
                value=value,
                operator=operator,
                timeout=timeout,
                output_format="dict",
            )
        else:
            result = client.get_tag(xml_tag=xml_tag, timeout=timeout, output_format="dict")
    except SophosFirewallAPIError as exc:
        console.print(f"API request failed: {exc}", style="bold red")
        raise typer.Exit(code=1) from exc

    _render(result)
