"""Typer-based command line interface for Sophos Firewall automation."""

from pathlib import Path

import typer
from sophosfirewall_python.api_client import SophosFirewallAuthFailure

from sophos_cli import __version__
from sophos_cli.command_support import (
    API_EXCEPTIONS,
    build_client,
    console,
    handle_api_exception,
    render_payload,
)
from sophos_cli.commands.admin import admin_app
from sophos_cli.commands.dns import dns_app
from sophos_cli.commands.firewall import firewall_app
from sophos_cli.commands.network import network_app
from sophos_cli.commands.raw import raw_app
from sophos_cli.commands.service import service_app
from sophos_cli.commands.system import system_app
from sophos_cli.commands.user import user_app
from sophos_cli.commands.webfilter import webfilter_app
from sophos_cli.commands.zone import zone_app
from sophos_cli.config import Settings
from sophos_cli.connection import (
    HostOption,
    InsecureOption,
    PasswordOption,
    PortOption,
    UsernameOption,
)

app = typer.Typer(
    no_args_is_help=True,
    help="LLM-first command line tooling for Sophos Firewall automation.",
)
app.add_typer(dns_app, name="dns")
app.add_typer(network_app, name="network")
app.add_typer(service_app, name="service")
app.add_typer(firewall_app, name="firewall")
app.add_typer(zone_app, name="zone")
app.add_typer(admin_app, name="admin")
app.add_typer(user_app, name="user")
app.add_typer(webfilter_app, name="webfilter")
app.add_typer(system_app, name="system")
app.add_typer(raw_app, name="raw", hidden=True)


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

    result: object = {}
    try:
        client = build_client(ctx, host, username, password, port, insecure)
        result = client.login(output_format="dict")
    except SophosFirewallAuthFailure as exc:
        console.print(f"Authentication failed: {exc}", style="bold red")
        raise typer.Exit(code=1) from exc
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)

    render_payload(result)
