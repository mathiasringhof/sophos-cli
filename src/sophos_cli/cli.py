"""Typer-based command line interface for Sophos Firewall automation."""

from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.json import JSON
from sophosfirewall_python.api_client import SophosFirewallAPIError, SophosFirewallAuthFailure

from sophos_cli import __version__
from sophos_cli.config import Settings
from sophos_cli.sdk import create_client

app = typer.Typer(
    no_args_is_help=True,
    help="CLI scaffold for Sophos Firewall automation via sophosfirewall-python.",
)
console = Console()


def _render(payload: Any) -> None:
    """Render API payloads in a readable JSON format."""

    console.print(JSON.from_data(payload))


def _resolve(value: str | None, default: str | None, option_name: str) -> str:
    if value:
        return value
    if default:
        return default
    raise typer.BadParameter(
        f"Provide --{option_name} or set SOPHOS_CLI_{option_name.upper().replace('-', '_')}."
    )


def _connection_params(
    settings: Settings,
    host: str | None,
    username: str | None,
    password: str | None,
    port: int | None,
    insecure: bool,
) -> dict[str, Any]:
    return {
        "host": _resolve(host, settings.host, "host"),
        "username": _resolve(username, settings.username, "username"),
        "password": _resolve(password, settings.password, "password"),
        "port": port if port is not None else settings.port,
        "verify_ssl": False if insecure else settings.verify_ssl,
    }


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
    host: str | None = typer.Option(None, help="Firewall hostname or IP."),
    username: str | None = typer.Option(None, help="Firewall API username."),
    password: str | None = typer.Option(None, help="Firewall API password."),
    port: int | None = typer.Option(None, min=1, max=65535, help="Firewall API port."),
    insecure: bool = typer.Option(False, help="Disable TLS certificate verification."),
) -> None:
    """Validate API authentication with a login call."""

    settings: Settings = ctx.obj["settings"]
    params = _connection_params(settings, host, username, password, port, insecure)

    try:
        client = create_client(**params)
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
    host: str | None = typer.Option(None, help="Firewall hostname or IP."),
    username: str | None = typer.Option(None, help="Firewall API username."),
    password: str | None = typer.Option(None, help="Firewall API password."),
    port: int | None = typer.Option(None, min=1, max=65535, help="Firewall API port."),
    insecure: bool = typer.Option(False, help="Disable TLS certificate verification."),
    key: str | None = typer.Option(None, help="Optional filter key."),
    value: str | None = typer.Option(None, help="Optional filter value."),
    operator: str = typer.Option("like", help="Filter operator: =, !=, like."),
    timeout: int = typer.Option(30, min=1, help="Request timeout in seconds."),
) -> None:
    """Run a generic get request against the Sophos XML API."""

    settings: Settings = ctx.obj["settings"]
    params = _connection_params(settings, host, username, password, port, insecure)

    try:
        client = create_client(**params)
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
