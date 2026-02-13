"""Shared connection option resolution for CLI commands."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated

import typer

from sophos_cli.config import Settings

HostOption = Annotated[str | None, typer.Option(help="Firewall hostname or IP.")]
UsernameOption = Annotated[str | None, typer.Option(help="Firewall API username.")]
PasswordOption = Annotated[str | None, typer.Option(help="Firewall API password.")]
PortOption = Annotated[int | None, typer.Option(min=1, max=65535, help="Firewall API port.")]
InsecureOption = Annotated[
    bool,
    typer.Option(help="Disable TLS certificate verification."),
]


@dataclass(frozen=True, slots=True)
class ConnectionParams:
    """Resolved connection parameters for the firewall SDK client."""

    host: str
    username: str
    password: str
    port: int
    verify_ssl: bool


def _resolve(value: str | None, default: str | None, option_name: str) -> str:
    if value:
        return value
    if default:
        return default
    raise typer.BadParameter(
        f"Provide --{option_name} or set SOPHOS_CLI_{option_name.upper().replace('-', '_')}."
    )


def connection_params(
    settings: Settings,
    host: str | None,
    username: str | None,
    password: str | None,
    port: int | None,
    insecure: bool,
) -> ConnectionParams:
    """Resolve command options and settings into SDK client kwargs."""

    return ConnectionParams(
        host=_resolve(host, settings.host, "host"),
        username=_resolve(username, settings.username, "username"),
        password=_resolve(password, settings.password, "password"),
        port=port if port is not None else settings.port,
        verify_ssl=False if insecure else settings.verify_ssl,
    )
