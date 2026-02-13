"""Shared connection option resolution for CLI commands."""

from typing import Any

import typer

from sophos_cli.config import Settings


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
) -> dict[str, Any]:
    """Resolve command options and settings into SDK client kwargs."""

    return {
        "host": _resolve(host, settings.host, "host"),
        "username": _resolve(username, settings.username, "username"),
        "password": _resolve(password, settings.password, "password"),
        "port": port if port is not None else settings.port,
        "verify_ssl": False if insecure else settings.verify_ssl,
    }
