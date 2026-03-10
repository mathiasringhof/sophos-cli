"""Hidden raw command group for unsupported XML API calls."""

from __future__ import annotations

from typing import Annotated

import typer

from sophos_cli.command_support import build_client, handle_api_exception, render_payload
from sophos_cli.connection import (
    HostOption,
    InsecureOption,
    PasswordOption,
    PortOption,
    UsernameOption,
)

raw_app = typer.Typer(
    no_args_is_help=True,
    help="Unsafe raw SDK/XML escape hatch for unsupported scenarios.",
)


@raw_app.command("get-tag")
def get_tag(
    ctx: typer.Context,
    xml_tag: Annotated[str, typer.Argument(help="XML tag to query from the firewall API.")],
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

    result: object = {}
    try:
        client = build_client(ctx, host, username, password, port, insecure)
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
    except Exception as exc:
        handle_api_exception(exc)

    render_payload(result)
