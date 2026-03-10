"""Shared runtime helpers for CLI command modules."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Literal, cast

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
from sophos_cli.connection import connection_params
from sophos_cli.firewall_client import FirewallClientProtocol, FirewallObject
from sophos_cli.sdk import create_client

OutputFormat = Literal["auto", "json", "table"]

console = Console()
API_EXCEPTIONS = (
    SophosFirewallAPIError,
    SophosFirewallAuthFailure,
    SophosFirewallInvalidArgument,
)


def build_client(
    ctx: typer.Context,
    host: str | None,
    username: str | None,
    password: str | None,
    port: int | None,
    insecure: bool,
) -> FirewallClientProtocol:
    """Build a configured SDK client from CLI context and overrides."""

    settings: Settings = ctx.obj["settings"]
    params = connection_params(settings, host, username, password, port, insecure)
    return create_client(params)


def normalize_object_dict(value: object) -> FirewallObject:
    """Normalize a dynamic SDK response object into a string-keyed dict."""

    if not isinstance(value, dict):
        return {}

    normalized: FirewallObject = {}
    for key, item in cast(dict[object, object], value).items():
        if isinstance(key, str):
            normalized[key] = item
    return normalized


def response_body(response: object) -> FirewallObject:
    """Return the top-level `Response` container from an SDK response."""

    return normalize_object_dict(normalize_object_dict(response).get("Response"))


def response_records(response: object, tag: str) -> list[FirewallObject]:
    """Extract one-or-many resource records from an SDK response."""

    raw = response_body(response).get(tag)
    if raw is None:
        return []
    if isinstance(raw, list):
        return [normalize_object_dict(item) for item in cast(list[object], raw)]
    return [normalize_object_dict(raw)]


def resolve_output_format(output: OutputFormat) -> Literal["json", "table"]:
    """Resolve auto output mode based on stdout TTY presence."""

    if output == "json":
        return "json"
    if output == "table":
        return "table"
    return "table" if sys.stdout.isatty() else "json"


def render_payload(payload: Any) -> None:
    """Render arbitrary payloads as JSON."""

    console.print(JSON.from_data(payload))


def render_records(
    records: list[dict[str, Any]],
    *,
    output: OutputFormat,
    title: str,
    columns: list[tuple[str, str]] | None = None,
) -> None:
    """Render resource records using table output on TTY and JSON otherwise."""

    if resolve_output_format(output) == "json":
        render_payload(records)
        return

    if not records:
        console.print(f"No {title.lower()} found.")
        return

    if columns is None:
        ordered_keys = list(records[0].keys())
        columns = [(key, key) for key in ordered_keys]

    table = Table(title=title)
    for _, label in columns:
        table.add_column(label)

    for record in records:
        row: list[str] = []
        for key, _ in columns:
            value = record.get(key, "")
            if isinstance(value, list):
                row.append(", ".join(str(item) for item in cast(list[object], value)))
            elif isinstance(value, dict):
                row.append(json.dumps(value, sort_keys=True))
            else:
                row.append("" if value is None else str(value))
        table.add_row(*row)

    console.print(table)


def render_named_result(
    message: str,
    payload: Any,
    *,
    output: OutputFormat = "auto",
) -> None:
    """Render a status line plus the resulting payload."""

    if resolve_output_format(output) == "json":
        render_payload(payload)
        return

    console.print(message)
    render_payload(payload)


def handle_api_exception(exc: Exception) -> None:
    """Render a consistent SDK/API error and exit."""

    console.print(f"API request failed: {exc}", style="bold red")
    raise typer.Exit(code=1) from exc


def require_yes(yes: bool) -> None:
    """Require an explicit acknowledgement for destructive commands."""

    if yes:
        return
    console.print("Pass --yes to confirm this destructive operation.", style="bold red")
    raise typer.Exit(code=2)


def load_json_input(
    inline_data: str | None,
    file_path: Path | None,
) -> dict[str, Any]:
    """Load a JSON object from --data or --data-file."""

    if inline_data and file_path is not None:
        raise typer.BadParameter("Use either --data or --data-file, not both.")
    if not inline_data and file_path is None:
        raise typer.BadParameter("Provide --data or --data-file.")

    raw = inline_data
    if file_path is not None:
        raw = file_path.read_text(encoding="utf-8")

    try:
        payload = json.loads(raw or "")
    except json.JSONDecodeError as exc:
        raise typer.BadParameter(f"Invalid JSON payload: {exc}") from exc

    if not isinstance(payload, dict):
        raise typer.BadParameter("JSON payload must be an object.")

    return cast(dict[str, Any], payload)


def render_dry_run(method: str, arguments: dict[str, Any]) -> None:
    """Render the planned SDK method call without mutating the firewall."""

    render_payload({"dry_run": True, "method": method, "arguments": arguments})
