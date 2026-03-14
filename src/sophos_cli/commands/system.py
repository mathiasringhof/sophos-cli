"""Explicit system command tree."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from sophos_cli.command_support import (
    API_EXCEPTIONS,
    OutputFormat,
    build_client,
    handle_api_exception,
    load_json_input,
    render_payload,
    render_records,
)
from sophos_cli.connection import HostOption, InsecureOption, PasswordOption, PortOption, UsernameOption
from sophos_cli.services.system_service import SystemService

system_app = typer.Typer(no_args_is_help=True, help="Inspect and update system-level backup, notification, and retention resources.")
backup_app = typer.Typer(no_args_is_help=True, help="Inspect and update backup settings.")
notification_app = typer.Typer(no_args_is_help=True, help="Inspect notifications.")
notification_list_app = typer.Typer(no_args_is_help=True, help="Inspect notification list entries.")
reports_retention_app = typer.Typer(no_args_is_help=True, help="Inspect reports retention settings.")


def _service(
    ctx: typer.Context,
    host: str | None,
    username: str | None,
    password: str | None,
    port: int | None,
    insecure: bool,
) -> SystemService:
    return SystemService(build_client(ctx, host, username, password, port, insecure))


@backup_app.command("get")
def backup_get(
    ctx: typer.Context,
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """Get backup settings."""

    payload: dict[str, object] = {}
    try:
        payload = _service(ctx, host, username, password, port, insecure).get_backup()
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)
    render_payload(payload)


@backup_app.command("update")
def backup_update(
    ctx: typer.Context,
    data: Annotated[str | None, typer.Option("--data", help="Inline JSON backup payload.")] = None,
    data_file: Annotated[Path | None, typer.Option("--data-file", help="Path to a JSON backup payload file.")] = None,
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """Update backup settings."""

    response: dict[str, object] = {}
    try:
        response = _service(ctx, host, username, password, port, insecure).update_backup(
            load_json_input(data, data_file)
        )
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)
    render_payload(response)


@notification_app.command("list")
def notification_list(
    ctx: typer.Context,
    output: Annotated[OutputFormat, typer.Option("--output", help="Response format: auto, table, or json.")] = "auto",
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """List notifications."""

    records: list[dict[str, object]] = []
    try:
        records = _service(ctx, host, username, password, port, insecure).list_notifications()
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)
    render_records(records, output=output, title="Notifications")


@notification_app.command("get")
def notification_get(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(help="Notification name.")],
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """Get one notification."""

    record: dict[str, object] | None = None
    try:
        record = _service(ctx, host, username, password, port, insecure).get_notification(name)
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)
    if record is None:
        raise typer.Exit(code=1)
    render_payload(record)


@notification_list_app.command("list")
def notification_item_list(
    ctx: typer.Context,
    output: Annotated[OutputFormat, typer.Option("--output", help="Response format: auto, table, or json.")] = "auto",
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """List notification list entries."""

    records: list[dict[str, object]] = []
    try:
        records = _service(ctx, host, username, password, port, insecure).list_notification_items()
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)
    render_records(records, output=output, title="Notification List")


@notification_list_app.command("get")
def notification_item_get(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(help="Notification list entry name.")],
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """Get one notification list entry."""

    record: dict[str, object] | None = None
    try:
        record = _service(ctx, host, username, password, port, insecure).get_notification_item(name)
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)
    if record is None:
        raise typer.Exit(code=1)
    render_payload(record)


@reports_retention_app.command("get")
def reports_retention_get(
    ctx: typer.Context,
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """Get reports retention settings."""

    payload: dict[str, object] = {}
    try:
        payload = _service(ctx, host, username, password, port, insecure).get_reports_retention()
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)
    render_payload(payload)


system_app.add_typer(backup_app, name="backup")
system_app.add_typer(notification_app, name="notification")
system_app.add_typer(notification_list_app, name="notification-list")
system_app.add_typer(reports_retention_app, name="reports-retention")
