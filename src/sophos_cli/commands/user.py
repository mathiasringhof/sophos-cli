"""Explicit user command tree."""

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
    require_yes,
)
from sophos_cli.connection import HostOption, InsecureOption, PasswordOption, PortOption, UsernameOption
from sophos_cli.services.user_service import UserService

user_app = typer.Typer(no_args_is_help=True, help="Manage firewall user objects and credentials.")


def _service(
    ctx: typer.Context,
    host: str | None,
    username: str | None,
    password: str | None,
    port: int | None,
    insecure: bool,
) -> UserService:
    return UserService(build_client(ctx, host, username, password, port, insecure))


@user_app.command("list")
def user_list(
    ctx: typer.Context,
    output: Annotated[OutputFormat, typer.Option("--output", help="Response format: auto, table, or json.")] = "auto",
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """List users."""

    records: list[dict[str, object]] = []
    try:
        records = _service(ctx, host, username, password, port, insecure).list_users()
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)
    render_records(records, output=output, title="Users")


@user_app.command("get")
def user_get(
    ctx: typer.Context,
    username_value: Annotated[str, typer.Argument(help="Username.")],
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """Get one user."""

    record: dict[str, object] | None = None
    try:
        record = _service(ctx, host, username, password, port, insecure).get_user(username_value)
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)
    if record is None:
        raise typer.Exit(code=1)
    render_payload(record)


@user_app.command("create")
def user_create(
    ctx: typer.Context,
    username_value: Annotated[str, typer.Argument(help="Username.")],
    data: Annotated[str | None, typer.Option("--data", help="Inline JSON create payload.")] = None,
    data_file: Annotated[Path | None, typer.Option("--data-file", help="Path to a JSON create payload file.")] = None,
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """Create a user."""

    response: dict[str, object] = {}
    try:
        response = _service(ctx, host, username, password, port, insecure).create_user(
            username_value,
            load_json_input(data, data_file),
        )
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)
    render_payload(response)


@user_app.command("update-password")
def user_update_password(
    ctx: typer.Context,
    username_value: Annotated[str, typer.Argument(help="Username.")],
    new_password: Annotated[str, typer.Option("--new-password", help="New password.")],
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """Update a user's password."""

    response: dict[str, object] = {}
    try:
        response = _service(ctx, host, username, password, port, insecure).update_user_password(
            username_value,
            new_password,
        )
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)
    render_payload(response)


@user_app.command("delete")
def user_delete(
    ctx: typer.Context,
    username_value: Annotated[str, typer.Argument(help="Username.")],
    yes: Annotated[bool, typer.Option("--yes", help="Confirm deletion of the user.")] = False,
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """Delete a user."""

    require_yes(yes)
    response: dict[str, object] = {}
    try:
        response = _service(ctx, host, username, password, port, insecure).delete_user(username_value)
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)
    render_payload(response)
