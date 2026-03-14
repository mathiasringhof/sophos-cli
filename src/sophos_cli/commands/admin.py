"""Explicit admin command tree."""

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
from sophos_cli.services.admin_service import AdminService

admin_app = typer.Typer(no_args_is_help=True, help="Manage administrator profiles and admin-facing settings.")
profile_app = typer.Typer(no_args_is_help=True, help="Manage admin profiles.")
authen_app = typer.Typer(no_args_is_help=True, help="Inspect admin authentication settings.")
settings_app = typer.Typer(no_args_is_help=True, help="Inspect admin settings.")


def _service(
    ctx: typer.Context,
    host: str | None,
    username: str | None,
    password: str | None,
    port: int | None,
    insecure: bool,
) -> AdminService:
    return AdminService(build_client(ctx, host, username, password, port, insecure))


@profile_app.command("list")
def profile_list(
    ctx: typer.Context,
    output: Annotated[OutputFormat, typer.Option("--output", help="Response format: auto, table, or json.")] = "auto",
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """List admin profiles."""

    records: list[dict[str, object]] = []
    try:
        records = _service(ctx, host, username, password, port, insecure).list_profiles()
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)
    render_records(records, output=output, title="Admin Profiles")


@profile_app.command("get")
def profile_get(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(help="Admin profile name.")],
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """Get one admin profile."""

    record: dict[str, object] | None = None
    try:
        record = _service(ctx, host, username, password, port, insecure).get_profile(name)
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)
    if record is None:
        raise typer.Exit(code=1)
    render_payload(record)


@profile_app.command("create")
def profile_create(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(help="Admin profile name.")],
    data: Annotated[str | None, typer.Option("--data", help="Inline JSON create payload.")] = None,
    data_file: Annotated[Path | None, typer.Option("--data-file", help="Path to a JSON create payload file.")] = None,
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """Create an admin profile."""

    response: dict[str, object] = {}
    try:
        response = _service(ctx, host, username, password, port, insecure).create_profile(
            name,
            load_json_input(data, data_file),
        )
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)
    render_payload(response)


@profile_app.command("update")
def profile_update(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(help="Admin profile name.")],
    data: Annotated[str | None, typer.Option("--data", help="Inline JSON update payload.")] = None,
    data_file: Annotated[Path | None, typer.Option("--data-file", help="Path to a JSON update payload file.")] = None,
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """Update an admin profile."""

    response: dict[str, object] = {}
    try:
        response = _service(ctx, host, username, password, port, insecure).update_profile(
            name,
            load_json_input(data, data_file),
        )
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)
    render_payload(response)


@profile_app.command("delete")
def profile_delete(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(help="Admin profile name.")],
    yes: Annotated[bool, typer.Option("--yes", help="Confirm deletion of the admin profile.")] = False,
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """Delete an admin profile."""

    require_yes(yes)
    response: dict[str, object] = {}
    try:
        response = _service(ctx, host, username, password, port, insecure).delete_profile(name)
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)
    render_payload(response)


@authen_app.command("get")
def authen_get(
    ctx: typer.Context,
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """Get admin authentication settings."""

    payload: dict[str, object] = {}
    try:
        payload = _service(ctx, host, username, password, port, insecure).get_authentication()
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)
    render_payload(payload)


@settings_app.command("get")
def settings_get(
    ctx: typer.Context,
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """Get admin settings."""

    payload: dict[str, object] = {}
    try:
        payload = _service(ctx, host, username, password, port, insecure).get_settings()
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)
    render_payload(payload)


admin_app.add_typer(profile_app, name="profile")
admin_app.add_typer(authen_app, name="authen")
admin_app.add_typer(settings_app, name="settings")
