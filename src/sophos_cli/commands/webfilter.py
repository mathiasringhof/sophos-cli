"""Explicit web filter command tree."""

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
from sophos_cli.services.webfilter_service import WebFilterService

webfilter_app = typer.Typer(no_args_is_help=True, help="Manage web filter policies and related objects.")
policy_app = typer.Typer(no_args_is_help=True, help="Manage web filter policies.")
user_activity_app = typer.Typer(no_args_is_help=True, help="Manage user activity objects.")


def _service(
    ctx: typer.Context,
    host: str | None,
    username: str | None,
    password: str | None,
    port: int | None,
    insecure: bool,
) -> WebFilterService:
    return WebFilterService(build_client(ctx, host, username, password, port, insecure))


@policy_app.command("list")
def policy_list(
    ctx: typer.Context,
    output: Annotated[OutputFormat, typer.Option("--output", help="Response format: auto, table, or json.")] = "auto",
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """List web filter policies."""

    records: list[dict[str, object]] = []
    try:
        records = _service(ctx, host, username, password, port, insecure).list_policies()
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)
    render_records(records, output=output, title="Web Filter Policies")


@policy_app.command("get")
def policy_get(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(help="Web filter policy name.")],
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """Get one web filter policy."""

    record: dict[str, object] | None = None
    try:
        record = _service(ctx, host, username, password, port, insecure).get_policy(name)
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)
    if record is None:
        raise typer.Exit(code=1)
    render_payload(record)


@policy_app.command("create")
def policy_create(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(help="Web filter policy name.")],
    data: Annotated[str | None, typer.Option("--data", help="Inline JSON create payload.")] = None,
    data_file: Annotated[Path | None, typer.Option("--data-file", help="Path to a JSON create payload file.")] = None,
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """Create a web filter policy."""

    response: dict[str, object] = {}
    try:
        response = _service(ctx, host, username, password, port, insecure).create_policy(
            name,
            load_json_input(data, data_file),
        )
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)
    render_payload(response)


@policy_app.command("update")
def policy_update(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(help="Web filter policy name.")],
    data: Annotated[str | None, typer.Option("--data", help="Inline JSON update payload.")] = None,
    data_file: Annotated[Path | None, typer.Option("--data-file", help="Path to a JSON update payload file.")] = None,
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """Update a web filter policy."""

    response: dict[str, object] = {}
    try:
        response = _service(ctx, host, username, password, port, insecure).update_policy(
            name,
            load_json_input(data, data_file),
        )
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)
    render_payload(response)


@policy_app.command("delete")
def policy_delete(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(help="Web filter policy name.")],
    yes: Annotated[bool, typer.Option("--yes", help="Confirm deletion of the web filter policy.")] = False,
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """Delete a web filter policy."""

    require_yes(yes)
    response: dict[str, object] = {}
    try:
        response = _service(ctx, host, username, password, port, insecure).delete_policy(name)
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)
    render_payload(response)


@user_activity_app.command("list")
def user_activity_list(
    ctx: typer.Context,
    output: Annotated[OutputFormat, typer.Option("--output", help="Response format: auto, table, or json.")] = "auto",
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """List user activity objects."""

    records: list[dict[str, object]] = []
    try:
        records = _service(ctx, host, username, password, port, insecure).list_user_activities()
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)
    render_records(records, output=output, title="User Activity")


@user_activity_app.command("get")
def user_activity_get(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(help="User activity name.")],
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """Get one user activity object."""

    record: dict[str, object] | None = None
    try:
        record = _service(ctx, host, username, password, port, insecure).get_user_activity(name)
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)
    if record is None:
        raise typer.Exit(code=1)
    render_payload(record)


@user_activity_app.command("create")
def user_activity_create(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(help="User activity name.")],
    data: Annotated[str | None, typer.Option("--data", help="Inline JSON create payload.")] = None,
    data_file: Annotated[Path | None, typer.Option("--data-file", help="Path to a JSON create payload file.")] = None,
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """Create a user activity object."""

    response: dict[str, object] = {}
    try:
        response = _service(ctx, host, username, password, port, insecure).create_user_activity(
            name,
            load_json_input(data, data_file),
        )
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)
    render_payload(response)


@user_activity_app.command("delete")
def user_activity_delete(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(help="User activity name.")],
    yes: Annotated[bool, typer.Option("--yes", help="Confirm deletion of the user activity object.")] = False,
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """Delete a user activity object."""

    require_yes(yes)
    response: dict[str, object] = {}
    try:
        response = _service(ctx, host, username, password, port, insecure).delete_user_activity(name)
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)
    render_payload(response)


webfilter_app.add_typer(policy_app, name="policy")
webfilter_app.add_typer(user_activity_app, name="user-activity")
