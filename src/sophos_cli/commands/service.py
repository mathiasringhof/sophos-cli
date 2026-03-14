"""Explicit service-domain command tree."""

from __future__ import annotations

import json
from typing import Annotated, Any, cast

import typer

from sophos_cli.command_support import (
    API_EXCEPTIONS,
    OutputFormat,
    build_client,
    handle_api_exception,
    render_payload,
    render_records,
    require_yes,
)
from sophos_cli.connection import (
    HostOption,
    InsecureOption,
    PasswordOption,
    PortOption,
    UsernameOption,
)
from sophos_cli.models.service import (
    GroupAction,
    ServiceCreate,
    ServiceEntry,
    ServiceGroupCreate,
    ServiceGroupUpdate,
    ServiceType,
    ServiceUpdate,
    UrlGroupCreate,
    UrlGroupUpdate,
)
from sophos_cli.services.service_service import ServiceService

service_app = typer.Typer(no_args_is_help=True, help="Manage services, service groups, and URL groups.")
service_group_app = typer.Typer(no_args_is_help=True, help="Manage service groups.")
url_group_app = typer.Typer(no_args_is_help=True, help="Manage URL groups.")


def _service(
    ctx: typer.Context,
    host: str | None,
    username: str | None,
    password: str | None,
    port: int | None,
    insecure: bool,
) -> ServiceService:
    return ServiceService(build_client(ctx, host, username, password, port, insecure))


def _parse_entry_json(entry_json: list[str]) -> list[ServiceEntry]:
    entries: list[ServiceEntry] = []
    for raw in entry_json:
        try:
            decoded = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise typer.BadParameter(f"Invalid --entry-json value: {exc}") from exc
        if not isinstance(decoded, dict):
            raise typer.BadParameter("--entry-json values must decode to JSON objects.")
        entries.append(ServiceEntry.model_validate(decoded))
    return entries


@service_app.command("list")
def service_list(
    ctx: typer.Context,
    output: Annotated[OutputFormat, typer.Option("--output", help="Response format: auto, table, or json.")] = "auto",
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """List services."""

    records: list[dict[str, object]] = []
    try:
        records = _service(ctx, host, username, password, port, insecure).list_services()
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)
    render_records(records, output=output, title="Services")


@service_app.command("get")
def service_get(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(help="Service name.")],
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """Get one service."""

    record: dict[str, object] | None = None
    try:
        record = _service(ctx, host, username, password, port, insecure).get_service(name)
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)
    if record is None:
        raise typer.Exit(code=1)
    render_payload(record)


@service_app.command("create")
def service_create(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(help="Service name.")],
    service_type: Annotated[ServiceType, typer.Option("--service-type", help="Service type.")],
    entry_json: Annotated[
        list[str],
        typer.Option(
            "--entry-json",
            help="Service entry as JSON. Repeat for multiple entries.",
        ),
    ],
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """Create a service."""

    response: dict[str, object] = {}
    try:
        payload = ServiceCreate(name=name, service_type=service_type, service_list=_parse_entry_json(entry_json))
        response = _service(ctx, host, username, password, port, insecure).create_service(payload)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)
    render_payload(response)


@service_app.command("update")
def service_update(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(help="Service name.")],
    service_type: Annotated[ServiceType, typer.Option("--service-type", help="Service type.")],
    entry_json: Annotated[
        list[str],
        typer.Option(
            "--entry-json",
            help="Service entry as JSON. Repeat for multiple entries.",
        ),
    ],
    action: Annotated[GroupAction, typer.Option("--action", help="Update action: add, remove, replace.")] = "add",
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """Update a service."""

    response: dict[str, object] = {}
    try:
        payload = ServiceUpdate(
            name=name,
            service_type=service_type,
            service_list=_parse_entry_json(entry_json),
            action=cast(GroupAction, action),
        )
        response = _service(ctx, host, username, password, port, insecure).update_service(payload)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)
    render_payload(response)


@service_app.command("delete")
def service_delete(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(help="Service name.")],
    yes: Annotated[bool, typer.Option("--yes", help="Confirm deletion of the service.")] = False,
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """Delete a service."""

    require_yes(yes)
    response: dict[str, object] = {}
    try:
        response = _service(ctx, host, username, password, port, insecure).delete_service(name)
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)
    render_payload(response)


@service_group_app.command("list")
def service_group_list(
    ctx: typer.Context,
    output: Annotated[OutputFormat, typer.Option("--output", help="Response format: auto, table, or json.")] = "auto",
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """List service groups."""

    records: list[dict[str, object]] = []
    try:
        records = _service(ctx, host, username, password, port, insecure).list_service_groups()
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)
    render_records(records, output=output, title="Service Groups")


@service_group_app.command("get")
def service_group_get(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(help="Service group name.")],
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """Get one service group."""

    record: dict[str, object] | None = None
    try:
        record = _service(ctx, host, username, password, port, insecure).get_service_group(name)
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)
    if record is None:
        raise typer.Exit(code=1)
    render_payload(record)


@service_group_app.command("create")
def service_group_create(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(help="Service group name.")],
    members: Annotated[list[str], typer.Option("--member", help="Service members to include.")],
    description: Annotated[str | None, typer.Option("--description", help="Optional description.")] = None,
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """Create a service group."""

    response: dict[str, object] = {}
    try:
        response = _service(ctx, host, username, password, port, insecure).create_service_group(
            ServiceGroupCreate(name=name, service_list=members, description=description)
        )
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)
    render_payload(response)


@service_group_app.command("update")
def service_group_update(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(help="Service group name.")],
    members: Annotated[list[str], typer.Option("--member", help="Service members to add/remove/replace.")],
    action: Annotated[GroupAction, typer.Option("--action", help="Membership action: add, remove, replace.")] = "add",
    description: Annotated[str | None, typer.Option("--description", help="Optional description override.")] = None,
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """Update a service group."""

    response: dict[str, object] = {}
    try:
        response = _service(ctx, host, username, password, port, insecure).update_service_group(
            ServiceGroupUpdate(
                name=name,
                service_list=members,
                action=cast(GroupAction, action),
                description=description,
            )
        )
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)
    render_payload(response)


@service_group_app.command("delete")
def service_group_delete(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(help="Service group name.")],
    yes: Annotated[bool, typer.Option("--yes", help="Confirm deletion of the service group.")] = False,
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """Delete a service group."""

    require_yes(yes)
    response: dict[str, object] = {}
    try:
        response = _service(ctx, host, username, password, port, insecure).delete_service_group(name)
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)
    render_payload(response)


@url_group_app.command("list")
def url_group_list(
    ctx: typer.Context,
    output: Annotated[OutputFormat, typer.Option("--output", help="Response format: auto, table, or json.")] = "auto",
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """List URL groups."""

    records: list[dict[str, object]] = []
    try:
        records = _service(ctx, host, username, password, port, insecure).list_url_groups()
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)
    render_records(records, output=output, title="URL Groups")


@url_group_app.command("get")
def url_group_get(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(help="URL group name.")],
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """Get one URL group."""

    record: dict[str, object] | None = None
    try:
        record = _service(ctx, host, username, password, port, insecure).get_url_group(name)
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)
    if record is None:
        raise typer.Exit(code=1)
    render_payload(record)


@url_group_app.command("create")
def url_group_create(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(help="URL group name.")],
    domains: Annotated[list[str], typer.Option("--domain", help="Domain entries to include.")],
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """Create a URL group."""

    response: dict[str, object] = {}
    try:
        response = _service(ctx, host, username, password, port, insecure).create_url_group(
            UrlGroupCreate(name=name, domain_list=domains)
        )
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)
    render_payload(response)


@url_group_app.command("update")
def url_group_update(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(help="URL group name.")],
    domains: Annotated[list[str], typer.Option("--domain", help="Domain entries to add/remove/replace.")],
    action: Annotated[GroupAction, typer.Option("--action", help="Update action: add, remove, replace.")] = "add",
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """Update a URL group."""

    response: dict[str, object] = {}
    try:
        response = _service(ctx, host, username, password, port, insecure).update_url_group(
            UrlGroupUpdate(name=name, domain_list=domains, action=cast(GroupAction, action))
        )
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)
    render_payload(response)


@url_group_app.command("delete")
def url_group_delete(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(help="URL group name.")],
    yes: Annotated[bool, typer.Option("--yes", help="Confirm deletion of the URL group.")] = False,
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """Delete a URL group."""

    require_yes(yes)
    response: dict[str, object] = {}
    try:
        response = _service(ctx, host, username, password, port, insecure).delete_url_group(name)
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)
    render_payload(response)


service_app.add_typer(service_group_app, name="service-group")
service_app.add_typer(url_group_app, name="url-group")
