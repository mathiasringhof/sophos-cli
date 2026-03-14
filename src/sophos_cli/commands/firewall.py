"""Explicit firewall command tree."""

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
from sophos_cli.services.firewall_service import FirewallService

firewall_app = typer.Typer(no_args_is_help=True, help="Manage firewall rules, rule groups, and ACL rules.")
rule_app = typer.Typer(no_args_is_help=True, help="Manage firewall rules.")
rule_group_app = typer.Typer(no_args_is_help=True, help="Manage firewall rule groups.")
acl_rule_app = typer.Typer(no_args_is_help=True, help="Manage local service ACL exception rules.")


def _service(
    ctx: typer.Context,
    host: str | None,
    username: str | None,
    password: str | None,
    port: int | None,
    insecure: bool,
) -> FirewallService:
    return FirewallService(build_client(ctx, host, username, password, port, insecure))


@rule_app.command("list")
def rule_list(
    ctx: typer.Context,
    output: Annotated[OutputFormat, typer.Option("--output", help="Response format: auto, table, or json.")] = "auto",
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """List firewall rules."""

    records: list[dict[str, object]] = []
    try:
        records = _service(ctx, host, username, password, port, insecure).list_rules()
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)
    render_records(records, output=output, title="Firewall Rules")


@rule_app.command("get")
def rule_get(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(help="Firewall rule name.")],
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """Get one firewall rule."""

    record: dict[str, object] | None = None
    try:
        record = _service(ctx, host, username, password, port, insecure).get_rule(name)
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)
    if record is None:
        raise typer.Exit(code=1)
    render_payload(record)


@rule_app.command("create")
def rule_create(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(help="Firewall rule name.")],
    data: Annotated[str | None, typer.Option("--data", help="Inline JSON rule payload.")] = None,
    data_file: Annotated[Path | None, typer.Option("--data-file", help="Path to a JSON rule payload file.")] = None,
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """Create a firewall rule."""

    response: dict[str, object] = {}
    try:
        response = _service(ctx, host, username, password, port, insecure).create_rule(
            name,
            load_json_input(data, data_file),
        )
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)
    render_payload(response)


@rule_app.command("update")
def rule_update(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(help="Firewall rule name.")],
    data: Annotated[str | None, typer.Option("--data", help="Inline JSON update payload.")] = None,
    data_file: Annotated[Path | None, typer.Option("--data-file", help="Path to a JSON update payload file.")] = None,
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """Update a firewall rule."""

    response: dict[str, object] = {}
    try:
        response = _service(ctx, host, username, password, port, insecure).update_rule(
            name,
            load_json_input(data, data_file),
        )
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)
    render_payload(response)


@rule_app.command("delete")
def rule_delete(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(help="Firewall rule name.")],
    yes: Annotated[bool, typer.Option("--yes", help="Confirm deletion of the firewall rule.")] = False,
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """Delete a firewall rule."""

    require_yes(yes)
    response: dict[str, object] = {}
    try:
        response = _service(ctx, host, username, password, port, insecure).delete_rule(name)
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)
    render_payload(response)


@rule_group_app.command("list")
def rule_group_list(
    ctx: typer.Context,
    output: Annotated[OutputFormat, typer.Option("--output", help="Response format: auto, table, or json.")] = "auto",
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """List firewall rule groups."""

    records: list[dict[str, object]] = []
    try:
        records = _service(ctx, host, username, password, port, insecure).list_rule_groups()
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)
    render_records(records, output=output, title="Firewall Rule Groups")


@rule_group_app.command("get")
def rule_group_get(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(help="Firewall rule group name.")],
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """Get one firewall rule group."""

    record: dict[str, object] | None = None
    try:
        record = _service(ctx, host, username, password, port, insecure).get_rule_group(name)
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)
    if record is None:
        raise typer.Exit(code=1)
    render_payload(record)


@rule_group_app.command("create")
def rule_group_create(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(help="Firewall rule group name.")],
    data: Annotated[str | None, typer.Option("--data", help="Inline JSON create payload.")] = None,
    data_file: Annotated[Path | None, typer.Option("--data-file", help="Path to a JSON create payload file.")] = None,
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """Create a firewall rule group."""

    response: dict[str, object] = {}
    try:
        response = _service(ctx, host, username, password, port, insecure).create_rule_group(
            name,
            load_json_input(data, data_file),
        )
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)
    render_payload(response)


@rule_group_app.command("update")
def rule_group_update(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(help="Firewall rule group name.")],
    data: Annotated[str | None, typer.Option("--data", help="Inline JSON update payload.")] = None,
    data_file: Annotated[Path | None, typer.Option("--data-file", help="Path to a JSON update payload file.")] = None,
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """Update a firewall rule group."""

    response: dict[str, object] = {}
    try:
        response = _service(ctx, host, username, password, port, insecure).update_rule_group(
            name,
            load_json_input(data, data_file),
        )
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)
    render_payload(response)


@rule_group_app.command("delete")
def rule_group_delete(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(help="Firewall rule group name.")],
    yes: Annotated[bool, typer.Option("--yes", help="Confirm deletion of the firewall rule group.")] = False,
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """Delete a firewall rule group."""

    require_yes(yes)
    response: dict[str, object] = {}
    try:
        response = _service(ctx, host, username, password, port, insecure).delete_rule_group(name)
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)
    render_payload(response)


@acl_rule_app.command("list")
def acl_rule_list(
    ctx: typer.Context,
    output: Annotated[OutputFormat, typer.Option("--output", help="Response format: auto, table, or json.")] = "auto",
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """List ACL rules."""

    records: list[dict[str, object]] = []
    try:
        records = _service(ctx, host, username, password, port, insecure).list_acl_rules()
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)
    render_records(records, output=output, title="ACL Rules")


@acl_rule_app.command("get")
def acl_rule_get(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(help="ACL rule name.")],
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """Get one ACL rule."""

    record: dict[str, object] | None = None
    try:
        record = _service(ctx, host, username, password, port, insecure).get_acl_rule(name)
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)
    if record is None:
        raise typer.Exit(code=1)
    render_payload(record)


@acl_rule_app.command("create")
def acl_rule_create(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(help="ACL rule name.")],
    data: Annotated[str | None, typer.Option("--data", help="Inline JSON create payload.")] = None,
    data_file: Annotated[Path | None, typer.Option("--data-file", help="Path to a JSON create payload file.")] = None,
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """Create an ACL rule."""

    response: dict[str, object] = {}
    try:
        response = _service(ctx, host, username, password, port, insecure).create_acl_rule(
            name,
            load_json_input(data, data_file),
        )
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)
    render_payload(response)


@acl_rule_app.command("update")
def acl_rule_update(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(help="ACL rule name.")],
    data: Annotated[str | None, typer.Option("--data", help="Inline JSON update payload.")] = None,
    data_file: Annotated[Path | None, typer.Option("--data-file", help="Path to a JSON update payload file.")] = None,
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """Update an ACL rule."""

    response: dict[str, object] = {}
    try:
        response = _service(ctx, host, username, password, port, insecure).update_acl_rule(
            name,
            load_json_input(data, data_file),
        )
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)
    render_payload(response)


@acl_rule_app.command("delete")
def acl_rule_delete(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(help="ACL rule name.")],
    yes: Annotated[bool, typer.Option("--yes", help="Confirm deletion of the ACL rule.")] = False,
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """Delete an ACL rule."""

    require_yes(yes)
    response: dict[str, object] = {}
    try:
        response = _service(ctx, host, username, password, port, insecure).delete_acl_rule(name)
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)
    render_payload(response)


firewall_app.add_typer(rule_app, name="rule")
firewall_app.add_typer(rule_group_app, name="rule-group")
firewall_app.add_typer(acl_rule_app, name="acl-rule")
