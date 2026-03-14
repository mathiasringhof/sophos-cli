"""Explicit zone/network-topology command tree."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from sophos_cli.command_support import (
    API_EXCEPTIONS,
    OutputFormat,
    build_client,
    handle_api_exception,
    load_optional_json_input,
    render_payload,
    render_records,
    require_yes,
)
from sophos_cli.connection import HostOption, InsecureOption, PasswordOption, PortOption, UsernameOption
from sophos_cli.services.zone_service import ZoneService

zone_app = typer.Typer(no_args_is_help=True, help="Manage zones and inspect interfaces, VLANs, and DNS forwarders.")
interface_app = typer.Typer(no_args_is_help=True, help="Inspect interfaces.")
vlan_app = typer.Typer(no_args_is_help=True, help="Inspect VLANs.")
dns_forwarders_app = typer.Typer(no_args_is_help=True, help="Inspect DNS forwarders.")


def _service(
    ctx: typer.Context,
    host: str | None,
    username: str | None,
    password: str | None,
    port: int | None,
    insecure: bool,
) -> ZoneService:
    return ZoneService(build_client(ctx, host, username, password, port, insecure))


@zone_app.command("list")
def zone_list(
    ctx: typer.Context,
    output: Annotated[OutputFormat, typer.Option("--output", help="Response format: auto, table, or json.")] = "auto",
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """List zones."""

    records: list[dict[str, object]] = []
    try:
        records = _service(ctx, host, username, password, port, insecure).list_zones()
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)
    render_records(records, output=output, title="Zones")


@zone_app.command("get")
def zone_get(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(help="Zone name.")],
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """Get one zone."""

    record: dict[str, object] | None = None
    try:
        record = _service(ctx, host, username, password, port, insecure).get_zone(name)
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)
    if record is None:
        raise typer.Exit(code=1)
    render_payload(record)


@zone_app.command("create")
def zone_create(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(help="Zone name.")],
    zone_type: Annotated[str, typer.Option("--zone-type", help="Zone type.")],
    data: Annotated[str | None, typer.Option("--data", help="Inline JSON zone payload.")] = None,
    data_file: Annotated[Path | None, typer.Option("--data-file", help="Path to a JSON zone payload file.")] = None,
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """Create a zone."""

    response: dict[str, object] = {}
    try:
        response = _service(ctx, host, username, password, port, insecure).create_zone(
            name,
            zone_type,
            load_optional_json_input(data, data_file),
        )
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)
    render_payload(response)


@zone_app.command("update")
def zone_update(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(help="Zone name.")],
    data: Annotated[str | None, typer.Option("--data", help="Inline JSON zone update payload.")] = None,
    data_file: Annotated[Path | None, typer.Option("--data-file", help="Path to a JSON zone update payload file.")] = None,
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """Update a zone."""

    response: dict[str, object] = {}
    try:
        response = _service(ctx, host, username, password, port, insecure).update_zone(
            name,
            load_optional_json_input(data, data_file),
        )
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)
    render_payload(response)


@zone_app.command("delete")
def zone_delete(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(help="Zone name.")],
    yes: Annotated[bool, typer.Option("--yes", help="Confirm deletion of the zone.")] = False,
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """Delete a zone."""

    require_yes(yes)
    response: dict[str, object] = {}
    try:
        response = _service(ctx, host, username, password, port, insecure).delete_zone(name)
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)
    render_payload(response)


@interface_app.command("list")
def interface_list(
    ctx: typer.Context,
    output: Annotated[OutputFormat, typer.Option("--output", help="Response format: auto, table, or json.")] = "auto",
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """List interfaces."""

    records: list[dict[str, object]] = []
    try:
        records = _service(ctx, host, username, password, port, insecure).list_interfaces()
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)
    render_records(records, output=output, title="Interfaces")


@interface_app.command("get")
def interface_get(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(help="Interface name.")],
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """Get one interface."""

    record: dict[str, object] | None = None
    try:
        record = _service(ctx, host, username, password, port, insecure).get_interface(name)
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)
    if record is None:
        raise typer.Exit(code=1)
    render_payload(record)


@vlan_app.command("list")
def vlan_list(
    ctx: typer.Context,
    output: Annotated[OutputFormat, typer.Option("--output", help="Response format: auto, table, or json.")] = "auto",
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """List VLANs."""

    records: list[dict[str, object]] = []
    try:
        records = _service(ctx, host, username, password, port, insecure).list_vlans()
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)
    render_records(records, output=output, title="VLANs")


@vlan_app.command("get")
def vlan_get(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(help="VLAN name.")],
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """Get one VLAN."""

    record: dict[str, object] | None = None
    try:
        record = _service(ctx, host, username, password, port, insecure).get_vlan(name)
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)
    if record is None:
        raise typer.Exit(code=1)
    render_payload(record)


@dns_forwarders_app.command("get")
def dns_forwarders_get(
    ctx: typer.Context,
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """Get DNS forwarders."""

    payload: dict[str, object] = {}
    try:
        payload = _service(ctx, host, username, password, port, insecure).get_dns_forwarders()
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)
    render_payload(payload)


zone_app.add_typer(interface_app, name="interface")
zone_app.add_typer(vlan_app, name="vlan")
zone_app.add_typer(dns_forwarders_app, name="dns-forwarders")
