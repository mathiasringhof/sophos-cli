"""Wave 1 explicit network command tree."""

from __future__ import annotations

from typing import Annotated, cast

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
from sophos_cli.models.network import (
    FqdnHostCreate,
    FqdnHostGroupCreate,
    FqdnHostGroupUpdate,
    FqdnHostUpdate,
    GroupAction,
    IpHostCreate,
    IpHostGroupCreate,
    IpHostGroupUpdate,
    IpHostUpdate,
    IpNetworkCreate,
    IpNetworkUpdate,
    IpRangeCreate,
    IpRangeUpdate,
)
from sophos_cli.services.network_service import NetworkService

network_app = typer.Typer(no_args_is_help=True, help="Manage network objects and identity resources.")
ip_host_app = typer.Typer(no_args_is_help=True, help="Manage IP host objects.")
ip_host_group_app = typer.Typer(no_args_is_help=True, help="Manage IP host groups.")
ip_network_app = typer.Typer(no_args_is_help=True, help="Manage IP network objects.")
ip_range_app = typer.Typer(no_args_is_help=True, help="Manage IP range objects.")
fqdn_host_app = typer.Typer(no_args_is_help=True, help="Manage FQDN host objects.")
fqdn_host_group_app = typer.Typer(no_args_is_help=True, help="Manage FQDN host groups.")


def _service(
    ctx: typer.Context,
    host: str | None,
    username: str | None,
    password: str | None,
    port: int | None,
    insecure: bool,
) -> NetworkService:
    return NetworkService(build_client(ctx, host, username, password, port, insecure))


@ip_host_app.command("list")
def ip_host_list(
    ctx: typer.Context,
    output: Annotated[OutputFormat, typer.Option("--output", help="Response format: auto, table, or json.")] = "auto",
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """List IP host objects."""

    records: list[dict[str, object]] = []
    try:
        records = _service(ctx, host, username, password, port, insecure).list_ip_hosts()
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)

    render_records(records, output=output, title="IP Hosts", columns=[("Name", "Name"), ("IPAddress", "IP"), ("HostType", "Type")])


@ip_host_app.command("get")
def ip_host_get(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(help="IP host object name.")],
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """Get one IP host object."""

    record: dict[str, object] | None = None
    try:
        record = _service(ctx, host, username, password, port, insecure).get_ip_host(name)
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)

    if record is None:
        raise typer.Exit(code=1)
    render_payload(record)


@ip_host_app.command(
    "create",
    epilog="Example: sophos-cli network ip-host create branch-office --ip-address 192.0.2.44",
)
def ip_host_create(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(help="IP host object name.")],
    ip_address: Annotated[str, typer.Option("--ip-address", help="IPv4 address for the object.")],
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """Create an IP host object."""

    response: dict[str, object] = {}
    try:
        response = _service(ctx, host, username, password, port, insecure).create_ip_host(
            IpHostCreate(name=name, ip_address=ip_address)
        )
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)

    render_payload(response)


@ip_host_app.command("update")
def ip_host_update(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(help="IP host object name.")],
    ip_address: Annotated[str, typer.Option("--ip-address", help="Replacement IPv4 address.")],
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """Update an IP host object."""

    response: dict[str, object] = {}
    try:
        response = _service(ctx, host, username, password, port, insecure).update_ip_host(
            IpHostUpdate(name=name, ip_address=ip_address)
        )
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)

    render_payload(response)


@ip_host_app.command("delete")
def ip_host_delete(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(help="IP host object name.")],
    yes: Annotated[bool, typer.Option("--yes", help="Confirm deletion of the object.")] = False,
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """Delete an IP host object."""

    require_yes(yes)
    response: dict[str, object] = {}
    try:
        response = _service(ctx, host, username, password, port, insecure).delete_ip_host(name)
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)
    render_payload(response)

@ip_host_group_app.command("list")
def ip_host_group_list(
    ctx: typer.Context,
    output: Annotated[OutputFormat, typer.Option("--output", help="Response format: auto, table, or json.")] = "auto",
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """List IP host groups."""

    records: list[dict[str, object]] = []
    try:
        records = _service(ctx, host, username, password, port, insecure).list_ip_host_groups()
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)
    render_records(records, output=output, title="IP Host Groups")


@ip_host_group_app.command("get")
def ip_host_group_get(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(help="IP host group name.")],
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """Get one IP host group."""

    record: dict[str, object] | None = None
    try:
        record = _service(ctx, host, username, password, port, insecure).get_ip_host_group(name)
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)
    if record is None:
        raise typer.Exit(code=1)
    render_payload(record)


@ip_host_group_app.command("create")
def ip_host_group_create(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(help="IP host group name.")],
    members: Annotated[
        list[str] | None,
        typer.Option("--host", help="Existing IP host members to include."),
    ] = None,
    description: Annotated[str | None, typer.Option("--description", help="Optional description.")] = None,
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """Create an IP host group."""

    response: dict[str, object] = {}
    try:
        response = _service(ctx, host, username, password, port, insecure).create_ip_host_group(
            IpHostGroupCreate(name=name, host_list=members or [], description=description)
        )
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)
    render_payload(response)


@ip_host_group_app.command("update")
def ip_host_group_update(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(help="IP host group name.")],
    members: Annotated[
        list[str] | None,
        typer.Option("--host", help="Member hosts to add/remove/replace."),
    ] = None,
    action: Annotated[str, typer.Option("--action", help="Membership action: add, remove, replace.")] = "add",
    description: Annotated[str | None, typer.Option("--description", help="Optional description override.")] = None,
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """Update an IP host group."""

    response: dict[str, object] = {}
    try:
        response = _service(ctx, host, username, password, port, insecure).update_ip_host_group(
            IpHostGroupUpdate(
                name=name,
                host_list=members or [],
                description=description,
                action=cast(GroupAction, action),
            )
        )
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)
    render_payload(response)


@ip_host_group_app.command("delete")
def ip_host_group_delete(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(help="IP host group name.")],
    yes: Annotated[bool, typer.Option("--yes", help="Confirm deletion of the group.")] = False,
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """Delete an IP host group."""

    require_yes(yes)
    response: dict[str, object] = {}
    try:
        response = _service(ctx, host, username, password, port, insecure).delete_ip_host_group(name)
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)
    render_payload(response)


@ip_network_app.command("list")
def ip_network_list(
    ctx: typer.Context,
    output: Annotated[OutputFormat, typer.Option("--output", help="Response format: auto, table, or json.")] = "auto",
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """List IP network objects."""

    records: list[dict[str, object]] = []
    try:
        records = _service(ctx, host, username, password, port, insecure).list_ip_networks()
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)
    render_records(records, output=output, title="IP Networks")


@ip_network_app.command("get")
def ip_network_get(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(help="IP network object name.")],
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """Get one IP network object."""

    record: dict[str, object] | None = None
    try:
        record = _service(ctx, host, username, password, port, insecure).get_ip_network(name)
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)
    if record is None:
        raise typer.Exit(code=1)
    render_payload(record)


@ip_network_app.command("create")
def ip_network_create(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(help="IP network object name.")],
    ip_network: Annotated[str, typer.Option("--ip-network", help="Network address.")],
    mask: Annotated[str, typer.Option("--mask", help="Subnet mask in dotted decimal format.")],
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """Create an IP network object."""

    response: dict[str, object] = {}
    try:
        response = _service(ctx, host, username, password, port, insecure).create_ip_network(
            IpNetworkCreate(name=name, ip_network=ip_network, mask=mask)
        )
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)
    render_payload(response)


@ip_network_app.command("update")
def ip_network_update(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(help="IP network object name.")],
    ip_network: Annotated[str, typer.Option("--ip-network", help="Replacement network address.")],
    mask: Annotated[str, typer.Option("--mask", help="Replacement subnet mask.")],
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """Update an IP network object."""

    response: dict[str, object] = {}
    try:
        response = _service(ctx, host, username, password, port, insecure).update_ip_network(
            IpNetworkUpdate(name=name, ip_network=ip_network, mask=mask)
        )
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)
    render_payload(response)


@ip_network_app.command("delete")
def ip_network_delete(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(help="IP network object name.")],
    yes: Annotated[bool, typer.Option("--yes", help="Confirm deletion of the object.")] = False,
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """Delete an IP network object."""

    require_yes(yes)
    response: dict[str, object] = {}
    try:
        response = _service(ctx, host, username, password, port, insecure).delete_ip_network(name)
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)
    render_payload(response)


@ip_range_app.command("list")
def ip_range_list(
    ctx: typer.Context,
    output: Annotated[OutputFormat, typer.Option("--output", help="Response format: auto, table, or json.")] = "auto",
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """List IP range objects."""

    records: list[dict[str, object]] = []
    try:
        records = _service(ctx, host, username, password, port, insecure).list_ip_ranges()
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)
    render_records(records, output=output, title="IP Ranges")


@ip_range_app.command("get")
def ip_range_get(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(help="IP range object name.")],
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """Get one IP range object."""

    record: dict[str, object] | None = None
    try:
        record = _service(ctx, host, username, password, port, insecure).get_ip_range(name)
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)
    if record is None:
        raise typer.Exit(code=1)
    render_payload(record)


@ip_range_app.command("create")
def ip_range_create(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(help="IP range object name.")],
    start_ip: Annotated[str, typer.Option("--start-ip", help="Start address of the range.")],
    end_ip: Annotated[str, typer.Option("--end-ip", help="End address of the range.")],
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """Create an IP range object."""

    response: dict[str, object] = {}
    try:
        response = _service(ctx, host, username, password, port, insecure).create_ip_range(
            IpRangeCreate(name=name, start_ip=start_ip, end_ip=end_ip)
        )
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)
    render_payload(response)


@ip_range_app.command("update")
def ip_range_update(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(help="IP range object name.")],
    start_ip: Annotated[str, typer.Option("--start-ip", help="Replacement start address.")],
    end_ip: Annotated[str, typer.Option("--end-ip", help="Replacement end address.")],
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """Update an IP range object."""

    response: dict[str, object] = {}
    try:
        response = _service(ctx, host, username, password, port, insecure).update_ip_range(
            IpRangeUpdate(name=name, start_ip=start_ip, end_ip=end_ip)
        )
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)
    render_payload(response)


@ip_range_app.command("delete")
def ip_range_delete(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(help="IP range object name.")],
    yes: Annotated[bool, typer.Option("--yes", help="Confirm deletion of the object.")] = False,
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """Delete an IP range object."""

    require_yes(yes)
    response: dict[str, object] = {}
    try:
        response = _service(ctx, host, username, password, port, insecure).delete_ip_range(name)
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)
    render_payload(response)


@fqdn_host_app.command("list")
def fqdn_host_list(
    ctx: typer.Context,
    output: Annotated[OutputFormat, typer.Option("--output", help="Response format: auto, table, or json.")] = "auto",
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """List FQDN host objects."""

    records: list[dict[str, object]] = []
    try:
        records = _service(ctx, host, username, password, port, insecure).list_fqdn_hosts()
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)
    render_records(records, output=output, title="FQDN Hosts")


@fqdn_host_app.command("get")
def fqdn_host_get(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(help="FQDN host object name.")],
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """Get one FQDN host object."""

    record: dict[str, object] | None = None
    try:
        record = _service(ctx, host, username, password, port, insecure).get_fqdn_host(name)
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)
    if record is None:
        raise typer.Exit(code=1)
    render_payload(record)


@fqdn_host_app.command("create")
def fqdn_host_create(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(help="FQDN host object name.")],
    fqdn: Annotated[str, typer.Option("--fqdn", help="Fully qualified domain name to map.")],
    group: Annotated[
        list[str] | None,
        typer.Option("--group", help="Associated FQDN host groups."),
    ] = None,
    description: Annotated[str | None, typer.Option("--description", help="Optional description.")] = None,
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """Create an FQDN host object."""

    response: dict[str, object] = {}
    try:
        response = _service(ctx, host, username, password, port, insecure).create_fqdn_host(
            FqdnHostCreate(
                name=name,
                fqdn=fqdn,
                fqdn_group_list=group or [],
                description=description,
            )
        )
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)
    render_payload(response)


@fqdn_host_app.command("update")
def fqdn_host_update(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(help="FQDN host object name.")],
    fqdn: Annotated[str, typer.Option("--fqdn", help="Replacement fully qualified domain name.")],
    group: Annotated[
        list[str] | None,
        typer.Option("--group", help="Replacement associated groups."),
    ] = None,
    description: Annotated[str | None, typer.Option("--description", help="Optional description override.")] = None,
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """Update an FQDN host object."""

    response: dict[str, object] = {}
    try:
        response = _service(ctx, host, username, password, port, insecure).update_fqdn_host(
            FqdnHostUpdate(
                name=name,
                fqdn=fqdn,
                fqdn_group_list=group or [],
                description=description,
            )
        )
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)
    render_payload(response)


@fqdn_host_app.command("delete")
def fqdn_host_delete(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(help="FQDN host object name.")],
    yes: Annotated[bool, typer.Option("--yes", help="Confirm deletion of the object.")] = False,
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """Delete an FQDN host object."""

    require_yes(yes)
    response: dict[str, object] = {}
    try:
        response = _service(ctx, host, username, password, port, insecure).delete_fqdn_host(name)
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)
    render_payload(response)


@fqdn_host_group_app.command("list")
def fqdn_host_group_list(
    ctx: typer.Context,
    output: Annotated[OutputFormat, typer.Option("--output", help="Response format: auto, table, or json.")] = "auto",
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """List FQDN host groups."""

    records: list[dict[str, object]] = []
    try:
        records = _service(ctx, host, username, password, port, insecure).list_fqdn_host_groups()
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)
    render_records(records, output=output, title="FQDN Host Groups")


@fqdn_host_group_app.command("get")
def fqdn_host_group_get(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(help="FQDN host group name.")],
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """Get one FQDN host group."""

    record: dict[str, object] | None = None
    try:
        record = _service(ctx, host, username, password, port, insecure).get_fqdn_host_group(name)
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)
    if record is None:
        raise typer.Exit(code=1)
    render_payload(record)


@fqdn_host_group_app.command("create")
def fqdn_host_group_create(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(help="FQDN host group name.")],
    members: Annotated[
        list[str] | None,
        typer.Option("--host", help="FQDN host members to include."),
    ] = None,
    description: Annotated[str | None, typer.Option("--description", help="Optional description.")] = None,
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """Create an FQDN host group."""

    response: dict[str, object] = {}
    try:
        response = _service(ctx, host, username, password, port, insecure).create_fqdn_host_group(
            FqdnHostGroupCreate(name=name, fqdn_host_list=members or [], description=description)
        )
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)
    render_payload(response)


@fqdn_host_group_app.command("update")
def fqdn_host_group_update(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(help="FQDN host group name.")],
    members: Annotated[
        list[str] | None,
        typer.Option("--host", help="Member hosts to add/remove/replace."),
    ] = None,
    action: Annotated[str, typer.Option("--action", help="Membership action: add, remove, replace.")] = "add",
    description: Annotated[str | None, typer.Option("--description", help="Optional description override.")] = None,
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """Update an FQDN host group."""

    response: dict[str, object] = {}
    try:
        response = _service(ctx, host, username, password, port, insecure).update_fqdn_host_group(
            FqdnHostGroupUpdate(
                name=name,
                fqdn_host_list=members or [],
                description=description,
                action=cast(GroupAction, action),
            )
        )
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)
    render_payload(response)


@fqdn_host_group_app.command("delete")
def fqdn_host_group_delete(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(help="FQDN host group name.")],
    yes: Annotated[bool, typer.Option("--yes", help="Confirm deletion of the group.")] = False,
    host: HostOption = None,
    username: UsernameOption = None,
    password: PasswordOption = None,
    port: PortOption = None,
    insecure: InsecureOption = False,
) -> None:
    """Delete an FQDN host group."""

    require_yes(yes)
    response: dict[str, object] = {}
    try:
        response = _service(ctx, host, username, password, port, insecure).delete_fqdn_host_group(name)
    except API_EXCEPTIONS as exc:
        handle_api_exception(exc)
    render_payload(response)


network_app.add_typer(ip_host_app, name="ip-host")
network_app.add_typer(ip_host_group_app, name="ip-host-group")
network_app.add_typer(ip_network_app, name="ip-network")
network_app.add_typer(ip_range_app, name="ip-range")
network_app.add_typer(fqdn_host_app, name="fqdn-host")
network_app.add_typer(fqdn_host_group_app, name="fqdn-host-group")
