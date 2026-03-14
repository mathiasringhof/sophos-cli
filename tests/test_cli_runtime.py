from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from sophosfirewall_python.api_client import (
    SophosFirewallAPIError,
    SophosFirewallAuthFailure,
    SophosFirewallZeroRecords,
)
from typer.testing import CliRunner

from sophos_cli.cli import app
from sophos_cli.connection import ConnectionParams


def test_dns_list_requires_connection_settings(runner: CliRunner) -> None:
    result = runner.invoke(
        app,
        ["dns", "list"],
        env={
            "SOPHOS_CLI_HOST": "",
            "SOPHOS_CLI_USERNAME": "",
            "SOPHOS_CLI_PASSWORD": "",
        },
    )

    assert result.exit_code == 2


def test_test_connection_success(
    runner: CliRunner,
    connection_args: list[str],
    firewall_client: Any,
) -> None:
    result = runner.invoke(app, ["test-connection", *connection_args])

    assert result.exit_code == 0
    assert "Authentication Successful" in result.stdout
    assert firewall_client.last_call == ("login", {})


def test_test_connection_auth_failure(
    runner: CliRunner,
    connection_args: list[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class AuthFailureClient:
        def login(self, output_format: str = "dict") -> object:
            del output_format
            raise SophosFirewallAuthFailure("invalid credentials")

    def _create_client(_params: ConnectionParams) -> AuthFailureClient:
        return AuthFailureClient()

    monkeypatch.setattr("sophos_cli.command_support.create_client", _create_client)

    result = runner.invoke(app, ["test-connection", *connection_args])

    assert result.exit_code == 1
    assert "Authentication failed: invalid credentials" in result.stdout


def test_get_tag_with_filter_uses_filtered_api_call(
    runner: CliRunner,
    connection_args: list[str],
    firewall_client: Any,
) -> None:
    firewall_client.seed_entry("web-1.example.com", "192.0.2.10")

    result = runner.invoke(
        app,
        [
            "raw",
            "get-tag",
            "DNSHostEntry",
            "--key",
            "HostName",
            "--value",
            "web-1.example.com",
            "--operator",
            "=",
            *connection_args,
        ],
    )

    assert result.exit_code == 0
    assert firewall_client.last_call is not None
    assert firewall_client.last_call[0] == "get_tag_with_filter"


def test_get_tag_handles_api_error(
    runner: CliRunner,
    connection_args: list[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class ApiErrorClient:
        def get_tag(self, xml_tag: str, timeout: int = 30, output_format: str = "dict") -> object:
            del xml_tag, timeout, output_format
            raise SophosFirewallAPIError("request failed")

    def _create_client(_params: ConnectionParams) -> ApiErrorClient:
        return ApiErrorClient()

    monkeypatch.setattr("sophos_cli.command_support.create_client", _create_client)

    result = runner.invoke(app, ["raw", "get-tag", "Network", *connection_args])

    assert result.exit_code == 1
    assert "API request failed: request failed" in result.stdout


def test_dns_get_missing_returns_exit_code_1(
    runner: CliRunner,
    connection_args: list[str],
    firewall_client: Any,
) -> None:
    del firewall_client
    result = runner.invoke(app, ["dns", "get", "missing.example.com", *connection_args])

    assert result.exit_code == 1
    assert "DNS entry 'missing.example.com' not found" in result.stdout


def test_dns_update_rejects_address_options_without_ip(
    runner: CliRunner, connection_args: list[str]
) -> None:
    result = runner.invoke(
        app,
        [
            "dns",
            "update",
            "web-1.example.com",
            "--ttl",
            "120",
            *connection_args,
        ],
    )

    assert result.exit_code == 1
    assert "require --ip-address" in result.stdout


def test_dns_add_many_missing_file_returns_exit_code_1(
    runner: CliRunner,
    connection_args: list[str],
) -> None:
    result = runner.invoke(
        app,
        [
            "dns",
            "create-many",
            "--file",
            "does-not-exist.json",
            *connection_args,
        ],
    )

    assert result.exit_code == 1
    assert "Invalid input" in result.stdout


def test_dns_add_many_partial_failure_returns_exit_code_2(
    runner: CliRunner,
    connection_args: list[str],
    firewall_client: Any,
    tmp_path: Path,
) -> None:
    firewall_client.seed_entry("web-1.example.com", "192.0.2.10")
    source = tmp_path / "entries.json"
    source.write_text(
        (
            '[{"host_name": "web-1.example.com", "ip_address": "192.0.2.11"}, '
            '{"host_name": "api-1.example.com", "ip_address": "192.0.2.20"}]'
        ),
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        [
            "dns",
            "create-many",
            "--file",
            str(source),
            "--continue-on-error",
            *connection_args,
        ],
    )

    assert result.exit_code == 2
    assert "create-many summary: total=2 created=1 updated=0 failed=1" in result.stdout


def test_dns_list_defaults_to_json_when_stdout_is_not_a_tty(
    runner: CliRunner,
    connection_args: list[str],
    firewall_client: Any,
) -> None:
    firewall_client.seed_entry("web-1.example.com", "192.0.2.10")

    result = runner.invoke(app, ["dns", "list", *connection_args])

    assert result.exit_code == 0
    assert '"host_name": "web-1.example.com"' in result.stdout
    assert "DNS Host Entries" not in result.stdout


def test_firewall_rule_list_outputs_valid_json_for_multiline_strings(
    runner: CliRunner,
    connection_args: list[str],
    firewall_client: Any,
) -> None:
    def _get_rule(name: str | None = None) -> dict[str, object]:
        del name
        return {
            "Response": {
                "FirewallRule": {
                    "Name": "Allow Home Assistant",
                    "Description": "Allow Home Assistant to communicate\nwith targets in other zones",
                }
            }
        }

    firewall_client.get_rule = _get_rule

    result = runner.invoke(app, ["firewall", "rule", "list", *connection_args])

    assert result.exit_code == 0
    payload = result.stdout
    assert "Allow Home Assistant to communicate\\nwith targets in other zones" in payload
    assert json.loads(payload)[0]["Description"].startswith("Allow Home Assistant")


def test_user_list_returns_empty_json_array_for_zero_records(
    runner: CliRunner,
    connection_args: list[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class ZeroUserClient:
        def get_user(self, username: str | None = None) -> object:
            del username
            raise SophosFirewallZeroRecords("Number of records Zero.")

    def _create_client(_params: ConnectionParams) -> ZeroUserClient:
        return ZeroUserClient()

    monkeypatch.setattr("sophos_cli.command_support.create_client", _create_client)

    result = runner.invoke(app, ["user", "list", *connection_args])

    assert result.exit_code == 0
    assert result.stdout.strip() == "[]"


def test_dns_create_alias_still_works_for_add(
    runner: CliRunner,
    connection_args: list[str],
    firewall_client: Any,
) -> None:
    del firewall_client

    result = runner.invoke(
        app,
        ["dns", "create", "api-1.example.com", "--ip-address", "192.0.2.20", *connection_args],
    )

    assert result.exit_code == 0
    assert "DNS entry 'api-1.example.com' created" in result.stdout


def test_dns_delete_requires_yes(
    runner: CliRunner,
    connection_args: list[str],
    firewall_client: Any,
) -> None:
    firewall_client.seed_entry("web-1.example.com", "192.0.2.10")

    result = runner.invoke(app, ["dns", "delete", "web-1.example.com", *connection_args])

    assert result.exit_code == 2
    assert "--yes" in result.stdout


def test_network_ip_host_create_and_get(
    runner: CliRunner,
    connection_args: list[str],
    firewall_client: Any,
) -> None:
    create_result = runner.invoke(
        app,
        [
            "network",
            "ip-host",
            "create",
            "branch-office",
            "--ip-address",
            "192.0.2.44",
            *connection_args,
        ],
    )

    assert create_result.exit_code == 0
    assert '"Name": "branch-office"' in create_result.stdout

    get_result = runner.invoke(
        app,
        ["network", "ip-host", "get", "branch-office", *connection_args],
    )

    assert get_result.exit_code == 0
    assert '"IPAddress": "192.0.2.44"' in get_result.stdout


def test_api_generated_command_dispatches_scalar_options(
    runner: CliRunner,
    connection_args: list[str],
    firewall_client: Any,
) -> None:
    firewall_client.create_ip_host(name="web-1", ip_address="192.0.2.10")

    result = runner.invoke(
        app,
        [
            "api",
            "get-ip-host",
            "--name",
            "web-1",
            "--ip-address",
            "192.0.2.10",
            "--operator",
            "=",
            *connection_args,
        ],
    )

    assert result.exit_code == 0
    assert firewall_client.last_call == (
        "get_ip_host",
        {"name": "web-1", "ip_address": "192.0.2.10"},
    )


def test_api_generated_command_parses_json_options(
    runner: CliRunner,
    connection_args: list[str],
    firewall_client: Any,
) -> None:
    result = runner.invoke(
        app,
        [
            "api",
            "create-service",
            "--name",
            "HTTPS",
            "--service-type",
            "TCPorUDP",
            "--service-list-json",
            '[{"protocol":"TCP","dst_port":"443"}]',
            *connection_args,
        ],
    )

    assert result.exit_code == 0
    assert firewall_client.last_call == (
        "create_service",
        {
            "args": [],
            "kwargs": {
                "name": "HTTPS",
                "service_type": "TCPorUDP",
                "service_list": [{"protocol": "TCP", "dst_port": "443"}],
            },
        },
    )


def test_api_generated_command_accepts_extra_json_kwargs(
    runner: CliRunner,
    connection_args: list[str],
    firewall_client: Any,
) -> None:
    result = runner.invoke(
        app,
        [
            "api",
            "create-admin-profile",
            "--name",
            "readonly",
            "--default-permission",
            "Read-Only",
            "--extra-json",
            '{"dashboard":"Read-Only"}',
            *connection_args,
        ],
    )

    assert result.exit_code == 0
    assert firewall_client.last_call == (
        "create_admin_profile",
        {
            "args": [],
            "kwargs": {
                "name": "readonly",
                "default_permission": "Read-Only",
                "dashboard": "Read-Only",
            },
        },
    )


def test_network_ip_host_group_create_uses_member_option(
    runner: CliRunner,
    connection_args: list[str],
    firewall_client: Any,
) -> None:
    firewall_client.create_ip_host(name="web-1", ip_address="192.0.2.10")

    result = runner.invoke(
        app,
        [
            "network",
            "ip-host-group",
            "create",
            "branch-group",
            "--member",
            "web-1",
            "--description",
            "Branch hosts",
            *connection_args,
        ],
    )

    assert result.exit_code == 0
    assert firewall_client.last_call == (
        "create_ip_hostgroup",
        {
            "Name": "branch-group",
            "Description": "Branch hosts",
            "HostList": {"Host": ["web-1"]},
        },
    )


def test_network_ip_host_group_update_uses_member_option(
    runner: CliRunner,
    connection_args: list[str],
    firewall_client: Any,
) -> None:
    firewall_client.create_ip_host(name="web-1", ip_address="192.0.2.10")
    firewall_client.create_ip_host(name="web-2", ip_address="192.0.2.11")
    firewall_client.create_ip_hostgroup(name="branch-group", host_list=["web-1"])

    result = runner.invoke(
        app,
        [
            "network",
            "ip-host-group",
            "update",
            "branch-group",
            "--member",
            "web-2",
            "--action",
            "add",
            *connection_args,
        ],
    )

    assert result.exit_code == 0
    assert firewall_client.last_call == (
        "update_ip_hostgroup",
        {"name": "branch-group", "action": "add", "host_list": ["web-2"]},
    )


def test_network_fqdn_host_group_create_uses_member_option(
    runner: CliRunner,
    connection_args: list[str],
    firewall_client: Any,
) -> None:
    firewall_client.create_fqdn_host(name="app-1", fqdn="app-1.example.com")

    result = runner.invoke(
        app,
        [
            "network",
            "fqdn-host-group",
            "create",
            "apps",
            "--member",
            "app-1",
            "--description",
            "Application hosts",
            *connection_args,
        ],
    )

    assert result.exit_code == 0
    assert firewall_client.last_call == (
        "create_fqdn_hostgroup",
        {
            "Name": "apps",
            "Description": "Application hosts",
            "FQDNHostList": {"FQDNHost": ["app-1"]},
        },
    )


def test_network_fqdn_host_group_update_uses_member_option(
    runner: CliRunner,
    connection_args: list[str],
    firewall_client: Any,
) -> None:
    firewall_client.create_fqdn_host(name="app-1", fqdn="app-1.example.com")
    firewall_client.create_fqdn_host(name="app-2", fqdn="app-2.example.com")
    firewall_client.create_fqdn_hostgroup(name="apps", fqdn_host_list=["app-1"])

    result = runner.invoke(
        app,
        [
            "network",
            "fqdn-host-group",
            "update",
            "apps",
            "--member",
            "app-2",
            "--action",
            "add",
            *connection_args,
        ],
    )

    assert result.exit_code == 0
    assert firewall_client.last_call == (
        "update_fqdn_hostgroup",
        {"name": "apps", "action": "add", "fqdn_host_list": ["app-2"]},
    )


def test_service_create_parses_entry_json(
    runner: CliRunner,
    connection_args: list[str],
    firewall_client: Any,
) -> None:
    result = runner.invoke(
        app,
        [
            "service",
            "create",
            "HTTPS",
            "--service-type",
            "TCPorUDP",
            "--entry-json",
            '{"protocol":"TCP","dst_port":"443"}',
            *connection_args,
        ],
    )

    assert result.exit_code == 0
    assert firewall_client.last_call == (
        "create_service",
        {
            "args": [],
            "kwargs": {
                "name": "HTTPS",
                "service_type": "TCPorUDP",
                "service_list": [{"protocol": "TCP", "dst_port": "443"}],
            },
        },
    )


def test_service_get_uses_services_response_tag(
    runner: CliRunner,
    connection_args: list[str],
    firewall_client: Any,
) -> None:
    def _get_service(
        name: str | None = None,
        operator: str = "=",
        dst_proto: str | None = None,
        dst_port: str | None = None,
    ) -> dict[str, object]:
        del operator, dst_proto, dst_port
        payload: dict[str, object] = {
            "Name": name or "codex-svc",
            "Type": "TCPorUDP",
            "ServiceDetails": {"ServiceDetail": {"Protocol": "TCP", "DestinationPort": "443"}},
        }
        return {"Response": {"Services": payload}}

    firewall_client.get_service = _get_service

    result = runner.invoke(app, ["service", "get", "codex-svc", *connection_args])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["Name"] == "codex-svc"
    assert payload["ServiceDetails"]["ServiceDetail"]["DestinationPort"] == "443"


def test_service_update_passes_action_and_entries(
    runner: CliRunner,
    connection_args: list[str],
    firewall_client: Any,
) -> None:
    result = runner.invoke(
        app,
        [
            "service",
            "update",
            "HTTPS",
            "--service-type",
            "TCPorUDP",
            "--entry-json",
            '{"protocol":"TCP","dst_port":"8443"}',
            "--action",
            "replace",
            *connection_args,
        ],
    )

    assert result.exit_code == 0
    assert firewall_client.last_call == (
        "update_service",
        {
            "args": [],
            "kwargs": {
                "name": "HTTPS",
                "service_type": "TCPorUDP",
                "service_list": [{"protocol": "TCP", "dst_port": "8443"}],
                "action": "replace",
            },
        },
    )


def test_service_delete_uses_services_xml_tag(
    runner: CliRunner,
    connection_args: list[str],
    firewall_client: Any,
) -> None:
    result = runner.invoke(
        app,
        [
            "service",
            "delete",
            "HTTPS-alt",
            "--yes",
            *connection_args,
        ],
    )

    assert result.exit_code == 0
    assert firewall_client.last_call == (
        "remove",
        {
            "xml_tag": "Services",
            "name": "HTTPS-alt",
            "key": "Name",
        },
    )


def test_url_group_get_uses_webfilter_url_group_response_tag(
    runner: CliRunner,
    connection_args: list[str],
    firewall_client: Any,
) -> None:
    def _get_urlgroup(name: str | None = None, operator: str = "=") -> dict[str, object]:
        del operator
        payload: dict[str, object] = {
            "Name": name or "codex-urlgrp",
            "URLlist": {"URL": "example.com"},
        }
        return {"Response": {"WebFilterURLGroup": payload}}

    firewall_client.get_urlgroup = _get_urlgroup

    result = runner.invoke(app, ["service", "url-group", "get", "codex-urlgrp", *connection_args])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["Name"] == "codex-urlgrp"
    assert payload["URLlist"]["URL"] == "example.com"


def test_service_group_create_uses_member_option(
    runner: CliRunner,
    connection_args: list[str],
    firewall_client: Any,
) -> None:
    result = runner.invoke(
        app,
        [
            "service",
            "service-group",
            "create",
            "web-services",
            "--member",
            "HTTPS",
            "--member",
            "HTTP",
            "--description",
            "Web traffic",
            *connection_args,
        ],
    )

    assert result.exit_code == 0
    assert firewall_client.last_call == (
        "create_service_group",
        {
            "args": [],
            "kwargs": {
                "name": "web-services",
                "service_list": ["HTTPS", "HTTP"],
                "description": "Web traffic",
            },
        },
    )


def test_service_group_update_uses_member_option(
    runner: CliRunner,
    connection_args: list[str],
    firewall_client: Any,
) -> None:
    result = runner.invoke(
        app,
        [
            "service",
            "service-group",
            "update",
            "web-services",
            "--member",
            "HTTPS",
            "--action",
            "remove",
            *connection_args,
        ],
    )

    assert result.exit_code == 0
    assert firewall_client.last_call == (
        "update_service_group",
        {
            "args": [],
            "kwargs": {
                "name": "web-services",
                "service_list": ["HTTPS"],
                "action": "remove",
                "description": None,
            },
        },
    )


def test_url_group_create_uses_domain_option(
    runner: CliRunner,
    connection_args: list[str],
    firewall_client: Any,
) -> None:
    result = runner.invoke(
        app,
        [
            "service",
            "url-group",
            "create",
            "allowed-domains",
            "--domain",
            "example.com",
            "--domain",
            "example.org",
            *connection_args,
        ],
    )

    assert result.exit_code == 0
    assert firewall_client.last_call == (
        "create_urlgroup",
        {
            "args": [],
            "kwargs": {
                "name": "allowed-domains",
                "domain_list": ["example.com", "example.org"],
            },
        },
    )


def test_url_group_update_uses_domain_option(
    runner: CliRunner,
    connection_args: list[str],
    firewall_client: Any,
) -> None:
    result = runner.invoke(
        app,
        [
            "service",
            "url-group",
            "update",
            "allowed-domains",
            "--domain",
            "example.net",
            "--action",
            "add",
            *connection_args,
        ],
    )

    assert result.exit_code == 0
    assert firewall_client.last_call == (
        "update_urlgroup",
        {
            "args": [],
            "kwargs": {
                "name": "allowed-domains",
                "domain_list": ["example.net"],
                "action": "add",
            },
        },
    )


def test_firewall_rule_create_passes_json_payload(
    runner: CliRunner,
    connection_args: list[str],
    firewall_client: Any,
) -> None:
    result = runner.invoke(
        app,
        [
            "firewall",
            "rule",
            "create",
            "allow-web",
            "--data",
            '{"action":"Accept","src_zones":["LAN"],"dst_zones":["WAN"],"service_list":["HTTPS"]}',
            *connection_args,
        ],
    )

    assert result.exit_code == 0
    assert firewall_client.last_call == (
        "create_rule",
        {
            "args": [],
            "kwargs": {
                "rule_params": {
                    "rulename": "allow-web",
                    "action": "Accept",
                    "src_zones": ["LAN"],
                    "dst_zones": ["WAN"],
                    "service_list": ["HTTPS"],
                }
            },
        },
    )


def test_firewall_rule_update_preserves_existing_status_when_not_provided(
    runner: CliRunner,
    connection_args: list[str],
    firewall_client: Any,
) -> None:
    def _get_rule(name: str | None = None, operator: str = "=") -> dict[str, object]:
        del operator
        return {
            "Response": {
                "FirewallRule": {
                    "Name": name or "allow-web",
                    "Status": "Disable",
                    "Description": "existing",
                    "NetworkPolicy": {"Action": "Accept", "LogTraffic": "Disable"},
                }
            }
        }

    def _update_rule(name: str, rule_params: dict[str, object], debug: bool = False) -> dict[str, object]:
        del debug
        firewall_client.last_call = ("update_rule", {"name": name, "rule_params": rule_params})
        return {"Response": {"FirewallRule": {"Name": name}}}

    firewall_client.get_rule = _get_rule
    firewall_client.update_rule = _update_rule

    result = runner.invoke(
        app,
        [
            "firewall",
            "rule",
            "update",
            "allow-web",
            "--data",
            '{"description":"updated"}',
            *connection_args,
        ],
    )

    assert result.exit_code == 0
    assert firewall_client.last_call == (
        "update_rule",
        {"name": "allow-web", "rule_params": {"description": "updated", "status": "Disable"}},
    )


def test_firewall_acl_rule_update_passes_json_payload(
    runner: CliRunner,
    connection_args: list[str],
    firewall_client: Any,
) -> None:
    result = runner.invoke(
        app,
        [
            "firewall",
            "acl-rule",
            "update",
            "admin-access",
            "--data",
            '{"action":"Drop","update_action":"replace"}',
            *connection_args,
        ],
    )

    assert result.exit_code == 0
    assert firewall_client.last_call == (
        "update_acl_rule",
        {
            "args": [],
            "kwargs": {
                "name": "admin-access",
                "action": "Drop",
                "update_action": "replace",
            },
        },
    )


def test_zone_create_passes_zone_type_and_payload(
    runner: CliRunner,
    connection_args: list[str],
    firewall_client: Any,
) -> None:
    result = runner.invoke(
        app,
        [
            "zone",
            "create",
            "branch",
            "--zone-type",
            "LAN",
            "--data",
            '{"description":"Branch LAN"}',
            *connection_args,
        ],
    )

    assert result.exit_code == 0
    assert firewall_client.last_call == (
        "create_zone",
        {
            "args": [],
            "kwargs": {
                "name": "branch",
                "zone_type": "LAN",
                "zone_params": {"description": "Branch LAN"},
            },
        },
    )


def test_admin_profile_create_passes_kwargs_payload(
    runner: CliRunner,
    connection_args: list[str],
    firewall_client: Any,
) -> None:
    result = runner.invoke(
        app,
        [
            "admin",
            "profile",
            "create",
            "readonly",
            "--data",
            '{"default_permission":"Read-Only","dashboard":"Read-Only"}',
            *connection_args,
        ],
    )

    assert result.exit_code == 0
    assert firewall_client.last_call == (
        "create_admin_profile",
        {
            "args": [],
            "kwargs": {
                "name": "readonly",
                "default_permission": "Read-Only",
                "dashboard": "Read-Only",
            },
        },
    )


def test_system_backup_update_passes_backup_payload(
    runner: CliRunner,
    connection_args: list[str],
    firewall_client: Any,
) -> None:
    result = runner.invoke(
        app,
        [
            "system",
            "backup",
            "update",
            "--data",
            '{"BackupMode":"Local","BackupFrequency":"Daily"}',
            *connection_args,
        ],
    )

    assert result.exit_code == 0
    assert firewall_client.last_call == (
        "update_backup",
        {
            "args": [],
            "kwargs": {
                "backup_params": {"BackupMode": "Local", "BackupFrequency": "Daily"},
            },
        },
    )


def test_user_create_passes_username_and_payload(
    runner: CliRunner,
    connection_args: list[str],
    firewall_client: Any,
) -> None:
    result = runner.invoke(
        app,
        [
            "user",
            "create",
            "alice",
            "--data",
            '{"name":"Alice","user_password":"secret","profile":"Default"}',
            *connection_args,
        ],
    )

    assert result.exit_code == 0
    assert firewall_client.last_call == (
        "create_user",
        {
            "args": [],
            "kwargs": {
                "user": "alice",
                "name": "Alice",
                "user_password": "secret",
                "profile": "Default",
            },
        },
    )


def test_user_delete_uses_name_lookup_key(
    runner: CliRunner,
    connection_args: list[str],
    firewall_client: Any,
) -> None:
    result = runner.invoke(
        app,
        [
            "user",
            "delete",
            "alice",
            "--yes",
            *connection_args,
        ],
    )

    assert result.exit_code == 0
    assert firewall_client.last_call == (
        "remove",
        {
            "xml_tag": "User",
            "name": "alice",
            "key": "Name",
        },
    )


def test_webfilter_policy_create_passes_payload(
    runner: CliRunner,
    connection_args: list[str],
    firewall_client: Any,
) -> None:
    result = runner.invoke(
        app,
        [
            "webfilter",
            "policy",
            "create",
            "default-policy",
            "--data",
            '{"default_action":"Allow"}',
            *connection_args,
        ],
    )

    assert result.exit_code == 0
    assert firewall_client.last_call == (
        "create_webfilterpolicy",
        {
            "args": [],
            "kwargs": {
                "name": "default-policy",
                "default_action": "Allow",
            },
        },
    )


def test_webfilter_user_activity_create_passes_payload(
    runner: CliRunner,
    connection_args: list[str],
    firewall_client: Any,
) -> None:
    result = runner.invoke(
        app,
        [
            "webfilter",
            "user-activity",
            "create",
            "restricted-browsing",
            "--data",
            '{"category_list":[{"id":"Streaming Media","type":"web category"}]}',
            *connection_args,
        ],
    )

    assert result.exit_code == 0
    assert firewall_client.last_call == (
        "create_useractivity",
        {
            "args": [],
            "kwargs": {
                "name": "restricted-browsing",
                "category_list": [{"id": "Streaming Media", "type": "web category"}],
            },
        },
    )
