from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from sophosfirewall_python.api_client import SophosFirewallAPIError, SophosFirewallAuthFailure
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

    monkeypatch.setattr("sophos_cli.cli.create_client", _create_client)

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

    monkeypatch.setattr("sophos_cli.cli.create_client", _create_client)

    result = runner.invoke(app, ["get-tag", "Network", *connection_args])

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
            "add-many",
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
            "add-many",
            "--file",
            str(source),
            "--continue-on-error",
            *connection_args,
        ],
    )

    assert result.exit_code == 2
    assert "add-many summary: total=2 created=1 updated=0 failed=1" in result.stdout
