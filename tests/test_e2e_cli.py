from __future__ import annotations

import json
import os
from typing import cast

import pytest
from typer.testing import CliRunner

from sophos_cli.cli import app


def _e2e_env() -> dict[str, str]:
    host = os.getenv("SOPHOS_CLI_E2E_HOST")
    port = os.getenv("SOPHOS_CLI_E2E_PORT")
    username = os.getenv("SOPHOS_CLI_E2E_USERNAME")
    password = os.getenv("SOPHOS_CLI_E2E_PASSWORD")

    if not all([host, port, username, password]):
        pytest.skip("Live Sophos E2E credentials are not configured.")

    return {
        "SOPHOS_CLI_HOST": cast(str, host),
        "SOPHOS_CLI_PORT": cast(str, port),
        "SOPHOS_CLI_USERNAME": cast(str, username),
        "SOPHOS_CLI_PASSWORD": cast(str, password),
        "SOPHOS_CLI_VERIFY_SSL": "false",
    }


@pytest.mark.e2e
def test_e2e_raw_get_tag_smoke(runner: CliRunner) -> None:
    result = runner.invoke(app, ["raw", "get-tag", "DNSHostEntry"], env=_e2e_env())

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert "Response" in payload


@pytest.mark.e2e
def test_e2e_dns_list_defaults_to_json(runner: CliRunner) -> None:
    result = runner.invoke(app, ["dns", "list"], env=_e2e_env())

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert isinstance(payload, list)


@pytest.mark.e2e
def test_e2e_network_ip_host_list_smoke(runner: CliRunner) -> None:
    result = runner.invoke(app, ["network", "ip-host", "list"], env=_e2e_env())

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert isinstance(payload, list)


@pytest.mark.e2e
def test_e2e_service_list_smoke(runner: CliRunner) -> None:
    result = runner.invoke(app, ["service", "list"], env=_e2e_env())

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert isinstance(payload, list)


@pytest.mark.e2e
def test_e2e_firewall_rule_list_smoke(runner: CliRunner) -> None:
    result = runner.invoke(app, ["firewall", "rule", "list"], env=_e2e_env())

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert isinstance(payload, list)


@pytest.mark.e2e
def test_e2e_zone_list_smoke(runner: CliRunner) -> None:
    result = runner.invoke(app, ["zone", "list"], env=_e2e_env())

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert isinstance(payload, list)


@pytest.mark.e2e
def test_e2e_admin_profile_list_smoke(runner: CliRunner) -> None:
    result = runner.invoke(app, ["admin", "profile", "list"], env=_e2e_env())

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert isinstance(payload, list)


@pytest.mark.e2e
def test_e2e_system_backup_get_smoke(runner: CliRunner) -> None:
    result = runner.invoke(app, ["system", "backup", "get"], env=_e2e_env())

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert isinstance(payload, dict)
    assert "BackupRestore" in payload


@pytest.mark.e2e
def test_e2e_user_list_smoke(runner: CliRunner) -> None:
    result = runner.invoke(app, ["user", "list"], env=_e2e_env())

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert isinstance(payload, list)


@pytest.mark.e2e
def test_e2e_webfilter_policy_list_smoke(runner: CliRunner) -> None:
    result = runner.invoke(app, ["webfilter", "policy", "list"], env=_e2e_env())

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert isinstance(payload, list)
