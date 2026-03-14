from typer.testing import CliRunner

from sophos_cli.cli import app


def test_help_shows_available_commands(runner: CliRunner) -> None:
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "test-connection" in result.stdout
    assert "api" in result.stdout
    assert "dns" in result.stdout
    assert "network" in result.stdout
    assert "service" in result.stdout
    assert "firewall" in result.stdout
    assert "zone" in result.stdout
    assert "admin" in result.stdout
    assert "user" in result.stdout
    assert "webfilter" in result.stdout
    assert "system" in result.stdout
    assert "get-tag" not in result.stdout
    assert "raw" not in result.stdout


def test_dns_help_shows_expected_subcommands(runner: CliRunner) -> None:
    result = runner.invoke(app, ["dns", "--help"])

    assert result.exit_code == 0
    assert "create" in result.stdout
    assert "list" in result.stdout
    assert "get" in result.stdout
    assert "update" in result.stdout
    assert "delete" in result.stdout
    assert "create-many" in result.stdout
    assert "update-many" in result.stdout


def test_dns_create_many_help_shows_input_examples(runner: CliRunner) -> None:
    result = runner.invoke(app, ["dns", "create-many", "--help"])

    assert result.exit_code == 0
    assert "Input examples:" in result.stdout
    assert '"host_name": "web-1.example.com"' in result.stdout
    assert "host_name,ip_address,ip_family,entry_type" in result.stdout
    assert "Use `dns add-many` only for backward compatibility." in result.stdout


def test_dns_update_many_help_shows_input_examples(runner: CliRunner) -> None:
    result = runner.invoke(app, ["dns", "update-many", "--help"])

    assert result.exit_code == 0
    assert "Input examples:" in result.stdout
    assert '"add_reverse_dns_lookup": true' in result.stdout
    assert "host_name,ip_address,ip_family,entry_type" in result.stdout


def test_api_help_shows_generated_sdk_commands(runner: CliRunner) -> None:
    result = runner.invoke(app, ["api", "--help"])

    assert result.exit_code == 0
    assert "get-ip-host" in result.stdout
    assert "create-ip-host" in result.stdout
    assert "create-admin-profile" in result.stdout
    assert "remove" in result.stdout


def test_api_method_help_shows_expected_options(runner: CliRunner) -> None:
    result = runner.invoke(app, ["api", "get-ip-host", "--help"])

    assert result.exit_code == 0
    assert "--name" in result.stdout
    assert "--ip-address" in result.stdout
    assert "--operator" in result.stdout


def test_network_help_shows_wave_one_subcommands(runner: CliRunner) -> None:
    result = runner.invoke(app, ["network", "--help"])

    assert result.exit_code == 0
    assert "ip-host" in result.stdout
    assert "ip-host-group" in result.stdout
    assert "ip-network" in result.stdout
    assert "ip-range" in result.stdout
    assert "fqdn-host" in result.stdout
    assert "fqdn-host-group" in result.stdout


def test_service_help_shows_expected_subcommands(runner: CliRunner) -> None:
    result = runner.invoke(app, ["service", "--help"])

    assert result.exit_code == 0
    assert "list" in result.stdout
    assert "get" in result.stdout
    assert "create" in result.stdout
    assert "update" in result.stdout
    assert "delete" in result.stdout
    assert "service-group" in result.stdout
    assert "url-group" in result.stdout


def test_firewall_help_shows_expected_subcommands(runner: CliRunner) -> None:
    result = runner.invoke(app, ["firewall", "--help"])

    assert result.exit_code == 0
    assert "rule" in result.stdout
    assert "rule-group" in result.stdout
    assert "acl-rule" in result.stdout


def test_zone_help_shows_expected_subcommands(runner: CliRunner) -> None:
    result = runner.invoke(app, ["zone", "--help"])

    assert result.exit_code == 0
    assert "list" in result.stdout
    assert "get" in result.stdout
    assert "create" in result.stdout
    assert "update" in result.stdout
    assert "delete" in result.stdout
    assert "interface" in result.stdout
    assert "vlan" in result.stdout
    assert "dns-forwarders" in result.stdout


def test_admin_system_user_webfilter_help_shows_expected_subcommands(runner: CliRunner) -> None:
    admin_result = runner.invoke(app, ["admin", "--help"])
    system_result = runner.invoke(app, ["system", "--help"])
    user_result = runner.invoke(app, ["user", "--help"])
    webfilter_result = runner.invoke(app, ["webfilter", "--help"])

    assert admin_result.exit_code == 0
    assert "profile" in admin_result.stdout
    assert "authen" in admin_result.stdout
    assert "settings" in admin_result.stdout

    assert system_result.exit_code == 0
    assert "backup" in system_result.stdout
    assert "notification" in system_result.stdout
    assert "notification-list" in system_result.stdout
    assert "reports-retention" in system_result.stdout

    assert user_result.exit_code == 0
    assert "create" in user_result.stdout
    assert "update-password" in user_result.stdout

    assert webfilter_result.exit_code == 0
    assert "policy" in webfilter_result.stdout
    assert "user-activity" in webfilter_result.stdout


def test_network_group_help_uses_member_option(runner: CliRunner) -> None:
    ip_group_result = runner.invoke(app, ["network", "ip-host-group", "create", "--help"])
    fqdn_group_result = runner.invoke(app, ["network", "fqdn-host-group", "create", "--help"])

    assert ip_group_result.exit_code == 0
    assert "--member" in ip_group_result.stdout
    assert "--host" in ip_group_result.stdout

    assert fqdn_group_result.exit_code == 0
    assert "--member" in fqdn_group_result.stdout
    assert "--host" in fqdn_group_result.stdout
