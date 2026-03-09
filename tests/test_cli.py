from typer.testing import CliRunner

from sophos_cli.cli import app


def test_help_shows_available_commands(runner: CliRunner) -> None:
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "test-connection" in result.stdout
    assert "get-tag" in result.stdout
    assert "api" in result.stdout
    assert "dns" in result.stdout


def test_dns_help_shows_expected_subcommands(runner: CliRunner) -> None:
    result = runner.invoke(app, ["dns", "--help"])

    assert result.exit_code == 0
    assert "add" in result.stdout
    assert "list" in result.stdout
    assert "get" in result.stdout
    assert "update" in result.stdout
    assert "add-many" in result.stdout
    assert "update-many" in result.stdout


def test_dns_add_many_help_shows_input_examples(runner: CliRunner) -> None:
    result = runner.invoke(app, ["dns", "add-many", "--help"])

    assert result.exit_code == 0
    assert "Input examples:" in result.stdout
    assert '"host_name": "web-1.example.com"' in result.stdout
    assert "host_name,ip_address,ip_family,entry_type" in result.stdout


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
