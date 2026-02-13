from typer.testing import CliRunner

from sophos_cli.cli import app

runner = CliRunner()


def test_help_shows_available_commands() -> None:
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "test-connection" in result.stdout
    assert "get-tag" in result.stdout
    assert "dns" in result.stdout


def test_dns_help_shows_expected_subcommands() -> None:
    result = runner.invoke(app, ["dns", "--help"])

    assert result.exit_code == 0
    assert "add" in result.stdout
    assert "list" in result.stdout
    assert "get" in result.stdout
    assert "update" in result.stdout
    assert "add-many" in result.stdout
    assert "update-many" in result.stdout
