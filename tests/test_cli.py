from typer.testing import CliRunner

from sophos_cli.cli import app

runner = CliRunner()


def test_help_shows_available_commands() -> None:
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "test-connection" in result.stdout
    assert "get-tag" in result.stdout
