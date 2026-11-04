"""Tests for TRIPWIRE CLI entrypoint."""

from typer.testing import CliRunner

from backend.cli import app

runner = CliRunner()


def test_cli_version() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "TRIPWIRE version 0.0.1" in result.stdout


def test_cli_status() -> None:
    result = runner.invoke(app, ["status"])
    assert result.exit_code == 0
    assert "System Status: Operational" in result.stdout
