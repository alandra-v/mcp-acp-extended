"""Unit tests for logs command.

Tests CLI behavior using Click's CliRunner for isolated, fast testing.
Tests use the AAA pattern (Arrange-Act-Assert) for clarity.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from mcp_acp_extended.cli import cli


@pytest.fixture
def runner() -> CliRunner:
    """Create a CLI runner for testing."""
    return CliRunner()


@pytest.fixture
def sample_decisions_log() -> str:
    """Return sample decision log entries."""
    entries = [
        {
            "timestamp": "2024-01-15T10:30:00Z",
            "effect": "ALLOW",
            "tool_name": "read_file",
            "matched_rule": {"id": "rule-1"},
        },
        {
            "timestamp": "2024-01-15T10:30:05Z",
            "effect": "DENY",
            "tool_name": "bash",
            "matched_rule": {"id": "rule-2"},
        },
        {
            "timestamp": "2024-01-15T10:30:10Z",
            "effect": "HITL",
            "tool_name": "write_file",
            "matched_rule": {"id": "rule-3"},
        },
    ]
    return "\n".join(json.dumps(e) for e in entries)


@pytest.fixture
def sample_system_log() -> str:
    """Return sample system log entries."""
    entries = [
        {
            "timestamp": "2024-01-15T10:30:00Z",
            "level": "INFO",
            "message": "Proxy started",
        },
        {
            "timestamp": "2024-01-15T10:30:05Z",
            "level": "WARNING",
            "message": "Rate limit approaching",
        },
        {
            "timestamp": "2024-01-15T10:30:10Z",
            "level": "ERROR",
            "message": "Connection failed",
        },
    ]
    return "\n".join(json.dumps(e) for e in entries)


@pytest.fixture
def mock_config():
    """Create a mock config object."""
    config = MagicMock()
    config.logging.log_dir = "/tmp/test-logs"
    return config


class TestLogsShowCommand:
    """Tests for logs show command."""

    def test_show_displays_recent_entries(
        self, runner: CliRunner, sample_decisions_log: str, mock_config: MagicMock
    ):
        """Given log file exists, shows recent entries."""
        # Arrange
        with runner.isolated_filesystem() as tmpdir:
            log_path = Path(tmpdir) / "decisions.jsonl"
            log_path.write_text(sample_decisions_log)

            with patch(
                "mcp_acp_extended.cli.commands.logs._load_config",
                return_value=mock_config,
            ):
                with patch(
                    "mcp_acp_extended.cli.commands.logs._get_log_path",
                    return_value=log_path,
                ):
                    # Act
                    result = runner.invoke(cli, ["logs", "show"])

        # Assert
        assert result.exit_code == 0
        assert "read_file" in result.output
        assert "bash" in result.output
        assert "write_file" in result.output

    def test_show_formats_effects_with_colors(
        self, runner: CliRunner, sample_decisions_log: str, mock_config: MagicMock
    ):
        """Given decision entries, formats effects appropriately."""
        # Arrange
        with runner.isolated_filesystem() as tmpdir:
            log_path = Path(tmpdir) / "decisions.jsonl"
            log_path.write_text(sample_decisions_log)

            with patch(
                "mcp_acp_extended.cli.commands.logs._load_config",
                return_value=mock_config,
            ):
                with patch(
                    "mcp_acp_extended.cli.commands.logs._get_log_path",
                    return_value=log_path,
                ):
                    # Act
                    result = runner.invoke(cli, ["logs", "show"])

        # Assert
        assert result.exit_code == 0
        assert "ALLOW" in result.output
        assert "DENY" in result.output
        assert "HITL" in result.output

    def test_show_respects_limit(self, runner: CliRunner, sample_decisions_log: str, mock_config: MagicMock):
        """Given --limit flag, shows only that many entries."""
        # Arrange
        with runner.isolated_filesystem() as tmpdir:
            log_path = Path(tmpdir) / "decisions.jsonl"
            log_path.write_text(sample_decisions_log)

            with patch(
                "mcp_acp_extended.cli.commands.logs._load_config",
                return_value=mock_config,
            ):
                with patch(
                    "mcp_acp_extended.cli.commands.logs._get_log_path",
                    return_value=log_path,
                ):
                    # Act
                    result = runner.invoke(cli, ["logs", "show", "--limit=1"])

        # Assert
        assert result.exit_code == 0
        assert "last 1 entries" in result.output

    def test_show_system_log_type(self, runner: CliRunner, sample_system_log: str, mock_config: MagicMock):
        """Given --type=system, shows system log entries."""
        # Arrange
        with runner.isolated_filesystem() as tmpdir:
            log_path = Path(tmpdir) / "system.jsonl"
            log_path.write_text(sample_system_log)

            with patch(
                "mcp_acp_extended.cli.commands.logs._load_config",
                return_value=mock_config,
            ):
                with patch(
                    "mcp_acp_extended.cli.commands.logs._get_log_path",
                    return_value=log_path,
                ):
                    # Act
                    result = runner.invoke(cli, ["logs", "show", "--type=system"])

        # Assert
        assert result.exit_code == 0
        assert "System logs" in result.output
        assert "Proxy started" in result.output
        assert "Rate limit approaching" in result.output

    def test_show_missing_log_file(self, runner: CliRunner, mock_config: MagicMock):
        """Given missing log file, shows appropriate message."""
        # Arrange
        with runner.isolated_filesystem() as tmpdir:
            log_path = Path(tmpdir) / "nonexistent.jsonl"

            with patch(
                "mcp_acp_extended.cli.commands.logs._load_config",
                return_value=mock_config,
            ):
                with patch(
                    "mcp_acp_extended.cli.commands.logs._get_log_path",
                    return_value=log_path,
                ):
                    # Act
                    result = runner.invoke(cli, ["logs", "show"])

        # Assert
        assert result.exit_code == 0
        assert "not found" in result.output.lower()
        assert "not have written any logs yet" in result.output

    def test_show_empty_log_file(self, runner: CliRunner, mock_config: MagicMock):
        """Given empty log file, shows appropriate message."""
        # Arrange
        with runner.isolated_filesystem() as tmpdir:
            log_path = Path(tmpdir) / "decisions.jsonl"
            log_path.write_text("")

            with patch(
                "mcp_acp_extended.cli.commands.logs._load_config",
                return_value=mock_config,
            ):
                with patch(
                    "mcp_acp_extended.cli.commands.logs._get_log_path",
                    return_value=log_path,
                ):
                    # Act
                    result = runner.invoke(cli, ["logs", "show"])

        # Assert
        assert result.exit_code == 0
        assert "No entries" in result.output

    def test_show_missing_config(self, runner: CliRunner):
        """Given missing config file, shows error."""
        # Arrange
        with runner.isolated_filesystem():
            with patch(
                "mcp_acp_extended.cli.commands.logs.get_config_path",
                return_value=Path("nonexistent.json"),
            ):
                # Act
                result = runner.invoke(cli, ["logs", "show"])

        # Assert
        assert result.exit_code == 1
        assert "not found" in result.output.lower() or "Configuration" in result.output


class TestLogsShowJsonOutput:
    """Tests for logs show --json flag."""

    def test_show_json_outputs_raw_jsonl(
        self, runner: CliRunner, sample_decisions_log: str, mock_config: MagicMock
    ):
        """Given --json flag, outputs raw JSONL."""
        # Arrange
        with runner.isolated_filesystem() as tmpdir:
            log_path = Path(tmpdir) / "decisions.jsonl"
            log_path.write_text(sample_decisions_log)

            with patch(
                "mcp_acp_extended.cli.commands.logs._load_config",
                return_value=mock_config,
            ):
                with patch(
                    "mcp_acp_extended.cli.commands.logs._get_log_path",
                    return_value=log_path,
                ):
                    # Act
                    result = runner.invoke(cli, ["logs", "show", "--json"])

        # Assert
        assert result.exit_code == 0
        # Each line should be valid JSON
        lines = [line for line in result.output.strip().split("\n") if line]
        for line in lines:
            data = json.loads(line)
            assert "timestamp" in data

    def test_show_json_preserves_all_fields(
        self, runner: CliRunner, sample_decisions_log: str, mock_config: MagicMock
    ):
        """Given --json flag, preserves all log fields."""
        # Arrange
        with runner.isolated_filesystem() as tmpdir:
            log_path = Path(tmpdir) / "decisions.jsonl"
            log_path.write_text(sample_decisions_log)

            with patch(
                "mcp_acp_extended.cli.commands.logs._load_config",
                return_value=mock_config,
            ):
                with patch(
                    "mcp_acp_extended.cli.commands.logs._get_log_path",
                    return_value=log_path,
                ):
                    # Act
                    result = runner.invoke(cli, ["logs", "show", "--json"])

        # Assert
        lines = [line for line in result.output.strip().split("\n") if line]
        first_entry = json.loads(lines[0])
        assert "effect" in first_entry
        assert "tool_name" in first_entry
        assert "matched_rule" in first_entry


class TestLogsTailCommand:
    """Tests for logs tail command."""

    def test_tail_help_shows_options(self, runner: CliRunner):
        """Given logs tail --help, shows options."""
        # Act
        result = runner.invoke(cli, ["logs", "tail", "--help"])

        # Assert
        assert result.exit_code == 0
        assert "--type" in result.output
        assert "--json" in result.output

    def test_tail_missing_config(self, runner: CliRunner):
        """Given missing config file, shows error."""
        # Arrange
        with runner.isolated_filesystem():
            with patch(
                "mcp_acp_extended.cli.commands.logs.get_config_path",
                return_value=Path("nonexistent.json"),
            ):
                # Act
                result = runner.invoke(cli, ["logs", "tail"])

        # Assert
        assert result.exit_code == 1
        assert "not found" in result.output.lower() or "Configuration" in result.output


class TestLogsHelp:
    """Tests for logs command help."""

    def test_logs_help_shows_subcommands(self, runner: CliRunner):
        """Given logs --help, shows available subcommands."""
        # Act
        result = runner.invoke(cli, ["logs", "--help"])

        # Assert
        assert result.exit_code == 0
        assert "show" in result.output
        assert "tail" in result.output

    def test_logs_show_help_shows_options(self, runner: CliRunner):
        """Given logs show --help, shows options."""
        # Act
        result = runner.invoke(cli, ["logs", "show", "--help"])

        # Assert
        assert result.exit_code == 0
        assert "--type" in result.output
        assert "--limit" in result.output
        assert "--json" in result.output


class TestLogsTypeValidation:
    """Tests for log type validation."""

    def test_show_invalid_type_shows_error(self, runner: CliRunner):
        """Given invalid log type, shows error."""
        # Act
        result = runner.invoke(cli, ["logs", "show", "--type=invalid"])

        # Assert
        assert result.exit_code == 2
        assert "invalid" in result.output.lower()

    @pytest.mark.parametrize("log_type", ["decisions", "operations", "auth", "system"])
    def test_show_valid_types_accepted(self, runner: CliRunner, log_type: str, mock_config: MagicMock):
        """Given valid log types, command proceeds."""
        # Arrange
        with runner.isolated_filesystem() as tmpdir:
            log_path = Path(tmpdir) / f"{log_type}.jsonl"
            log_path.write_text("")

            with patch(
                "mcp_acp_extended.cli.commands.logs._load_config",
                return_value=mock_config,
            ):
                with patch(
                    "mcp_acp_extended.cli.commands.logs._get_log_path",
                    return_value=log_path,
                ):
                    # Act
                    result = runner.invoke(cli, ["logs", "show", f"--type={log_type}"])

        # Assert - should not fail due to invalid type
        assert result.exit_code == 0
