"""Main CLI entry point for mcp-acp-extended.

Defines the CLI group and registers all subcommands.

Commands:
    auth    - Authentication commands (login, logout, status)
    init    - Initialize proxy configuration (interactive or with flags)
    start   - Start the proxy server manually (for testing)
    config  - Configuration management commands
        show - Display current configuration
        path - Show config file path
        edit - Edit configuration in $EDITOR

Usage:
    mcp-acp-extended -h, --help      Show help message
    mcp-acp-extended -v, --version   Show version
    mcp-acp-extended auth login      Authenticate via browser (Device Flow)
    mcp-acp-extended auth logout     Clear stored credentials
    mcp-acp-extended auth status     Show authentication status
    mcp-acp-extended init            Initialize configuration
    mcp-acp-extended start           Start proxy server
    mcp-acp-extended config show     Display configuration
    mcp-acp-extended config path     Show config file path
    mcp-acp-extended config edit     Edit configuration in $EDITOR

Subcommand help:
    mcp-acp-extended COMMAND -h      Show help for a specific command
"""

import sys

import click

from mcp_acp_extended import __version__

from .commands.auth import auth
from .commands.config import config
from .commands.init import init
from .commands.start import start


class ReorderedGroup(click.Group):
    """Custom group that shows commands before custom help text."""

    def format_epilog(self, ctx: click.Context, formatter: click.HelpFormatter) -> None:
        """Add extra help after commands section."""
        formatter.write(
            """
Quick Start:
  mcp-acp-extended init                     Interactive setup wizard
  mcp-acp-extended start                    Test the proxy manually

Non-Interactive Setup (stdio):
  mcp-acp-extended init --non-interactive \\
    --server-name my-server \\
    --connection-type stdio \\
    --command npx \\
    --args "-y,@modelcontextprotocol/server-filesystem,/tmp"

Non-Interactive Setup (both transports):
  mcp-acp-extended init --non-interactive \\
    --server-name my-server \\
    --connection-type both \\
    --command npx \\
    --args "-y,@modelcontextprotocol/server-filesystem,/tmp" \\
    --url http://localhost:3010/mcp

Connection Types (--connection-type):
  stdio   Spawn local server process (npx, uvx, python)
  http    Connect to remote HTTP server (requires --url)
  both    Auto-detect: tries HTTP first, falls back to STDIO
"""
        )


@click.group(
    cls=ReorderedGroup,
    invoke_without_command=True,
    context_settings={"help_option_names": ["-h", "--help"]},
)
@click.option("--version", "-v", is_flag=True, help="Show version")
@click.pass_context
def cli(ctx: click.Context, version: bool) -> None:
    """mcp-acp-extended: Zero Trust Access Control Proxy for MCP."""
    if version:
        click.echo(f"mcp-acp-extended {__version__}")
        sys.exit(0)
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


# Register commands
cli.add_command(auth)
cli.add_command(init)
cli.add_command(start)
cli.add_command(config)


def main() -> None:
    """CLI entry point."""
    cli()
