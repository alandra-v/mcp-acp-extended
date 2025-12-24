"""Interactive prompt helpers for CLI commands.

Provides reusable prompt utilities for gathering user input.
"""

import click

from mcp_acp_extended.config import HttpTransportConfig, StdioTransportConfig
from mcp_acp_extended.constants import DEFAULT_HTTP_TIMEOUT_SECONDS, HEALTH_CHECK_TIMEOUT_SECONDS
from mcp_acp_extended.utils.transport import check_http_health


def prompt_with_retry(prompt_text: str) -> str:
    """Prompt for a required value, retrying if empty.

    Args:
        prompt_text: Text to show in prompt.

    Returns:
        Non-empty string value from user.
    """
    while True:
        value: str = click.prompt(prompt_text, type=str, default="", show_default=False)
        if value.strip():
            return value.strip()
        click.echo("  This field is required.")


def prompt_optional(prompt_text: str, default: str = "") -> str:
    """Prompt for an optional value with default.

    Args:
        prompt_text: Text to show in prompt.
        default: Default value if user presses enter.

    Returns:
        String value from user or default.
    """
    value: str = click.prompt(prompt_text, type=str, default=default, show_default=True)
    return value.strip()


def prompt_stdio_config() -> StdioTransportConfig:
    """Prompt for STDIO transport configuration.

    Returns:
        StdioTransportConfig with user-provided values.
    """
    click.echo("\n[STDIO Configuration]")
    command = prompt_with_retry("Command to run")
    args_str = prompt_with_retry("Arguments (comma-separated)")
    args_list = [arg.strip() for arg in args_str.split(",") if arg.strip()]
    return StdioTransportConfig(command=command, args=args_list)


def prompt_http_config() -> HttpTransportConfig:
    """Prompt for HTTP transport configuration and test connectivity.

    Returns:
        HttpTransportConfig with user-provided values.

    Raises:
        click.Abort: If user aborts after connection failure.
    """
    click.echo("\n[HTTP Configuration]")

    while True:
        url = prompt_with_retry("Server URL")
        timeout_str = prompt_optional("Connection timeout (seconds)", str(DEFAULT_HTTP_TIMEOUT_SECONDS))
        try:
            timeout = int(timeout_str)
        except ValueError:
            click.echo(f"  Invalid timeout, using default {DEFAULT_HTTP_TIMEOUT_SECONDS}")
            timeout = DEFAULT_HTTP_TIMEOUT_SECONDS

        # Test connection
        click.echo(f"\nTesting connection to {url}...")
        try:
            check_http_health(url, timeout=min(timeout, HEALTH_CHECK_TIMEOUT_SECONDS))
            click.echo("Server is reachable!")
            return HttpTransportConfig(url=url, timeout=timeout)
        except Exception:
            click.echo(f"\nHealth check failed: could not reach {url}")
            click.echo("What would you like to do?")
            click.echo("  1. Continue anyway - save this configuration")
            click.echo("  2. Reconfigure - enter a different URL")
            click.echo("  3. Cancel - abort setup")
            choice = click.prompt("Select an option", type=click.IntRange(1, 3), default=1)
            if choice == 1:
                return HttpTransportConfig(url=url, timeout=timeout)
            elif choice == 3:
                raise click.Abort()
            # choice == 2: loop continues
