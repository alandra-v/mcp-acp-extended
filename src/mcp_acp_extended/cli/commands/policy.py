"""Policy command group for mcp-acp-extended CLI.

Provides policy management subcommands.
"""

import sys
from pathlib import Path

import click
import httpx

from mcp_acp_extended.constants import DEFAULT_API_PORT
from mcp_acp_extended.utils.policy import get_policy_path, load_policy


@click.group()
def policy() -> None:
    """Policy management commands."""
    pass


@policy.command("validate")
@click.option(
    "--path",
    "-p",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Path to policy file (default: OS config location)",
)
def policy_validate(path: Path | None) -> None:
    """Validate policy file.

    Checks the policy file for:
    - Valid JSON syntax
    - Schema validation (conditions, effects, rule structure)
    - At least one condition per rule (security requirement)

    Exit codes:
        0: Policy is valid
        1: Policy is invalid or not found
    """
    policy_path = path or get_policy_path()

    try:
        policy_config = load_policy(policy_path)
        rule_count = len(policy_config.rules)
        click.echo(f"✓ Policy valid: {policy_path}")
        click.echo(f"  {rule_count} rule{'s' if rule_count != 1 else ''} defined")
        click.echo(f"  Default action: {policy_config.default_action}")
        click.echo(f"  HITL timeout: {policy_config.hitl.timeout_seconds}s")
    except (FileNotFoundError, ValueError) as e:
        click.echo(f"✗ {e}", err=True)
        sys.exit(1)


@policy.command("path")
def policy_path_cmd() -> None:
    """Show policy file path.

    Displays the OS-appropriate policy file location.
    """
    path = get_policy_path()
    click.echo(str(path))

    if not path.exists():
        click.echo("(file does not exist - run 'mcp-acp-extended init' to create)", err=True)


@policy.command("reload")
def policy_reload() -> None:
    """Reload policy in running proxy.

    Validates and applies the current policy.json without restarting the proxy.
    Requires the proxy to be running (start with 'mcp-acp-extended start' or via MCP client).

    This command communicates with the proxy's management API on localhost.

    Exit codes:
        0: Policy reloaded successfully
        1: Reload failed (validation error, file error, or proxy not running)
    """
    try:
        response = httpx.post(
            f"http://127.0.0.1:{DEFAULT_API_PORT}/api/control/reload-policy",
            timeout=10.0,
        )
        response.raise_for_status()
        result = response.json()

        if result["status"] == "success":
            old_count = result.get("old_rules_count", "?")
            new_count = result.get("new_rules_count", "?")
            approvals_cleared = result.get("approvals_cleared", 0)
            version = result.get("policy_version")

            click.echo(f"✓ Policy reloaded: {old_count} → {new_count} rules")
            if approvals_cleared > 0:
                click.echo(
                    f"  {approvals_cleared} cached approval{'s' if approvals_cleared != 1 else ''} cleared"
                )
            if version:
                click.echo(f"  Version: {version}")
        else:
            error = result.get("error", "Unknown error")
            click.echo(f"✗ Reload failed: {error}", err=True)
            sys.exit(1)

    except httpx.ConnectError:
        click.echo("✗ Error: Proxy not running", err=True)
        click.echo("  Start the proxy with: mcp-acp-extended start", err=True)
        click.echo("  Or restart your MCP client (e.g., Claude Desktop)", err=True)
        sys.exit(1)
    except httpx.HTTPStatusError as e:
        click.echo(f"✗ Error: HTTP {e.response.status_code}", err=True)
        try:
            detail = e.response.json().get("detail", str(e))
            click.echo(f"  {detail}", err=True)
        except (ValueError, KeyError):
            click.echo(f"  {e}", err=True)
        sys.exit(1)
    except httpx.TimeoutException:
        click.echo("✗ Error: Request timed out", err=True)
        click.echo("  The proxy may be busy or unresponsive", err=True)
        sys.exit(1)
