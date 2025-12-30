"""Policy command group for mcp-acp-extended CLI.

Provides policy management subcommands.
"""

import sys
from pathlib import Path

import click

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
