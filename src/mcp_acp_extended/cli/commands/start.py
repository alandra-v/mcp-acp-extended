"""Start command for mcp-acp-extended CLI.

Starts the proxy server for manual testing.
"""

import sys

import click

from mcp_acp_extended import __version__
from mcp_acp_extended.constants import BOOTSTRAP_LOG_FILENAME, CLI_SEPARATOR
from mcp_acp_extended.config import AppConfig
from mcp_acp_extended.utils.policy import get_policy_path, load_policy
from mcp_acp_extended.utils.history_logging.policy_logger import (
    log_policy_loaded,
    log_policy_validation_failed,
)
from mcp_acp_extended.proxy import create_proxy
from mcp_acp_extended.exceptions import AuditFailure
from mcp_acp_extended.utils.config import (
    ensure_directories,
    get_config_history_path,
    get_config_path,
    get_policy_history_path,
)
from mcp_acp_extended.utils.history_logging import (
    log_config_loaded,
    log_config_validation_failed as log_config_validation_failed_fn,
)


@click.command()
def start() -> None:
    """Start the proxy server manually (for testing).

    Loads configuration from the OS-appropriate location.
    No runtime overrides - all settings come from config file.

    Normally the proxy is started by the MCP client (e.g., Claude Desktop).
    This command is useful for manual testing.
    """
    config_path = get_config_path()

    try:
        # Load configuration
        loaded_config = AppConfig.load_from_files(config_path)

        # Ensure directories exist
        ensure_directories(loaded_config)

        # Log config loaded (detects manual changes, updates version)
        config_version, config_manual_changed = log_config_loaded(
            get_config_history_path(loaded_config),
            config_path,
            loaded_config.model_dump(),
            component="cli",
            source="cli_start",
        )

        # Load policy
        policy_path = get_policy_path()
        loaded_policy = load_policy(policy_path)

        # Log policy loaded (detects manual changes, updates version)
        policy_version, policy_manual_changed = log_policy_loaded(
            get_policy_history_path(loaded_config),
            policy_path,
            loaded_policy.model_dump(),
            component="cli",
            source="cli_start",
        )

        # Show startup info (transport shown after detection)
        click.echo(f"mcp-acp-extended v{__version__}", err=True)
        click.echo(f"Config version: {config_version}", err=True)
        click.echo(f"Policy version: {policy_version}", err=True)
        if config_manual_changed:
            click.echo("Note: Manual config changes detected", err=True)
        if policy_manual_changed:
            click.echo("Note: Manual policy changes detected", err=True)
        click.echo(f"Backend: {loaded_config.backend.server_name}", err=True)

        # Create proxy (detects/validates transport)
        proxy, actual_transport = create_proxy(
            loaded_config,
            config_version=config_version,
            policy_version=policy_version,
        )

        # Display actual transport used (after detection)
        click.echo(f"Backend transport: {actual_transport}", err=True)
        click.echo(CLI_SEPARATOR, err=True)

        click.echo("Proxy server ready - listening on STDIO", err=True)
        # proxy server listens for clients via STDIO
        proxy.run()

    except FileNotFoundError as e:
        click.echo(f"\nError: {e}", err=True)
        sys.exit(1)

    except ValueError as e:
        error_msg = str(e)

        # Determine if this is a config or policy error
        is_policy_error = "policy" in error_msg.lower()

        # Log validation failure to bootstrap log (before user's log_dir is available)
        try:
            bootstrap_log_path = config_path.parent / BOOTSTRAP_LOG_FILENAME
            if is_policy_error:
                log_policy_validation_failed(
                    bootstrap_log_path,
                    get_policy_path(),
                    error_type="ValidationError",
                    error_message=error_msg,
                    component="cli",
                    source="cli_start",
                )
            else:
                log_config_validation_failed_fn(
                    bootstrap_log_path,
                    config_path,
                    error_type="ValidationError",
                    error_message=error_msg,
                    component="cli",
                    source="cli_start",
                )
        except OSError:
            pass  # Don't fail startup due to logging errors

        if is_policy_error:
            click.echo(f"\nError: Invalid policy: {e}", err=True)
        else:
            click.echo(f"\nError: Invalid configuration: {e}", err=True)

        # Check for backup if config file is corrupt
        if "Invalid JSON" in error_msg or "Could not read" in error_msg:
            if is_policy_error:
                backup_path = get_policy_path().with_suffix(".json.bak")
            else:
                backup_path = config_path.with_suffix(".json.bak")
            if backup_path.exists():
                click.echo("\nA backup file exists from a previous edit.", err=True)
                click.echo(f"To restore: cp '{backup_path}' '{backup_path.with_suffix('')}'", err=True)

        sys.exit(1)

    except (TimeoutError, ConnectionError) as e:
        click.echo(f"Error: Backend connection failed: {e}", err=True)
        sys.exit(1)

    except AuditFailure as e:
        click.echo(f"Error: Audit log failure: {e}", err=True)
        click.echo("The proxy cannot start without a writable audit log.", err=True)
        sys.exit(10)

    except (PermissionError, RuntimeError, OSError) as e:
        click.echo(f"Error: Proxy startup failed: {e}", err=True)
        sys.exit(1)
