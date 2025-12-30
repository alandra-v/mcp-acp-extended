"""Start command for mcp-acp-extended CLI.

Starts the proxy server for manual testing.
"""

import sys

import click

from mcp_acp_extended import __version__
from mcp_acp_extended.config import AppConfig
from mcp_acp_extended.utils.policy import get_policy_path, load_policy
from mcp_acp_extended.utils.history_logging.policy_logger import (
    log_policy_loaded,
    log_policy_validation_failed,
)
from mcp_acp_extended.cli.startup_alerts import show_startup_error_popup
from mcp_acp_extended.exceptions import AuditFailure, AuthenticationError, DeviceHealthError
from mcp_acp_extended.proxy import create_proxy
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

# Bootstrap log filename (used when config is invalid and log_dir unavailable)
BOOTSTRAP_LOG_FILENAME = "bootstrap.jsonl"


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
        click.echo("-" * 50, err=True)

        click.echo("Proxy server ready - listening on STDIO", err=True)
        # proxy server listens for clients via STDIO
        proxy.run()

    except FileNotFoundError as e:
        error_msg = str(e).lower()
        # Distinguish between config not found vs mTLS cert not found
        if "mtls" in error_msg or "certificate" in error_msg or "cert" in error_msg:
            show_startup_error_popup(
                title="MCP ACP",
                message="mTLS certificate not found.",
                detail=f"{e}\n\nCheck certificate paths in config or run:\n  mcp-acp-extended init",
            )
            click.echo(f"\nError: mTLS certificate not found: {e}", err=True)
        else:
            show_startup_error_popup(
                title="MCP ACP",
                message="Configuration not found.",
                detail="Run in terminal:\n  mcp-acp-extended init\n\nThen restart your MCP client.",
            )
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
        except OSError as log_err:
            # Don't fail startup due to logging errors, but warn for debugging
            click.echo(f"Warning: Could not write to bootstrap log: {log_err}", err=True)

        if is_policy_error:
            show_startup_error_popup(
                title="MCP ACP",
                message="Invalid policy.",
                detail=f"{error_msg}\n\nFix policy file or run:\n  mcp-acp-extended init",
            )
            click.echo(f"\nError: Invalid policy: {e}", err=True)
        else:
            show_startup_error_popup(
                title="MCP ACP",
                message="Invalid configuration.",
                detail=f"{error_msg}\n\nFix config file or run:\n  mcp-acp-extended init",
            )
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

    except TimeoutError as e:
        show_startup_error_popup(
            title="MCP ACP",
            message="Backend connection timed out.",
            detail=f"{e}\n\nCheck that the backend server is running and responsive.",
        )
        click.echo(f"Error: Backend connection timed out: {e}", err=True)
        sys.exit(1)

    except ConnectionError as e:
        # Check for SSL-specific errors
        error_msg = str(e).lower()
        if "ssl" in error_msg or "certificate" in error_msg:
            show_startup_error_popup(
                title="MCP ACP",
                message="SSL/TLS error.",
                detail=f"{e}\n\nCheck your mTLS certificate configuration.",
            )
            click.echo(f"Error: SSL/TLS error: {e}", err=True)
        else:
            show_startup_error_popup(
                title="MCP ACP",
                message="Backend connection failed.",
                detail=f"{e}\n\nCheck that the backend server is running.",
            )
            click.echo(f"Error: Backend connection failed: {e}", err=True)
        sys.exit(1)

    except AuditFailure as e:
        show_startup_error_popup(
            title="MCP ACP",
            message="Audit log failure.",
            detail=f"{e}\n\nThe proxy cannot start without a writable audit log.\nCheck file permissions in the log directory.",
        )
        click.echo(f"Error: Audit log failure: {e}", err=True)
        click.echo("The proxy cannot start without a writable audit log.", err=True)
        sys.exit(10)

    except AuthenticationError as e:
        error_msg = str(e).lower()
        if "not authenticated" in error_msg or "no token" in error_msg or "token not found" in error_msg:
            show_startup_error_popup(
                title="MCP ACP",
                message="Not authenticated.",
                detail="Run in terminal:\n  mcp-acp-extended auth login\n\nThen restart your MCP client.",
            )
        elif "expired" in error_msg:
            show_startup_error_popup(
                title="MCP ACP",
                message="Authentication expired.",
                detail="Run in terminal:\n  mcp-acp-extended auth login\n\nThen restart your MCP client.",
            )
        else:
            show_startup_error_popup(
                title="MCP ACP",
                message="Authentication error.",
                detail=f"{e}\n\nRun 'mcp-acp-extended auth login' to re-authenticate.",
            )
        click.echo(f"\nError: {e}", err=True)
        sys.exit(13)

    except DeviceHealthError as e:
        show_startup_error_popup(
            title="MCP ACP",
            message="Device health check failed.",
            detail=f"{e}\n\nEnsure FileVault is enabled and SIP is not disabled.",
        )
        click.echo(f"\nError: Device health check failed", err=True)
        click.echo(str(e), err=True)
        sys.exit(14)

    except (PermissionError, RuntimeError, OSError) as e:
        show_startup_error_popup(
            title="MCP ACP",
            message="Proxy startup failed.",
            detail=f"{e}\n\nCheck file permissions and system configuration.",
        )
        click.echo(f"Error: Proxy startup failed: {e}", err=True)
        sys.exit(1)
