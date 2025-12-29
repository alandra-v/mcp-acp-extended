"""Init command for mcp-acp-extended CLI.

Handles interactive and non-interactive configuration initialization.
"""

import sys
from pathlib import Path
from typing import Literal, cast

import click

from mcp_acp_extended.config import (
    AppConfig,
    AuthConfig,
    BackendConfig,
    HttpTransportConfig,
    LoggingConfig,
    MTLSConfig,
    OIDCConfig,
    StdioTransportConfig,
)
from mcp_acp_extended.constants import (
    DEFAULT_HTTP_TIMEOUT_SECONDS,
    HEALTH_CHECK_TIMEOUT_SECONDS,
    RECOMMENDED_LOG_DIR,
)
from mcp_acp_extended.pdp import create_default_policy
from mcp_acp_extended.utils.policy import get_policy_path, save_policy
from mcp_acp_extended.utils.history_logging.policy_logger import log_policy_created
from mcp_acp_extended.utils.config import (
    ensure_directories,
    get_config_history_path,
    get_config_path,
    get_policy_history_path,
)
from mcp_acp_extended.utils.history_logging import log_config_created
from mcp_acp_extended.utils.transport import check_http_health, validate_mtls_config

from ..prompts import prompt_http_config, prompt_stdio_config, prompt_with_retry


def _create_policy_only(config: AppConfig, policy_path: Path) -> None:
    """Create policy file using existing config's log_dir.

    Args:
        config: Existing AppConfig (for log_dir).
        policy_path: Path to save policy file.
    """
    policy = create_default_policy()
    save_policy(policy, policy_path)

    # Log policy creation to history
    ensure_directories(config)
    log_policy_created(
        get_policy_history_path(config),
        policy_path,
        policy.model_dump(),
        source="cli_init",
    )


def _create_and_save_config(
    config_path: Path,
    log_dir: str,
    log_level: str,
    server_name: str,
    connection_type: str,
    stdio_config: StdioTransportConfig | None,
    http_config: HttpTransportConfig | None,
    auth_config: AuthConfig,
) -> None:
    """Create and save configuration and policy files.

    Args:
        config_path: Path to save config file.
        log_dir: Log directory path.
        log_level: Logging level.
        server_name: Backend server name.
        connection_type: Connection type (stdio, http, or both).
        stdio_config: STDIO transport config (if applicable).
        http_config: HTTP transport config (if applicable).
        auth_config: Authentication configuration.

    Raises:
        OSError: If files cannot be saved.
    """
    log_level_literal = cast(
        Literal["DEBUG", "INFO"],
        log_level.upper(),
    )

    # Determine transport setting based on connection type
    # CLI uses "both" -> config uses None (auto-detect)
    transport: Literal["stdio", "streamablehttp"] | None
    if connection_type == "stdio":
        transport = "stdio"
    elif connection_type == "http":
        transport = "streamablehttp"
    elif connection_type == "both":
        transport = None  # auto-detect at runtime
    else:
        raise ValueError(f"Invalid connection_type: {connection_type}")

    config = AppConfig(
        auth=auth_config,
        logging=LoggingConfig(
            log_dir=log_dir,
            log_level=log_level_literal,
        ),
        backend=BackendConfig(
            server_name=server_name,
            transport=transport,
            stdio=stdio_config,
            http=http_config,
        ),
    )

    # Save configuration
    config.save_to_file(config_path)

    # Log config creation to history (with versioning and checksum)
    ensure_directories(config)
    log_config_created(
        get_config_history_path(config),
        config_path,
        config.model_dump(),
        source="cli_init",
    )

    # Create default policy file
    policy_path = get_policy_path()
    _create_policy_only(config, policy_path)

    # Display result
    click.echo(f"\nConfiguration saved to {config_path}")
    click.echo(f"Policy saved to {policy_path}")
    if transport is None:
        click.echo("Transport: auto-detect (prefers HTTP when reachable)")
    else:
        click.echo(f"Transport: {transport}")
    click.echo("\nRun 'mcp-acp-extended start' to test the proxy manually.")


def _prompt_auth_config(http_config: HttpTransportConfig | None) -> AuthConfig:
    """Prompt for authentication configuration.

    Args:
        http_config: HTTP config if using HTTP transport.

    Returns:
        AuthConfig with user-provided values.
    """
    click.echo("\n--- Authentication ---")
    click.echo("Configure Auth0/OIDC for user authentication.\n")

    # OIDC settings
    issuer = prompt_with_retry("OIDC issuer URL (e.g., https://your-tenant.auth0.com)")
    client_id = prompt_with_retry("Auth0 client ID")
    audience = prompt_with_retry("API audience (e.g., https://your-api.example.com)")

    oidc_config = OIDCConfig(
        issuer=issuer,
        client_id=client_id,
        audience=audience,
    )

    # mTLS settings (only for HTTPS backends)
    mtls_config: MTLSConfig | None = None
    if http_config and http_config.url.startswith("https://"):
        click.echo("\n--- mTLS (Mutual TLS) ---")
        click.echo("HTTPS backend detected. mTLS allows the proxy to authenticate")
        click.echo("itself to the backend using a client certificate.\n")
        click.echo("You need 3 PEM files (get from IT team or generate for testing):")
        click.echo("  - Client certificate: proves proxy identity to backend")
        click.echo("  - Client private key: must match certificate (keep secure)")
        click.echo("  - CA bundle: verifies backend server's certificate\n")
        click.echo("Skip if your backend doesn't require client certificates.")
        click.echo("See 'docs/auth.md' for how to generate test certificates.\n")

        if click.confirm("Configure mTLS?", default=False):
            click.echo("\n  (Paths support ~ expansion, e.g., ~/.mcp-certs/client.pem)")

            while True:
                client_cert = prompt_with_retry("Client certificate path")
                client_key = prompt_with_retry("Client private key path")
                ca_bundle = prompt_with_retry("CA bundle path")

                # Validate certificates
                click.echo("\nValidating certificates...")
                errors = validate_mtls_config(client_cert, client_key, ca_bundle)

                if not errors:
                    click.echo(click.style("  Certificates valid!", fg="green"))
                    mtls_config = MTLSConfig(
                        client_cert_path=client_cert,
                        client_key_path=client_key,
                        ca_bundle_path=ca_bundle,
                    )
                    break

                # Show errors
                click.echo(click.style("\n  Certificate validation failed:", fg="red"))
                for error in errors:
                    click.echo(f"    - {error}")
                click.echo()

                # Ask what to do
                choice = click.prompt(
                    "What would you like to do?",
                    type=click.Choice(["retry", "skip", "continue"]),
                    default="retry",
                    show_choices=True,
                )

                if choice == "skip":
                    click.echo("  Skipping mTLS configuration.")
                    break
                elif choice == "continue":
                    click.echo("  Saving config with invalid certificates (will fail at startup).")
                    mtls_config = MTLSConfig(
                        client_cert_path=client_cert,
                        client_key_path=client_key,
                        ca_bundle_path=ca_bundle,
                    )
                    break
                # else retry - loop continues

    click.echo("\nNote: Device health (disk encryption, firewall) is checked at startup.")

    return AuthConfig(
        oidc=oidc_config,
        mtls=mtls_config,
    )


def _run_interactive_init(
    log_dir: str | None,
    log_level: str,
    server_name: str | None,
) -> tuple[str, str, str, str, StdioTransportConfig | None, HttpTransportConfig | None, AuthConfig]:
    """Run interactive configuration wizard.

    Args:
        log_dir: Pre-provided log directory or None.
        log_level: Pre-provided log level.
        server_name: Pre-provided server name or None.

    Returns:
        Tuple of (log_dir, log_level, server_name, connection_type, stdio_config, http_config, auth_config).

    Raises:
        click.Abort: If user aborts during HTTP configuration.
    """
    click.echo("\nWelcome to mcp-acp-extended!\n")
    click.echo(f"Config will be saved to: {get_config_path()}\n")

    # Logging settings
    log_dir = log_dir or prompt_with_retry(f"Log directory (recommended: {RECOMMENDED_LOG_DIR})")
    click.echo("  DEBUG enables debug wire logs (client <-> proxy <-> backend)")
    log_level = click.prompt(
        "Log level",
        type=click.Choice(["DEBUG", "INFO"], case_sensitive=False),
        default=log_level,
    )

    # Backend settings
    server_name = server_name or prompt_with_retry("\nBackend server name")

    # Connection type selection
    click.echo("\nHow do you connect to this server?")
    click.echo("  1. Local command (STDIO) - spawn a process like npx, uvx, python")
    click.echo("  2. Remote URL (Streamable HTTP) - connect to http://...")
    click.echo("  3. Both (configure both, auto-detect at runtime)")
    choice = click.prompt("Select", type=click.Choice(["1", "2", "3"]), default="1")

    stdio_config: StdioTransportConfig | None = None
    http_config: HttpTransportConfig | None = None

    if choice == "1":
        connection_type = "stdio"
        stdio_config = prompt_stdio_config()
    elif choice == "2":
        connection_type = "http"
        http_config = prompt_http_config()
    else:  # choice == "3"
        connection_type = "both"
        click.echo("\n  Auto-detect behavior: HTTP is tried first. If unreachable,")
        click.echo("  falls back to STDIO automatically.\n")
        stdio_config = prompt_stdio_config()
        http_config = prompt_http_config()

    # Authentication settings
    auth_config = _prompt_auth_config(http_config)

    return log_dir, log_level, server_name, connection_type, stdio_config, http_config, auth_config


def _run_non_interactive_init(
    log_dir: str | None,
    log_level: str,
    server_name: str | None,
    connection_type: str | None,
    command: str | None,
    args: str | None,
    url: str | None,
    timeout: int,
    # Auth options
    oidc_issuer: str | None,
    oidc_client_id: str | None,
    oidc_audience: str | None,
    mtls_cert: str | None,
    mtls_key: str | None,
    mtls_ca: str | None,
) -> tuple[str, str, str, str, StdioTransportConfig | None, HttpTransportConfig | None, AuthConfig]:
    """Run non-interactive configuration setup.

    Args:
        log_dir: Log directory path.
        log_level: Logging level.
        server_name: Backend server name.
        connection_type: Transport type (stdio, http, both).
        command: STDIO command.
        args: STDIO arguments (comma-separated).
        url: HTTP URL.
        timeout: HTTP timeout.
        oidc_issuer: OIDC issuer URL.
        oidc_client_id: Auth0 client ID.
        oidc_audience: API audience.
        mtls_cert: mTLS client certificate path.
        mtls_key: mTLS client key path.
        mtls_ca: mTLS CA bundle path.

    Returns:
        Tuple of (log_dir, log_level, server_name, connection_type, stdio_config, http_config, auth_config).

    Raises:
        SystemExit: If required flags are missing.
    """
    # Validate required flags
    if not log_dir:
        click.echo("Error: --log-dir is required", err=True)
        sys.exit(1)
    if not server_name:
        click.echo("Error: --server-name is required", err=True)
        sys.exit(1)
    if not connection_type:
        click.echo("Error: --connection-type is required", err=True)
        sys.exit(1)

    # Validate auth flags
    if not oidc_issuer or not oidc_client_id or not oidc_audience:
        click.echo("Error: --oidc-issuer, --oidc-client-id, and --oidc-audience are required", err=True)
        sys.exit(1)

    stdio_config: StdioTransportConfig | None = None
    http_config: HttpTransportConfig | None = None

    # Validate transport-specific flags
    if connection_type.lower() in ("stdio", "both"):
        if not command or not args:
            click.echo("Error: --command and --args required for stdio connection", err=True)
            sys.exit(1)
        args_list = [arg.strip() for arg in args.split(",") if arg.strip()]
        stdio_config = StdioTransportConfig(command=command, args=args_list)

    if connection_type.lower() in ("http", "both"):
        if not url:
            click.echo("Error: --url required for http connection", err=True)
            sys.exit(1)
        http_config = HttpTransportConfig(url=url, timeout=timeout)

        # Test HTTP connectivity
        click.echo(f"Testing connection to {url}...")
        try:
            check_http_health(url, timeout=min(timeout, HEALTH_CHECK_TIMEOUT_SECONDS))
            click.echo("Server is reachable.")
        except Exception:
            click.echo(f"Health check failed: could not reach {url}", err=True)
            click.echo("Config will be saved anyway. Server may be offline.", err=True)

    # Build auth config
    oidc_config = OIDCConfig(
        issuer=oidc_issuer,
        client_id=oidc_client_id,
        audience=oidc_audience,
    )

    mtls_config: MTLSConfig | None = None
    if mtls_cert and mtls_key and mtls_ca:
        # Validate mTLS certificates
        click.echo("Validating mTLS certificates...")
        errors = validate_mtls_config(mtls_cert, mtls_key, mtls_ca)
        if errors:
            click.echo("Error: mTLS certificate validation failed:", err=True)
            for error in errors:
                click.echo(f"  - {error}", err=True)
            sys.exit(1)
        click.echo("mTLS certificates valid.")

        mtls_config = MTLSConfig(
            client_cert_path=mtls_cert,
            client_key_path=mtls_key,
            ca_bundle_path=mtls_ca,
        )

    auth_config = AuthConfig(
        oidc=oidc_config,
        mtls=mtls_config,
    )

    return log_dir, log_level, server_name, connection_type, stdio_config, http_config, auth_config


@click.command()
@click.option(
    "--non-interactive",
    is_flag=True,
    help="Skip prompts, require all options via flags",
)
@click.option(
    "--log-dir",
    help=f"Log directory path (recommended: {RECOMMENDED_LOG_DIR})",
)
@click.option(
    "--log-level",
    type=click.Choice(["DEBUG", "INFO"], case_sensitive=False),
    default="INFO",
    help="Logging verbosity (default: INFO). DEBUG enables debug wire logs.",
)
@click.option("--server-name", help="Backend server name")
@click.option(
    "--connection-type",
    type=click.Choice(["stdio", "http", "both"], case_sensitive=False),
    help="Transport: stdio (local), http (remote), both (HTTP with STDIO fallback)",
)
@click.option("--command", help="Backend command for STDIO (e.g., npx)")
@click.option("--args", help="Backend arguments for STDIO (comma-separated)")
@click.option("--url", help="Backend URL for HTTP (e.g., http://localhost:3010/mcp)")
@click.option(
    "--timeout",
    type=int,
    default=DEFAULT_HTTP_TIMEOUT_SECONDS,
    help=f"Connection timeout for HTTP (default: {DEFAULT_HTTP_TIMEOUT_SECONDS})",
)
# Auth options
@click.option("--oidc-issuer", help="OIDC issuer URL (e.g., https://your-tenant.auth0.com)")
@click.option("--oidc-client-id", help="Auth0 client ID")
@click.option("--oidc-audience", help="API audience for token validation")
@click.option(
    "--mtls-cert",
    help="Client certificate for mTLS (PEM). Presented to backend to prove proxy identity.",
)
@click.option(
    "--mtls-key",
    help="Client private key for mTLS (PEM). Must match --mtls-cert. Keep secure (0600).",
)
@click.option(
    "--mtls-ca",
    help="CA bundle for mTLS (PEM). Used to verify backend server's certificate.",
)
@click.option("--force", is_flag=True, help="Overwrite existing config without prompting")
def init(
    non_interactive: bool,
    log_dir: str | None,
    log_level: str,
    server_name: str | None,
    connection_type: str | None,
    command: str | None,
    args: str | None,
    url: str | None,
    timeout: int,
    oidc_issuer: str | None,
    oidc_client_id: str | None,
    oidc_audience: str | None,
    mtls_cert: str | None,
    mtls_key: str | None,
    mtls_ca: str | None,
    force: bool,
) -> None:
    """Initialize proxy configuration.

    Creates configuration at the OS-appropriate location:
    - macOS: ~/Library/Application Support/mcp-acp-extended/
    - Linux: ~/.config/mcp-acp-extended/
    - Windows: C:\\Users\\<user>\\AppData\\Roaming\\mcp-acp-extended/

    \b
    Connection types:
    - stdio: Spawn a local server process (e.g., npx, uvx, python).
            Requires --command and --args.
    - http:  Connect to a remote server via Streamable HTTP URL.
            Requires --url. Warns if server is unreachable but saves config.
    - both:  Configure both transports with automatic fallback.
            At runtime: tries HTTP first, falls back to STDIO if
            HTTP is unreachable. Useful for development (local)
            vs production (remote) flexibility.

    \b
    mTLS (Mutual TLS):
    For HTTPS backends requiring client certificate authentication,
    provide all three mTLS options: --mtls-cert, --mtls-key, --mtls-ca.
    Get certificates from your IT team or generate for testing.
    See 'docs/auth.md' for certificate generation instructions.

    Use --non-interactive with required flags for scripted setup.
    """
    config_path = get_config_path()
    policy_path = get_policy_path()

    config_exists = config_path.exists()
    policy_exists = policy_path.exists()

    # Upgrade path: config exists but policy missing - just create policy
    if config_exists and not policy_exists:
        click.echo("Policy file missing. Creating default policy...")
        try:
            existing_config = AppConfig.load_from_files(config_path)
            _create_policy_only(existing_config, policy_path)
            click.echo(f"Policy created at {policy_path}")
            return
        except ValueError as e:
            click.echo(f"Error: Cannot load existing config: {e}", err=True)
            click.echo("Fix the config or use --force to recreate both files.", err=True)
            sys.exit(1)

    # If config exists, ask to overwrite (unless --force)
    # If only policy exists, proceed - user wants to recreate config
    if config_exists and not force:
        if non_interactive:
            click.echo("Error: Config already exists. Use --force to overwrite.", err=True)
            sys.exit(1)
        if not click.confirm("Config already exists. Overwrite?", default=False):
            click.echo("Aborted.")
            sys.exit(0)

    # Gather configuration values
    try:
        if non_interactive:
            log_dir, log_level, server_name, connection_type, stdio_config, http_config, auth_config = (
                _run_non_interactive_init(
                    log_dir,
                    log_level,
                    server_name,
                    connection_type,
                    command,
                    args,
                    url,
                    timeout,
                    oidc_issuer,
                    oidc_client_id,
                    oidc_audience,
                    mtls_cert,
                    mtls_key,
                    mtls_ca,
                )
            )
        else:
            log_dir, log_level, server_name, connection_type, stdio_config, http_config, auth_config = (
                _run_interactive_init(log_dir, log_level, server_name)
            )
    except click.Abort:
        click.echo("Aborted.")
        sys.exit(0)

    # Create and save configuration (always creates both config and policy)
    # Note: log_dir, server_name, connection_type are guaranteed to be str after
    # _run_non_interactive_init (validates and exits) or _run_interactive_init (prompts until valid)
    assert log_dir is not None
    assert server_name is not None
    assert connection_type is not None
    try:
        _create_and_save_config(
            config_path,
            log_dir,
            log_level,
            server_name,
            connection_type,
            stdio_config,
            http_config,
            auth_config,
        )
    except OSError as e:
        click.echo(f"Error: Failed to save configuration: {e}", err=True)
        sys.exit(1)
