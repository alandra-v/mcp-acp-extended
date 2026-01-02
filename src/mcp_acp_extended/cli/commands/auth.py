"""Authentication commands for mcp-acp-extended CLI.

Commands:
    auth login  - Authenticate via browser (Device Flow)
    auth logout - Clear stored credentials
    auth status - Show authentication status
"""

from __future__ import annotations

import webbrowser
from typing import TYPE_CHECKING

import click

from mcp_acp_extended.config import AppConfig

if TYPE_CHECKING:
    from mcp_acp_extended.config import OIDCConfig
from mcp_acp_extended.exceptions import AuthenticationError
from mcp_acp_extended.security.auth.device_flow import (
    DeviceFlowDeniedError,
    DeviceFlowError,
    DeviceFlowExpiredError,
    run_device_flow,
)
from mcp_acp_extended.security.auth.token_storage import (
    create_token_storage,
    get_token_storage_info,
)
from mcp_acp_extended.utils.config import get_config_path


def _load_config() -> AppConfig:
    """Load configuration from default path.

    Returns:
        AppConfig instance.

    Raises:
        click.ClickException: If config not found or invalid.
    """
    config_path = get_config_path()

    if not config_path.exists():
        raise click.ClickException(
            f"Configuration not found at {config_path}\n"
            "Run 'mcp-acp-extended init' to create configuration."
        )

    try:
        return AppConfig.load_from_files(config_path)
    except Exception as e:
        raise click.ClickException(f"Failed to load configuration: {e}") from e


@click.group()
def auth() -> None:
    """Authentication commands."""
    pass


@auth.command()
@click.option(
    "--no-browser",
    is_flag=True,
    help="Don't automatically open browser",
)
def login(no_browser: bool) -> None:
    """Authenticate via browser using Device Flow.

    Opens your browser to complete authentication. Tokens are stored
    securely in your OS keychain.

    This is the same pattern as 'gh auth login' or 'aws sso login'.
    """
    # Load config to get OIDC settings
    config = _load_config()

    if config.auth is None or config.auth.oidc is None:
        raise click.ClickException(
            "Authentication not configured.\n"
            "Add 'auth.oidc' section to your config with issuer, client_id, and audience."
        )

    oidc_config = config.auth.oidc

    click.echo("Starting authentication...")
    click.echo()

    # Track if we've opened browser
    browser_opened = False

    def display_callback(
        user_code: str,
        verification_uri: str,
        verification_uri_complete: str | None,
    ) -> None:
        """Display authentication instructions to user."""
        nonlocal browser_opened

        # Use the complete URI if available (has code embedded)
        auth_url = verification_uri_complete or verification_uri

        click.echo(click.style("Authentication Required", fg="cyan", bold=True))
        click.echo()

        # Always show the code - user needs to confirm it matches in browser
        click.echo(f"  Your code: {click.style(user_code, fg='green', bold=True)}")
        click.echo()

        if verification_uri_complete:
            click.echo(f"  Open this URL in your browser:")
            click.echo(f"  {click.style(auth_url, fg='blue', underline=True)}")
        else:
            click.echo(f"  1. Open: {click.style(verification_uri, fg='blue', underline=True)}")
            click.echo(f"  2. Enter the code above")

        click.echo()

        # Try to open browser automatically
        if not no_browser:
            try:
                webbrowser.open(auth_url)
                browser_opened = True
                click.echo("  Browser opened automatically.")
            except (OSError, webbrowser.Error) as e:
                click.echo(f"  (Could not open browser automatically: {e})")

        click.echo()
        click.echo("Waiting for authentication", nl=False)

    def poll_callback() -> None:
        """Show progress while polling."""
        click.echo(".", nl=False)

    try:
        # Run the device flow
        token = run_device_flow(
            config=oidc_config,
            display_callback=display_callback,
            poll_callback=poll_callback,
        )

        click.echo()  # Newline after dots
        click.echo()

        # Store token
        storage = create_token_storage(oidc_config)
        storage.save(token)

        # Show success
        click.echo(click.style("Authentication successful!", fg="green", bold=True))
        click.echo()

        # Show storage info
        storage_info = get_token_storage_info()
        click.echo(f"  Token stored in: {storage_info['backend']}")

        # Show expiry
        hours_until_expiry = token.seconds_until_expiry / 3600
        click.echo(f"  Token expires in: {hours_until_expiry:.1f} hours")

        click.echo()
        click.echo("You can now start the proxy with 'mcp-acp-extended start'")

    except DeviceFlowExpiredError:
        click.echo()
        click.echo()
        raise click.ClickException(
            "Authentication timed out. Please run 'mcp-acp-extended auth login' again."
        )

    except DeviceFlowDeniedError:
        click.echo()
        click.echo()
        raise click.ClickException("Authentication was denied.")

    except DeviceFlowError as e:
        click.echo()
        click.echo()
        raise click.ClickException(f"Authentication failed: {e}")


@auth.command()
@click.option(
    "--federated",
    is_flag=True,
    help="Also log out of the identity provider (Auth0) in your browser",
)
def logout(federated: bool) -> None:
    """Clear stored credentials.

    Removes tokens from your OS keychain. You will need to run
    'auth login' again to use the proxy.

    Use --federated to also log out of Auth0 in your browser. This is
    useful when switching between different users.
    """
    # Load config to get OIDC settings (for storage selection)
    config = _load_config()

    oidc_config = config.auth.oidc if config.auth else None
    storage = create_token_storage(oidc_config)

    if not storage.exists():
        click.echo("No stored credentials found.")
        # Still do federated logout if requested (browser session may exist)
        if federated and oidc_config:
            _do_federated_logout(oidc_config)
        return

    try:
        storage.delete()
        click.echo(click.style("Local credentials cleared.", fg="green"))

        # Federated logout if requested
        if federated and oidc_config:
            _do_federated_logout(oidc_config)
        else:
            click.echo()
            click.echo("Note: Any running proxy will need to be restarted.")
            if oidc_config:
                click.echo("Tip: Use --federated to also log out of Auth0 in your browser.")

        click.echo()
        click.echo("Run 'mcp-acp-extended auth login' to authenticate again.")
    except AuthenticationError as e:
        raise click.ClickException(f"Failed to clear credentials: {e}")


def _do_federated_logout(oidc_config: OIDCConfig) -> None:
    """Open browser to log out of the identity provider.

    Args:
        oidc_config: OIDC configuration with issuer and client_id.
    """
    # Build Auth0 logout URL
    # Format: https://{issuer}/v2/logout?client_id={client_id}
    issuer = oidc_config.issuer.rstrip("/")
    logout_url = f"{issuer}/v2/logout?client_id={oidc_config.client_id}"

    click.echo()
    click.echo("Opening browser to log out of Auth0...")

    try:
        webbrowser.open(logout_url)
        click.echo(click.style("Browser opened for Auth0 logout.", fg="green"))
    except (OSError, webbrowser.Error) as e:
        click.echo(f"Could not open browser automatically: {e}")
        click.echo(f"Open this URL manually: {logout_url}")


@auth.command()
def status() -> None:
    """Show authentication status.

    Displays token validity, user info, and storage backend.
    """
    # Load config
    config = _load_config()

    if config.auth is None or config.auth.oidc is None:
        click.echo(click.style("Authentication not configured", fg="yellow"))
        click.echo()
        click.echo("Add 'auth.oidc' section to your config to enable authentication.")
        return

    oidc_config = config.auth.oidc
    storage = create_token_storage(oidc_config)

    # Show storage info
    storage_info = get_token_storage_info()
    click.echo(click.style("Storage", fg="cyan", bold=True))
    click.echo(f"  Backend: {storage_info['backend']}")
    if "keyring_backend" in storage_info:
        click.echo(f"  Keyring: {storage_info['keyring_backend']}")
    if "location" in storage_info:
        click.echo(f"  Location: {storage_info['location']}")
    click.echo()

    # Check for token
    if not storage.exists():
        click.echo(click.style("Status: Not authenticated", fg="yellow"))
        click.echo()
        click.echo("Run 'mcp-acp-extended auth login' to authenticate.")
        return

    # Load and validate token
    try:
        token = storage.load()
    except AuthenticationError as e:
        click.echo(click.style("Status: Token corrupted", fg="red"))
        click.echo(f"  Error: {e}")
        click.echo()
        click.echo("Run 'mcp-acp-extended auth logout' then 'auth login' to fix.")
        return

    if token is None:
        click.echo(click.style("Status: Not authenticated", fg="yellow"))
        return

    # Check expiry
    if token.is_expired:
        click.echo(click.style("Status: Token expired", fg="red"))
        click.echo()
        if token.refresh_token:
            click.echo("Token will be refreshed automatically on next proxy start.")
            click.echo("Or run 'mcp-acp-extended auth login' to re-authenticate now.")
        else:
            click.echo("Run 'mcp-acp-extended auth login' to re-authenticate.")
        return

    # Token is valid
    click.echo(click.style("Status: Authenticated", fg="green", bold=True))
    click.echo()

    # Show token info
    click.echo(click.style("Token", fg="cyan", bold=True))

    hours_until_expiry = token.seconds_until_expiry / 3600
    if hours_until_expiry > 24:
        days = hours_until_expiry / 24
        click.echo(f"  Expires in: {days:.1f} days")
    else:
        click.echo(f"  Expires in: {hours_until_expiry:.1f} hours")

    click.echo(f"  Has refresh token: {'Yes' if token.refresh_token else 'No'}")
    click.echo(f"  Has ID token: {'Yes' if token.id_token else 'No'}")

    # Try to extract user info from ID token
    if token.id_token:
        try:
            from mcp_acp_extended.security.auth.jwt_validator import JWTValidator

            # Extract claims from id_token for display (trusted - from our auth flow)
            validator = JWTValidator(oidc_config)
            claims = validator.decode_without_validation(token.id_token)

            click.echo()
            click.echo(click.style("User", fg="cyan", bold=True))
            if "email" in claims:
                click.echo(f"  Email: {claims['email']}")
            if "name" in claims:
                click.echo(f"  Name: {claims['name']}")
            if "sub" in claims:
                click.echo(f"  Subject: {claims['sub']}")

        except (ValueError, KeyError) as e:
            # Can't decode ID token - not critical, just skip user info display
            click.echo(f"  (Could not decode ID token: {e})", err=True)

    click.echo()
    click.echo(click.style("OIDC Configuration", fg="cyan", bold=True))
    click.echo(f"  Issuer: {oidc_config.issuer}")
    click.echo(f"  Client ID: {oidc_config.client_id}")
    click.echo(f"  Audience: {oidc_config.audience}")

    # Show mTLS certificate status if configured
    if config.auth.mtls:
        from mcp_acp_extended.utils.transport import get_certificate_expiry_info

        click.echo()
        click.echo(click.style("mTLS Certificate", fg="cyan", bold=True))
        click.echo(f"  Client cert: {config.auth.mtls.client_cert_path}")
        click.echo(f"  Client key: {config.auth.mtls.client_key_path}")
        click.echo(f"  CA bundle: {config.auth.mtls.ca_bundle_path}")

        # Check certificate expiry
        cert_info = get_certificate_expiry_info(config.auth.mtls.client_cert_path)

        if "error" in cert_info:
            click.echo(f"  Status: {click.style('Error', fg='red')} - {cert_info['error']}")
        else:
            status = cert_info["status"]
            days_value = cert_info.get("days_until_expiry")
            days = int(days_value) if days_value is not None else 0

            if status == "expired":
                click.echo(f"  Status: {click.style('EXPIRED', fg='red', bold=True)}")
                click.echo(f"  Expired: {abs(days)} days ago")
            elif status == "critical":
                click.echo(f"  Status: {click.style('CRITICAL', fg='red', bold=True)}")
                click.echo(f"  Expires in: {click.style(f'{days} days', fg='red')}")
                click.echo("  Renew immediately!")
            elif status == "warning":
                click.echo(f"  Status: {click.style('Warning', fg='yellow')}")
                click.echo(f"  Expires in: {click.style(f'{days} days', fg='yellow')}")
                click.echo("  Consider renewing soon.")
            else:
                click.echo(f"  Status: {click.style('Valid', fg='green')}")
                click.echo(f"  Expires in: {days} days")
