"""Application configuration for mcp-acp-extended.

Defines configuration models for logging, backend connections, and proxy behavior.
User creates config via `mcp-acp-extended init`. Config is stored at the OS-appropriate
location (via click.get_app_dir), log_dir is user-specified.

Example usage:
    # Load from config file
    config = AppConfig.load_from_files(config_path)

    # Save new configuration
    config.save_to_file(config_path)
"""

import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

from mcp_acp_extended.constants import (
    DEFAULT_HTTP_TIMEOUT_SECONDS,
    MAX_HTTP_TIMEOUT_SECONDS,
    MIN_HTTP_TIMEOUT_SECONDS,
)
from mcp_acp_extended.utils.file_helpers import load_validated_json, require_file_exists


# =============================================================================
# Authentication Configuration (Zero Trust - all features mandatory)
# =============================================================================


class OIDCConfig(BaseModel):
    """Auth0/OIDC configuration for user authentication.

    All fields are required - Zero Trust requires authenticated users.

    Attributes:
        issuer: OIDC issuer URL (e.g., "https://your-tenant.auth0.com").
        client_id: Auth0 application client ID.
        audience: API audience for token validation.
        scopes: OAuth scopes to request (default includes offline_access for refresh).
    """

    issuer: str
    client_id: str
    audience: str
    scopes: list[str] = Field(
        default=["openid", "profile", "email", "offline_access"],
        description="OAuth scopes to request",
    )


class MTLSConfig(BaseModel):
    """mTLS configuration for secure backend connections.

    Required when backend uses HTTPS. Provides mutual authentication
    between proxy and backend server.

    Attributes:
        client_cert_path: Path to client certificate (PEM format).
        client_key_path: Path to client private key (PEM format).
        ca_bundle_path: Path to CA bundle for server verification (PEM format).
    """

    client_cert_path: str
    client_key_path: str
    ca_bundle_path: str


class AuthConfig(BaseModel):
    """Authentication configuration for Zero Trust.

    All authentication is mandatory - there is no option to disable auth.
    This ensures Zero Trust compliance: every request has a verified identity.

    Note: Device health (disk encryption, firewall) is checked at runtime,
    not configured here. If checks fail, proxy won't start.

    Attributes:
        oidc: OIDC/Auth0 configuration for user authentication.
        mtls: mTLS configuration (required for HTTPS backends).
    """

    oidc: OIDCConfig
    mtls: MTLSConfig | None = None  # Required only for HTTPS backends


# =============================================================================
# Logging Configuration
# =============================================================================


class LoggingConfig(BaseModel):
    """Logging configuration settings.

    The log_dir specifies a base directory. Within it, logs are stored
    in a mcp_acp_extended_logs/ subdirectory with this structure:
        <log_dir>/
        └── mcp_acp_extended_logs/
            ├── debug/                  # Only created when log_level=DEBUG
            │   ├── client_wire.jsonl
            │   └── backend_wire.jsonl
            ├── system/
            │   ├── system.jsonl
            │   └── config_history.jsonl
            └── audit/                  # Always enabled (security audit trail)
                └── operations.jsonl

    Attributes:
        log_dir: Base directory for logs (required, user-specified via init).
        log_level: Logging level (DEBUG or INFO). DEBUG enables wire logs.
        include_payloads: Whether to include full message payloads in debug logs.
    """

    log_dir: str
    log_level: Literal["DEBUG", "INFO"] = "INFO"
    include_payloads: bool = True


class StdioTransportConfig(BaseModel):
    """STDIO transport configuration.

    Attributes:
        command: Command to launch backend server.
        args: Arguments to pass to backend command.
    """

    command: str
    args: list[str] = Field(default_factory=list)


class HttpTransportConfig(BaseModel):
    """Streamable HTTP transport configuration.

    Attributes:
        url: Backend server URL (e.g., "http://localhost:3010/mcp").
        timeout: Connection timeout in seconds (1-300).
    """

    url: str
    timeout: int = Field(
        default=DEFAULT_HTTP_TIMEOUT_SECONDS,
        ge=MIN_HTTP_TIMEOUT_SECONDS,
        le=MAX_HTTP_TIMEOUT_SECONDS,
    )


class BackendConfig(BaseModel):
    """Backend server configuration for a single server.

    Supports STDIO and Streamable HTTP transports. User configures via `init`.

    Transport selection:
    - If transport is explicitly set ("stdio" or "streamablehttp"), that transport
      is used and its corresponding config (stdio or http) must be present.
    - If transport is None (auto-detect), the proxy will prefer HTTP if configured
      and reachable, otherwise fall back to STDIO.

    Attributes:
        server_name: Name of the server (for display/reference).
        transport: Transport type, or None for auto-detect.
        stdio: STDIO transport configuration (command, args).
        http: Streamable HTTP transport configuration (url, timeout).
    """

    server_name: str
    transport: Literal["stdio", "streamablehttp"] | None = None
    stdio: StdioTransportConfig | None = None
    http: HttpTransportConfig | None = None


class ProxyConfig(BaseModel):
    """Proxy server configuration settings.

    Attributes:
        name: Proxy server name for identification.
    """

    name: str = "mcp-acp-extended"


class AppConfig(BaseModel):
    """Main application configuration for mcp-acp-extended.

    Contains all configuration sections including authentication, logging,
    backend server, and proxy settings.

    Zero Trust: Authentication is mandatory. The proxy will not start without
    valid auth configuration. There is no unauthenticated fallback.

    Attributes:
        auth: Authentication configuration (OIDC, mTLS). Required for proxy to start.
        logging: Logging configuration (log level, paths, payload settings).
        backend: Backend server configuration (STDIO or Streamable HTTP transport).
        proxy: Proxy server configuration (name).
    """

    auth: AuthConfig | None = None  # Validated at runtime - proxy won't start without it
    logging: LoggingConfig
    backend: BackendConfig
    proxy: ProxyConfig = Field(default_factory=ProxyConfig)

    def save_to_file(self, config_path: Path) -> None:
        """Save configuration to JSON file.

        Creates parent directories if they don't exist.
        Sets secure permissions (0o700) on the config directory.

        Args:
            config_path: Path where mcp_acp_extended_config.json should be saved.
        """
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.parent.chmod(0o700)

        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(self.model_dump(), f, indent=2)

        config_path.chmod(0o600)

    @classmethod
    def load_from_files(cls, config_path: Path) -> "AppConfig":
        """Load configuration from JSON file.

        Args:
            config_path: Path to the config file (mcp_acp_extended_config.json).

        Returns:
            AppConfig instance with loaded configuration.

        Raises:
            FileNotFoundError: If config file doesn't exist.
            ValueError: If config file is invalid or missing required fields.
        """
        require_file_exists(config_path, file_type="configuration")
        return load_validated_json(
            config_path,
            cls,
            file_type="config",
            recovery_hint="Run 'mcp-acp-extended init' to reconfigure.",
            encoding="utf-8",
        )
