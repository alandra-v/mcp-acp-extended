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

from pydantic import BaseModel, Field, ValidationError

from mcp_acp_extended.constants import (
    DEFAULT_HTTP_TIMEOUT_SECONDS,
    MAX_HTTP_TIMEOUT_SECONDS,
    MIN_HTTP_TIMEOUT_SECONDS,
)


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

    Contains all configuration sections including logging, backend server,
    and proxy settings. All configuration is required - user must run
    `mcp-acp-extended init` to create the config file.

    Attributes:
        logging: Logging configuration (log level, paths, payload settings).
        backend: Backend server configuration (STDIO or Streamable HTTP transport).
        proxy: Proxy server configuration (name).
    """

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
        if not config_path.exists():
            raise FileNotFoundError(
                f"Configuration not found at {config_path}.\n"
                "Run 'mcp-acp-extended init' to create a configuration file."
            )

        try:
            with open(config_path, "r", encoding="utf-8") as f:
                config_data = json.load(f)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in config file {config_path}: {e}") from e
        except OSError as e:
            raise ValueError(f"Could not read config file {config_path}: {e}") from e

        try:
            return cls.model_validate(config_data)
        except ValidationError as e:
            errors = []
            for error in e.errors():
                loc = ".".join(str(x) for x in error["loc"])
                msg = error["msg"]
                errors.append(f"  - {loc}: {msg}")

            raise ValueError(
                f"Invalid configuration in {config_path}:\n"
                + "\n".join(errors)
                + "\n\nRun 'mcp-acp-extended init' to reconfigure."
            ) from e
