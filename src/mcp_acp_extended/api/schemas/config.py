"""Configuration API schemas."""

from __future__ import annotations

__all__ = [
    # Response schemas
    "AuthConfigResponse",
    "BackendConfigResponse",
    "ConfigResponse",
    "ConfigUpdateResponse",
    "HttpTransportResponse",
    "LoggingConfigResponse",
    "MTLSConfigResponse",
    "OIDCConfigResponse",
    "ProxyConfigResponse",
    "StdioTransportResponse",
    # Update schemas
    "AuthConfigUpdate",
    "BackendConfigUpdate",
    "ConfigUpdateRequest",
    "HttpTransportUpdate",
    "LoggingConfigUpdate",
    "MTLSConfigUpdate",
    "OIDCConfigUpdate",
    "ProxyConfigUpdate",
    "StdioTransportUpdate",
]

from typing import Literal

from pydantic import BaseModel, Field

from mcp_acp_extended.constants import (
    MAX_HTTP_TIMEOUT_SECONDS,
    MIN_HTTP_TIMEOUT_SECONDS,
)


# =============================================================================
# Response Schemas (full details, no longer redacted)
# =============================================================================


class StdioTransportResponse(BaseModel):
    """STDIO transport configuration."""

    command: str
    args: list[str]


class HttpTransportResponse(BaseModel):
    """HTTP transport configuration."""

    url: str
    timeout: int


class BackendConfigResponse(BaseModel):
    """Backend configuration with full transport details."""

    server_name: str
    transport: Literal["stdio", "streamablehttp", "auto"] | None
    stdio: StdioTransportResponse | None = None
    http: HttpTransportResponse | None = None


class LoggingConfigResponse(BaseModel):
    """Logging configuration."""

    log_dir: str
    log_level: str
    include_payloads: bool


class OIDCConfigResponse(BaseModel):
    """OIDC configuration."""

    issuer: str
    client_id: str
    audience: str
    scopes: list[str]


class MTLSConfigResponse(BaseModel):
    """mTLS configuration."""

    client_cert_path: str
    client_key_path: str
    ca_bundle_path: str


class AuthConfigResponse(BaseModel):
    """Auth configuration with full OIDC and mTLS details."""

    oidc: OIDCConfigResponse | None = None
    mtls: MTLSConfigResponse | None = None


class ProxyConfigResponse(BaseModel):
    """Proxy configuration."""

    name: str


class ConfigResponse(BaseModel):
    """Full configuration response with all details."""

    backend: BackendConfigResponse
    logging: LoggingConfigResponse
    auth: AuthConfigResponse | None
    proxy: ProxyConfigResponse
    config_path: str
    requires_restart_for_changes: bool = True


# =============================================================================
# Update Schemas
# =============================================================================


class LoggingConfigUpdate(BaseModel):
    """Updatable logging fields."""

    log_dir: str | None = None
    log_level: Literal["DEBUG", "INFO"] | None = None
    include_payloads: bool | None = None


class StdioTransportUpdate(BaseModel):
    """Updatable STDIO transport fields."""

    command: str | None = None
    args: list[str] | None = None


class HttpTransportUpdate(BaseModel):
    """Updatable HTTP transport fields."""

    url: str | None = None
    timeout: int | None = Field(
        default=None,
        ge=MIN_HTTP_TIMEOUT_SECONDS,
        le=MAX_HTTP_TIMEOUT_SECONDS,
    )


class BackendConfigUpdate(BaseModel):
    """Updatable backend fields including transport details."""

    server_name: str | None = None
    transport: Literal["stdio", "streamablehttp", "auto"] | None = None
    stdio: StdioTransportUpdate | None = None
    http: HttpTransportUpdate | None = None


class ProxyConfigUpdate(BaseModel):
    """Updatable proxy fields."""

    name: str | None = None


class OIDCConfigUpdate(BaseModel):
    """Updatable OIDC fields."""

    issuer: str | None = None
    client_id: str | None = None
    audience: str | None = None
    scopes: list[str] | None = None


class MTLSConfigUpdate(BaseModel):
    """Updatable mTLS fields."""

    client_cert_path: str | None = None
    client_key_path: str | None = None
    ca_bundle_path: str | None = None


class AuthConfigUpdate(BaseModel):
    """Updatable auth fields."""

    oidc: OIDCConfigUpdate | None = None
    mtls: MTLSConfigUpdate | None = None


class ConfigUpdateRequest(BaseModel):
    """Request body for updating configuration.

    All fields are optional - only specified fields will be updated.
    Changes take effect on proxy restart.
    """

    logging: LoggingConfigUpdate | None = None
    backend: BackendConfigUpdate | None = None
    proxy: ProxyConfigUpdate | None = None
    auth: AuthConfigUpdate | None = None


class ConfigUpdateResponse(BaseModel):
    """Response after updating configuration."""

    config: ConfigResponse
    message: str
