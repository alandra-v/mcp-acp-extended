"""Configuration API schemas."""

from __future__ import annotations

__all__ = [
    "AuthConfigResponse",
    "BackendConfigResponse",
    "BackendConfigUpdate",
    "ConfigResponse",
    "ConfigUpdateRequest",
    "ConfigUpdateResponse",
    "LoggingConfigResponse",
    "LoggingConfigUpdate",
    "ProxyConfigResponse",
    "ProxyConfigUpdate",
]

from typing import Literal

from pydantic import BaseModel


class BackendConfigResponse(BaseModel):
    """Backend configuration (safe to expose)."""

    server_name: str
    transport: str | None


class LoggingConfigResponse(BaseModel):
    """Logging configuration (safe to expose)."""

    log_dir: str
    log_level: str
    include_payloads: bool


class AuthConfigResponse(BaseModel):
    """Auth configuration (sensitive fields redacted)."""

    oidc_issuer: str | None
    has_mtls: bool


class ProxyConfigResponse(BaseModel):
    """Proxy configuration (safe to expose)."""

    name: str


class ConfigResponse(BaseModel):
    """Full configuration response (sensitive fields redacted)."""

    backend: BackendConfigResponse
    logging: LoggingConfigResponse
    auth: AuthConfigResponse | None
    proxy: ProxyConfigResponse
    config_path: str
    requires_restart_for_changes: bool = True


class LoggingConfigUpdate(BaseModel):
    """Updatable logging fields."""

    log_dir: str | None = None
    log_level: Literal["DEBUG", "INFO"] | None = None
    include_payloads: bool | None = None


class BackendConfigUpdate(BaseModel):
    """Updatable backend fields."""

    server_name: str | None = None
    transport: Literal["stdio", "streamablehttp"] | None = None


class ProxyConfigUpdate(BaseModel):
    """Updatable proxy fields."""

    name: str | None = None


class ConfigUpdateRequest(BaseModel):
    """Request body for updating configuration.

    Note: Auth config is NOT updatable via API for security.
    Use CLI or edit config file directly.
    """

    logging: LoggingConfigUpdate | None = None
    backend: BackendConfigUpdate | None = None
    proxy: ProxyConfigUpdate | None = None


class ConfigUpdateResponse(BaseModel):
    """Response after updating configuration."""

    config: ConfigResponse
    message: str
