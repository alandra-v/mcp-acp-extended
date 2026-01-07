"""Configuration API endpoints.

Provides configuration management:
- GET /api/config - Read current config (sensitive fields redacted)
- PUT /api/config - Update config (validated, requires restart)

Routes mounted at: /api/config
"""

from __future__ import annotations

__all__ = ["router"]

from fastapi import APIRouter, HTTPException
from pydantic import ValidationError

from mcp_acp_extended.api.deps import ConfigDep
from mcp_acp_extended.api.schemas import (
    AuthConfigResponse,
    BackendConfigResponse,
    ConfigResponse,
    ConfigUpdateRequest,
    ConfigUpdateResponse,
    LoggingConfigResponse,
    ProxyConfigResponse,
)
from mcp_acp_extended.config import AppConfig
from mcp_acp_extended.utils.config import get_config_path

router = APIRouter()


# =============================================================================
# Helpers
# =============================================================================


def _build_config_response(config: AppConfig) -> ConfigResponse:
    """Build API response from AppConfig (redacting sensitive fields)."""
    auth_response = None
    if config.auth:
        auth_response = AuthConfigResponse(
            oidc_issuer=config.auth.oidc.issuer if config.auth.oidc else None,
            has_mtls=config.auth.mtls is not None,
        )

    return ConfigResponse(
        backend=BackendConfigResponse(
            server_name=config.backend.server_name,
            transport=config.backend.transport,
        ),
        logging=LoggingConfigResponse(
            log_dir=config.logging.log_dir,
            log_level=config.logging.log_level,
            include_payloads=config.logging.include_payloads,
        ),
        auth=auth_response,
        proxy=ProxyConfigResponse(name=config.proxy.name),
        config_path=str(get_config_path()),
        requires_restart_for_changes=True,
    )


# =============================================================================
# Endpoints
# =============================================================================


@router.get("")
async def get_config(config: ConfigDep) -> ConfigResponse:
    """Get current configuration.

    Returns configuration with sensitive fields (client_id, secrets,
    full paths) redacted for security.

    Note: This returns the config from memory (as loaded at startup).
    To see file changes, restart the proxy.
    """
    return _build_config_response(config)


@router.put("")
async def update_config(updates: ConfigUpdateRequest) -> ConfigUpdateResponse:
    """Update configuration file.

    Validates changes before saving. Changes take effect on restart.

    Note: Auth configuration is NOT updatable via this API for security.
    Use CLI `mcp-acp-extended init` or edit the config file directly.

    Returns the updated configuration (from file, not memory).
    """
    config_path = get_config_path()

    # Load current config from file (not memory, to get latest)
    try:
        current_config = AppConfig.load_from_files(config_path)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Config file not found")
    except ValueError as e:
        raise HTTPException(status_code=500, detail=f"Invalid config file: {e}")

    # Apply updates to a mutable dict
    update_dict = current_config.model_dump()

    if updates.logging:
        logging_updates = updates.logging.model_dump(exclude_none=True)
        if logging_updates:
            update_dict["logging"].update(logging_updates)

    if updates.backend:
        backend_updates = updates.backend.model_dump(exclude_none=True)
        if backend_updates:
            update_dict["backend"].update(backend_updates)

    if updates.proxy:
        proxy_updates = updates.proxy.model_dump(exclude_none=True)
        if proxy_updates:
            update_dict["proxy"].update(proxy_updates)

    # Validate by constructing new AppConfig
    try:
        new_config = AppConfig.model_validate(update_dict)
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=f"Invalid configuration: {e}")

    # Save to file
    try:
        new_config.save_to_file(config_path)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to save config: {e}")

    return ConfigUpdateResponse(
        config=_build_config_response(new_config),
        message="Configuration saved. Restart proxy to apply changes.",
    )
