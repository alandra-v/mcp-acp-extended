"""Shared dependencies for API routes.

FastAPI convention: deps.py contains reusable request dependencies.
All route files should import dependencies from here rather than
defining their own helper functions.

Usage with Annotated (recommended):
    from mcp_acp_extended.api.deps import ConfigDep, ProxyStateDep

    @router.get("/status")
    async def get_status(config: ConfigDep, state: ProxyStateDep) -> StatusResponse:
        ...
"""

from __future__ import annotations

__all__ = [
    # Dependency functions
    "get_approval_store",
    "get_config",
    "get_identity_provider",
    "get_oidc_config",
    "get_policy_reloader",
    "get_proxy_state",
    # Type aliases for Annotated pattern
    "ApprovalStoreDep",
    "ConfigDep",
    "IdentityProviderDep",
    "OIDCConfigDep",
    "PolicyReloaderDep",
    "ProxyStateDep",
]

from typing import TYPE_CHECKING, Annotated, cast

from fastapi import Depends, HTTPException, Request

if TYPE_CHECKING:
    from mcp_acp_extended.config import AppConfig, OIDCConfig
    from mcp_acp_extended.manager.state import ProxyState
    from mcp_acp_extended.pep.approval_store import ApprovalStore
    from mcp_acp_extended.pep.reloader import PolicyReloader
    from mcp_acp_extended.pips.auth.oidc_provider import OIDCIdentityProvider


# =============================================================================
# Dependency Functions
# =============================================================================


def get_proxy_state(request: Request) -> "ProxyState":
    """Get ProxyState from app.state.

    Args:
        request: FastAPI request object.

    Returns:
        ProxyState instance.

    Raises:
        HTTPException: 503 if proxy state not available.
    """
    state = getattr(request.app.state, "proxy_state", None)
    if state is None:
        raise HTTPException(
            status_code=503,
            detail="Proxy state not available. Proxy may still be starting.",
        )
    return cast("ProxyState", state)


def get_config(request: Request) -> "AppConfig":
    """Get AppConfig from app.state.

    Args:
        request: FastAPI request object.

    Returns:
        AppConfig instance.

    Raises:
        HTTPException: 503 if config not available.
    """
    config = getattr(request.app.state, "config", None)
    if config is None:
        raise HTTPException(
            status_code=503,
            detail="Config not available. Proxy may still be starting.",
        )
    return cast("AppConfig", config)


def get_policy_reloader(request: Request) -> "PolicyReloader":
    """Get PolicyReloader from app.state.

    Args:
        request: FastAPI request object.

    Returns:
        PolicyReloader instance.

    Raises:
        HTTPException: 503 if policy reloader not available.
    """
    reloader = getattr(request.app.state, "policy_reloader", None)
    if reloader is None:
        raise HTTPException(
            status_code=503,
            detail="Policy reloader not available. Proxy may still be starting.",
        )
    return cast("PolicyReloader", reloader)


def get_approval_store(request: Request) -> "ApprovalStore":
    """Get ApprovalStore from app.state.

    Args:
        request: FastAPI request object.

    Returns:
        ApprovalStore instance.

    Raises:
        HTTPException: 503 if approval store not available.
    """
    store = getattr(request.app.state, "approval_store", None)
    if store is None:
        raise HTTPException(
            status_code=503,
            detail="Approval store not available. Proxy may still be starting.",
        )
    return cast("ApprovalStore", store)


def get_identity_provider(request: Request) -> "OIDCIdentityProvider":
    """Get OIDCIdentityProvider from app.state.

    Args:
        request: FastAPI request object.

    Returns:
        OIDCIdentityProvider instance.

    Raises:
        HTTPException: 503 if identity provider not available.
    """
    provider = getattr(request.app.state, "identity_provider", None)
    if provider is None:
        raise HTTPException(
            status_code=503,
            detail="Identity provider not available. Auth may not be configured.",
        )
    return cast("OIDCIdentityProvider", provider)


def get_oidc_config(request: Request) -> "OIDCConfig":
    """Get OIDCConfig from app.state.config.

    Args:
        request: FastAPI request object.

    Returns:
        OIDCConfig instance.

    Raises:
        HTTPException: 503 if config not available.
        HTTPException: 400 if OIDC not configured.
    """
    config = get_config(request)
    if config.auth is None or config.auth.oidc is None:
        raise HTTPException(
            status_code=400,
            detail="Authentication not configured. Add 'auth.oidc' section to config.",
        )
    return config.auth.oidc


# =============================================================================
# Type Aliases for Annotated Pattern
# =============================================================================
# These allow clean route signatures:
#     async def endpoint(config: ConfigDep) -> Response:
# Instead of:
#     async def endpoint(config: AppConfig = Depends(get_config)) -> Response:


ProxyStateDep = Annotated["ProxyState", Depends(get_proxy_state)]
ConfigDep = Annotated["AppConfig", Depends(get_config)]
PolicyReloaderDep = Annotated["PolicyReloader", Depends(get_policy_reloader)]
ApprovalStoreDep = Annotated["ApprovalStore", Depends(get_approval_store)]
IdentityProviderDep = Annotated["OIDCIdentityProvider", Depends(get_identity_provider)]
OIDCConfigDep = Annotated["OIDCConfig", Depends(get_oidc_config)]
