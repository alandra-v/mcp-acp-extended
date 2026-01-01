"""Proxy control API endpoints.

Provides:
- GET /status - Current proxy and policy status
- POST /reload-policy - Hot reload policy from disk

Note: Start/stop/restart are placeholders for future multi-proxy Manager.
The proxy is spawned by Claude Desktop, not controlled via this API.
"""

__all__ = [
    "router",
    "ProxyStatus",
    "ReloadResponse",
]

from typing import TYPE_CHECKING, cast

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

if TYPE_CHECKING:
    from mcp_acp_extended.pep.reloader import PolicyReloader

router = APIRouter()


class ProxyStatus(BaseModel):
    """Proxy and policy status."""

    running: bool
    uptime_seconds: float
    policy_version: str | None
    policy_rules_count: int
    last_reload_at: str | None
    reload_count: int


class ReloadResponse(BaseModel):
    """Policy reload response."""

    status: str  # "success", "validation_error", "file_error"
    old_rules_count: int
    new_rules_count: int
    approvals_cleared: int
    error: str | None = None
    policy_version: str | None = None


def _get_reloader(request: Request) -> "PolicyReloader":
    """Get PolicyReloader from app state.

    Raises:
        HTTPException: If reloader not configured (proxy not fully started).
    """
    reloader = getattr(request.app.state, "policy_reloader", None)
    if reloader is None:
        raise HTTPException(
            status_code=503,
            detail="Policy reloader not available. Proxy may still be starting.",
        )
    return cast("PolicyReloader", reloader)


@router.get("/status")
async def get_status(request: Request) -> ProxyStatus:
    """Get current proxy and policy status.

    Returns:
        ProxyStatus with uptime, policy version, rules count, reload info.
    """
    reloader = _get_reloader(request)

    return ProxyStatus(
        running=True,
        uptime_seconds=reloader.uptime_seconds,
        policy_version=reloader.current_version,
        policy_rules_count=reloader.current_rules_count,
        last_reload_at=reloader.last_reload_at,
        reload_count=reloader.reload_count,
    )


@router.post("/reload-policy")
async def reload_policy(request: Request) -> ReloadResponse:
    """Reload policy from disk without restarting proxy.

    Validates the new policy before applying. On validation failure,
    the old policy remains active (Last Known Good pattern).

    Returns:
        ReloadResponse with status, rule counts, and version info.
    """
    reloader = _get_reloader(request)
    result = await reloader.reload()

    return ReloadResponse(
        status=result.status,
        old_rules_count=result.old_rules_count,
        new_rules_count=result.new_rules_count,
        approvals_cleared=result.approvals_cleared,
        error=result.error,
        policy_version=result.policy_version,
    )


# ============================================================================
# Placeholders for future multi-proxy Manager
# These will be implemented when Manager architecture is added
# ============================================================================


@router.post("/start")
async def start_proxy() -> dict[str, str]:
    """Start the proxy (placeholder).

    Note: Currently the proxy is spawned by Claude Desktop via STDIO.
    This endpoint will be implemented for the Manager architecture.
    """
    return {"status": "not_implemented", "message": "Proxy is managed by MCP client"}


@router.post("/stop")
async def stop_proxy() -> dict[str, str]:
    """Stop the proxy (placeholder).

    Note: Currently the proxy lifecycle is managed by Claude Desktop.
    This endpoint will be implemented for the Manager architecture.
    """
    return {"status": "not_implemented", "message": "Proxy is managed by MCP client"}


@router.post("/restart")
async def restart_proxy() -> dict[str, str]:
    """Restart the proxy (placeholder).

    Note: Currently requires restarting Claude Desktop.
    This endpoint will be implemented for the Manager architecture.
    """
    return {"status": "not_implemented", "message": "Proxy is managed by MCP client"}
