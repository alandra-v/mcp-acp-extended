"""Proxy control API endpoints.

Provides:
- GET /status - Current proxy and policy status
- POST /reload-policy - Hot reload policy from disk

Note: Proxy lifecycle management (start/stop/restart) will be added
in the multi-proxy Manager phase. See ui-progress.md.
"""

__all__ = [
    "router",
    "ProxyStatus",
    "ReloadResponse",
]

from fastapi import APIRouter
from pydantic import BaseModel

from mcp_acp_extended.api.deps import PolicyReloaderDep

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


@router.get("/status")
async def get_status(reloader: PolicyReloaderDep) -> ProxyStatus:
    """Get current proxy and policy status.

    Returns:
        ProxyStatus with uptime, policy version, rules count, reload info.
    """
    return ProxyStatus(
        running=True,
        uptime_seconds=reloader.uptime_seconds,
        policy_version=reloader.current_version,
        policy_rules_count=reloader.current_rules_count,
        last_reload_at=reloader.last_reload_at,
        reload_count=reloader.reload_count,
    )


@router.post("/reload-policy")
async def reload_policy(reloader: PolicyReloaderDep) -> ReloadResponse:
    """Reload policy from disk without restarting proxy.

    Validates the new policy before applying. On validation failure,
    the old policy remains active (Last Known Good pattern).

    Returns:
        ReloadResponse with status, rule counts, and version info.
    """
    result = await reloader.reload()

    return ReloadResponse(
        status=result.status,
        old_rules_count=result.old_rules_count,
        new_rules_count=result.new_rules_count,
        approvals_cleared=result.approvals_cleared,
        error=result.error,
        policy_version=result.policy_version,
    )
