"""Proxy information API endpoints.

Provides visibility into running proxy instances.

Routes mounted at: /api/proxies
"""

from __future__ import annotations

__all__ = ["router"]

from datetime import datetime

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from mcp_acp_extended.api.deps import get_proxy_state

router = APIRouter()


class ProxyResponse(BaseModel):
    """Response model for proxy information."""

    id: str
    backend_id: str
    status: str
    started_at: datetime
    pid: int
    api_port: int
    uptime_seconds: float


@router.get("", response_model=list[ProxyResponse])
async def list_proxies(request: Request) -> list[ProxyResponse]:
    """List all proxies.

    Returns array with single entry for this proxy.
    In multi-proxy Phase 2, Manager will aggregate from multiple proxies.
    """
    state = get_proxy_state(request)
    info = state.get_proxy_info()

    return [
        ProxyResponse(
            id=info.id,
            backend_id=info.backend_id,
            status=info.status,
            started_at=info.started_at,
            pid=info.pid,
            api_port=info.api_port,
            uptime_seconds=info.uptime_seconds,
        )
    ]


@router.get("/{proxy_id}", response_model=ProxyResponse)
async def get_proxy(proxy_id: str, request: Request) -> ProxyResponse:
    """Get details for a specific proxy.

    Args:
        proxy_id: The proxy ID to look up.

    Returns:
        ProxyResponse with proxy details.

    Raises:
        HTTPException: 404 if proxy not found.
    """
    state = get_proxy_state(request)
    info = state.get_proxy_info()

    if info.id != proxy_id:
        raise HTTPException(status_code=404, detail=f"Proxy '{proxy_id}' not found")

    return ProxyResponse(
        id=info.id,
        backend_id=info.backend_id,
        status=info.status,
        started_at=info.started_at,
        pid=info.pid,
        api_port=info.api_port,
        uptime_seconds=info.uptime_seconds,
    )
