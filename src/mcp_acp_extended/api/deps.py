"""Shared dependencies for API routes.

FastAPI convention: deps.py contains reusable request dependencies.
"""

from __future__ import annotations

__all__ = ["get_proxy_state"]

from typing import TYPE_CHECKING, cast

from fastapi import HTTPException, Request

if TYPE_CHECKING:
    from mcp_acp_extended.manager.state import ProxyState


def get_proxy_state(request: Request) -> "ProxyState":
    """Get ProxyState from request.app.state.

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
