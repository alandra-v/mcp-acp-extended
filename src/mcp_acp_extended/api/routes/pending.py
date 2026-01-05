"""Pending HITL approval API endpoints.

Provides real-time streaming and management of pending HITL approval requests.
These are requests currently waiting for user decision, not cached approvals.

Routes mounted at: /api/approvals/pending
"""

from __future__ import annotations

__all__ = ["router"]

import asyncio
import json
import logging
from datetime import datetime
from typing import AsyncIterator

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from mcp_acp_extended.api.deps import ProxyStateDep

logger = logging.getLogger(__name__)

router = APIRouter()


class PendingApprovalResponse(BaseModel):
    """Response model for pending approval information."""

    id: str
    proxy_id: str
    tool_name: str
    path: str | None
    subject_id: str
    created_at: datetime
    timeout_seconds: int
    request_id: str


class ApprovalActionResponse(BaseModel):
    """Response model for approval actions (approve/deny)."""

    status: str
    approval_id: str


@router.get("")
async def pending_approvals_stream(state: ProxyStateDep) -> StreamingResponse:
    """SSE stream of pending approvals.

    Streams events for:
    - Current pending approvals (on connect)
    - New pending approvals
    - Resolution events (approve/deny)
    - Timeout events

    Event format:
        data: {"type": "...", ...}

    Types:
        - pending_created: New pending approval
        - pending_resolved: Approval was resolved
        - pending_timeout: Approval timed out
        - snapshot: Initial list of pending approvals
    """

    async def event_generator() -> AsyncIterator[str]:
        queue = state.subscribe()
        logger.info("SSE client connected for pending approvals")
        try:
            # Send current pending approvals first (snapshot)
            pending = state.get_pending_approvals()
            snapshot = {
                "type": "snapshot",
                "approvals": [p.to_dict() for p in pending],
            }
            yield f"data: {json.dumps(snapshot)}\n\n"

            # Stream new events
            while True:
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=30)
                    yield f"data: {json.dumps(event)}\n\n"
                except asyncio.TimeoutError:
                    # Send keepalive comment to prevent connection timeout
                    yield ": keepalive\n\n"
        finally:
            state.unsubscribe(queue)
            logger.info("SSE client disconnected from pending approvals")

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",  # Disable nginx buffering
        },
    )


@router.get("/list", response_model=list[PendingApprovalResponse])
async def list_pending_approvals(state: ProxyStateDep) -> list[PendingApprovalResponse]:
    """List pending approvals (non-SSE).

    Alternative to SSE stream for clients that don't support SSE.
    Returns current pending approvals without streaming.
    """
    pending = state.get_pending_approvals()

    return [
        PendingApprovalResponse(
            id=p.id,
            proxy_id=p.proxy_id,
            tool_name=p.tool_name,
            path=p.path,
            subject_id=p.subject_id,
            created_at=p.created_at,
            timeout_seconds=p.timeout_seconds,
            request_id=p.request_id,
        )
        for p in pending
    ]


@router.post("/{approval_id}/approve", response_model=ApprovalActionResponse)
async def approve_pending(approval_id: str, state: ProxyStateDep) -> ApprovalActionResponse:
    """Approve a pending request.

    Args:
        approval_id: The pending approval ID.
        state: Proxy state (injected).

    Returns:
        Status confirmation.

    Raises:
        HTTPException: 404 if approval not found.
    """
    if not state.resolve_pending(approval_id, "allow"):
        raise HTTPException(
            status_code=404,
            detail=f"Pending approval '{approval_id}' not found or already resolved",
        )

    return ApprovalActionResponse(status="approved", approval_id=approval_id)


@router.post("/{approval_id}/deny", response_model=ApprovalActionResponse)
async def deny_pending(approval_id: str, state: ProxyStateDep) -> ApprovalActionResponse:
    """Deny a pending request.

    Args:
        approval_id: The pending approval ID.
        state: Proxy state (injected).

    Returns:
        Status confirmation.

    Raises:
        HTTPException: 404 if approval not found.
    """
    if not state.resolve_pending(approval_id, "deny"):
        raise HTTPException(
            status_code=404,
            detail=f"Pending approval '{approval_id}' not found or already resolved",
        )

    return ApprovalActionResponse(status="denied", approval_id=approval_id)
