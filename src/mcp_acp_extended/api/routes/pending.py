"""Pending HITL approval API endpoints.

Provides real-time streaming and management of pending HITL approval requests.
These are requests currently waiting for user decision, not cached approvals.

Routes mounted at: /api/approvals/pending
"""

from __future__ import annotations

__all__ = ["router"]

import asyncio
import json
from typing import AsyncIterator

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse

from mcp_acp_extended.api.deps import ProxyStateDep
from mcp_acp_extended.api.schemas import ApprovalActionResponse, PendingApprovalResponse
from mcp_acp_extended.manager.state import SSEEventType
from mcp_acp_extended.telemetry.system.system_logger import get_system_logger

logger = get_system_logger()

router = APIRouter()


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
                    try:
                        yield f"data: {json.dumps(event)}\n\n"
                    except (TypeError, ValueError) as e:
                        # Skip non-serializable events rather than crash stream
                        logger.error(
                            "Failed to serialize SSE event: %s (event type: %s)", e, event.get("type")
                        )
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


def _resolve_approval(
    approval_id: str,
    action: str,
    response_status: str,
    state: "ProxyStateDep",
) -> ApprovalActionResponse:
    """Resolve a pending approval with the given action.

    Args:
        approval_id: The pending approval ID.
        action: Resolution action ("allow", "allow_once", "deny").
        response_status: Status string for the response.
        state: Proxy state (injected).

    Returns:
        ApprovalActionResponse with status confirmation.

    Raises:
        HTTPException: 404 if approval not found.
    """
    if not state.resolve_pending(approval_id, action):
        state.emit_system_event(
            SSEEventType.PENDING_NOT_FOUND,
            severity="error",
            message="Approval not found (may have timed out)",
            approval_id=approval_id,
        )
        raise HTTPException(
            status_code=404,
            detail=f"Pending approval '{approval_id}' not found or already resolved",
        )

    return ApprovalActionResponse(status=response_status, approval_id=approval_id)


@router.post("/{approval_id}/approve", response_model=ApprovalActionResponse)
async def approve_pending(approval_id: str, state: ProxyStateDep) -> ApprovalActionResponse:
    """Approve a pending request (caches the approval)."""
    return _resolve_approval(approval_id, "allow", "approved", state)


@router.post("/{approval_id}/allow-once", response_model=ApprovalActionResponse)
async def allow_once_pending(approval_id: str, state: ProxyStateDep) -> ApprovalActionResponse:
    """Allow a pending request without caching."""
    return _resolve_approval(approval_id, "allow_once", "allowed_once", state)


@router.post("/{approval_id}/deny", response_model=ApprovalActionResponse)
async def deny_pending(approval_id: str, state: ProxyStateDep) -> ApprovalActionResponse:
    """Deny a pending request."""
    return _resolve_approval(approval_id, "deny", "denied", state)
