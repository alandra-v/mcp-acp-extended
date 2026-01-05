"""Cached approvals API endpoints.

Provides visibility into the HITL approval cache for debugging and management.
These are CACHED approvals (previously approved HITL decisions), not pending
HITL requests waiting for user decision.

Routes mounted at: /api/approvals/cached
"""

from __future__ import annotations

__all__ = ["router"]

import time

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from mcp_acp_extended.api.deps import ApprovalStoreDep

router = APIRouter()


class CachedApprovalResponse(BaseModel):
    """Cached approval for API response."""

    subject_id: str
    tool_name: str
    path: str | None
    request_id: str
    age_seconds: float
    ttl_seconds: int
    expires_in_seconds: float


class ApprovalCacheResponse(BaseModel):
    """Full cache state response."""

    count: int
    ttl_seconds: int
    approvals: list[CachedApprovalResponse]


@router.get("")
async def get_approvals(store: ApprovalStoreDep) -> ApprovalCacheResponse:
    """Get all cached approvals.

    Returns the current state of the approval cache for debugging.
    Note: May include expired entries (lazy expiration on lookup).
    """
    now = time.monotonic()
    ttl = store.ttl_seconds

    approvals = []
    for _key, approval in store.iter_all():
        age = now - approval.stored_at
        approvals.append(
            CachedApprovalResponse(
                subject_id=approval.subject_id,
                tool_name=approval.tool_name,
                path=approval.path,
                request_id=approval.request_id,
                age_seconds=round(age, 1),
                ttl_seconds=ttl,
                expires_in_seconds=round(max(0, ttl - age), 1),
            )
        )

    return ApprovalCacheResponse(
        count=len(approvals),
        ttl_seconds=ttl,
        approvals=approvals,
    )


class ClearApprovalsResponse(BaseModel):
    """Response for clear approvals endpoint."""

    cleared: int
    status: str


@router.delete("")
async def clear_approvals(store: ApprovalStoreDep) -> ClearApprovalsResponse:
    """Clear all cached approvals."""
    count = store.clear()
    return ClearApprovalsResponse(cleared=count, status="ok")


class DeleteApprovalResponse(BaseModel):
    """Response for single approval delete."""

    deleted: bool
    status: str


@router.delete("/entry")
async def delete_approval(
    store: ApprovalStoreDep,
    subject_id: str,
    tool_name: str,
    path: str | None = None,
) -> DeleteApprovalResponse:
    """Delete a specific cached approval.

    Args:
        store: Approval store (injected).
        subject_id: The user who approved.
        tool_name: The tool that was approved.
        path: The path that was approved (optional).

    Raises:
        HTTPException: 404 if approval not found.
    """
    deleted = store.delete(subject_id, tool_name, path)
    if not deleted:
        raise HTTPException(
            status_code=404,
            detail=f"Cached approval not found for {subject_id}/{tool_name}/{path}",
        )

    return DeleteApprovalResponse(deleted=True, status="ok")
