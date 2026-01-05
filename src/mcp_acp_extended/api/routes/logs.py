"""Log viewing API endpoints.

Provides read-only access to JSONL log files:
- GET /api/logs/decisions - Policy decision logs
- GET /api/logs/operations - Operation audit logs
- GET /api/logs/auth - Authentication event logs
- GET /api/logs/system - System logs

Routes mounted at: /api/logs
"""

from __future__ import annotations

__all__ = ["router"]

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

from fastapi import APIRouter, Query
from pydantic import BaseModel

from mcp_acp_extended.api.deps import ConfigDep

if TYPE_CHECKING:
    from mcp_acp_extended.config import AppConfig

router = APIRouter()


# =============================================================================
# Response Models
# =============================================================================


class LogsResponse(BaseModel):
    """Response containing log entries."""

    entries: list[dict[str, Any]]
    total_returned: int
    log_file: str
    has_more: bool


# =============================================================================
# Helpers
# =============================================================================


def _get_log_base_path(config: "AppConfig") -> Path:
    """Get base path for log files."""
    return Path(config.logging.log_dir) / "mcp_acp_extended_logs"


def _read_jsonl_tail(
    path: Path,
    limit: int,
    offset: int,
) -> tuple[list[dict[str, Any]], bool]:
    """Read last N entries from JSONL file (newest first).

    Args:
        path: Path to JSONL file.
        limit: Maximum entries to return.
        offset: Number of entries to skip from newest.

    Returns:
        Tuple of (entries, has_more).
    """
    if not path.exists():
        return [], False

    try:
        content = path.read_text(encoding="utf-8")
    except Exception:
        return [], False

    lines = content.strip().split("\n")
    lines = [line for line in lines if line.strip()]  # Filter empty

    # Reverse for newest first
    lines = list(reversed(lines))

    # Check if there are more entries
    total = len(lines)
    has_more = offset + limit < total

    # Apply offset and limit
    lines = lines[offset : offset + limit]

    # Parse JSON
    entries = []
    for line in lines:
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            # Skip malformed lines
            continue

    return entries, has_more


# =============================================================================
# Endpoints
# =============================================================================


@router.get("/decisions")
async def get_decision_logs(
    config: ConfigDep,
    limit: int = Query(default=100, ge=1, le=1000, description="Max entries to return"),
    offset: int = Query(default=0, ge=0, description="Entries to skip (for pagination)"),
) -> LogsResponse:
    """Get policy decision logs (newest first).

    Returns entries from audit/decisions.jsonl including:
    - Timestamp
    - Request details (tool, resource)
    - Policy decision (allow/deny/hitl)
    - Matched rule info
    """
    log_path = _get_log_base_path(config) / "audit" / "decisions.jsonl"

    entries, has_more = _read_jsonl_tail(log_path, limit, offset)

    return LogsResponse(
        entries=entries,
        total_returned=len(entries),
        log_file=str(log_path),
        has_more=has_more,
    )


@router.get("/operations")
async def get_operation_logs(
    config: ConfigDep,
    limit: int = Query(default=100, ge=1, le=1000, description="Max entries to return"),
    offset: int = Query(default=0, ge=0, description="Entries to skip (for pagination)"),
) -> LogsResponse:
    """Get operation audit logs (newest first).

    Returns entries from audit/operations.jsonl including:
    - Timestamp
    - Operation type
    - Subject (user) info
    - Resource accessed
    - Outcome
    """
    log_path = _get_log_base_path(config) / "audit" / "operations.jsonl"

    entries, has_more = _read_jsonl_tail(log_path, limit, offset)

    return LogsResponse(
        entries=entries,
        total_returned=len(entries),
        log_file=str(log_path),
        has_more=has_more,
    )


@router.get("/auth")
async def get_auth_logs(
    config: ConfigDep,
    limit: int = Query(default=100, ge=1, le=1000, description="Max entries to return"),
    offset: int = Query(default=0, ge=0, description="Entries to skip (for pagination)"),
) -> LogsResponse:
    """Get authentication event logs (newest first).

    Returns entries from audit/auth.jsonl including:
    - Timestamp
    - Event type (login, logout, token refresh, validation failure)
    - Subject info
    - Outcome
    """
    log_path = _get_log_base_path(config) / "audit" / "auth.jsonl"

    entries, has_more = _read_jsonl_tail(log_path, limit, offset)

    return LogsResponse(
        entries=entries,
        total_returned=len(entries),
        log_file=str(log_path),
        has_more=has_more,
    )


@router.get("/system")
async def get_system_logs(
    config: ConfigDep,
    limit: int = Query(default=100, ge=1, le=1000, description="Max entries to return"),
    offset: int = Query(default=0, ge=0, description="Entries to skip (for pagination)"),
) -> LogsResponse:
    """Get system logs (newest first).

    Returns entries from system/system.jsonl including:
    - Timestamp
    - Log level
    - Event type
    - Component
    - Message/details
    """
    log_path = _get_log_base_path(config) / "system" / "system.jsonl"

    entries, has_more = _read_jsonl_tail(log_path, limit, offset)

    return LogsResponse(
        entries=entries,
        total_returned=len(entries),
        log_file=str(log_path),
        has_more=has_more,
    )
