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

from mcp_acp_extended.api.deps import ConfigDep
from mcp_acp_extended.api.schemas import LogsResponse

if TYPE_CHECKING:
    from mcp_acp_extended.config import AppConfig

router = APIRouter()


# =============================================================================
# Helpers
# =============================================================================


def _get_log_base_path(config: "AppConfig") -> Path:
    """Get base path for log files."""
    return Path(config.logging.log_dir) / "mcp_acp_extended_logs"


# Maximum bytes to read from a log file (10MB)
# Prevents OOM on very large log files
_MAX_READ_BYTES = 10 * 1024 * 1024


def _read_jsonl_tail(
    path: Path,
    limit: int,
    offset: int,
) -> tuple[list[dict[str, Any]], bool]:
    """Read last N entries from JSONL file (newest first).

    Uses reverse file reading to efficiently get recent entries without
    loading the entire file into memory. Limited to last 10MB of file.

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
        file_size = path.stat().st_size
        if file_size == 0:
            return [], False

        # Read at most _MAX_READ_BYTES from end of file
        read_size = min(file_size, _MAX_READ_BYTES)

        with path.open("rb") as f:
            # Seek to position to start reading
            f.seek(max(0, file_size - read_size))

            # If we didn't start at beginning, skip partial first line
            if file_size > read_size:
                f.readline()  # Discard partial line

            # Read remaining content
            content = f.read().decode("utf-8", errors="replace")

    except Exception:
        return [], False

    lines = content.strip().split("\n")
    lines = [line for line in lines if line.strip()]  # Filter empty

    # Reverse for newest first
    lines = list(reversed(lines))

    # Check if there are more entries (approximate if file was truncated)
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

# Log file paths relative to log base directory
_LOG_PATHS = {
    "decisions": "audit/decisions.jsonl",
    "operations": "audit/operations.jsonl",
    "auth": "audit/auth.jsonl",
    "system": "system/system.jsonl",
}


def _get_logs(config: "AppConfig", log_type: str, limit: int, offset: int) -> LogsResponse:
    """Get log entries from the specified log file.

    Args:
        config: App configuration.
        log_type: Log type key (decisions, operations, auth, system).
        limit: Maximum entries to return.
        offset: Entries to skip for pagination.

    Returns:
        LogsResponse with entries and pagination info.
    """
    log_path = _get_log_base_path(config) / _LOG_PATHS[log_type]
    entries, has_more = _read_jsonl_tail(log_path, limit, offset)

    return LogsResponse(
        entries=entries,
        total_returned=len(entries),
        log_file=str(log_path),
        has_more=has_more,
    )


@router.get("/decisions")
async def get_decision_logs(
    config: ConfigDep,
    limit: int = Query(default=100, ge=1, le=1000, description="Max entries to return"),
    offset: int = Query(default=0, ge=0, description="Entries to skip (for pagination)"),
) -> LogsResponse:
    """Get policy decision logs (newest first).

    Returns entries from audit/decisions.jsonl including:
    - Timestamp, request details, policy decision, matched rule info
    """
    return _get_logs(config, "decisions", limit, offset)


@router.get("/operations")
async def get_operation_logs(
    config: ConfigDep,
    limit: int = Query(default=100, ge=1, le=1000, description="Max entries to return"),
    offset: int = Query(default=0, ge=0, description="Entries to skip (for pagination)"),
) -> LogsResponse:
    """Get operation audit logs (newest first).

    Returns entries from audit/operations.jsonl including:
    - Timestamp, operation type, subject info, resource accessed, outcome
    """
    return _get_logs(config, "operations", limit, offset)


@router.get("/auth")
async def get_auth_logs(
    config: ConfigDep,
    limit: int = Query(default=100, ge=1, le=1000, description="Max entries to return"),
    offset: int = Query(default=0, ge=0, description="Entries to skip (for pagination)"),
) -> LogsResponse:
    """Get authentication event logs (newest first).

    Returns entries from audit/auth.jsonl including:
    - Timestamp, event type (login, logout, refresh, validation failure), subject info
    """
    return _get_logs(config, "auth", limit, offset)


@router.get("/system")
async def get_system_logs(
    config: ConfigDep,
    limit: int = Query(default=100, ge=1, le=1000, description="Max entries to return"),
    offset: int = Query(default=0, ge=0, description="Entries to skip (for pagination)"),
) -> LogsResponse:
    """Get system logs (newest first).

    Returns entries from system/system.jsonl including:
    - Timestamp, log level, event type, component, message/details
    """
    return _get_logs(config, "system", limit, offset)
