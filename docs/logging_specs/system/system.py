from __future__ import annotations
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field


class SystemEvent(BaseModel):
    """
    One system/operational log entry (logs/system/system.jsonl).

    Inspired by:
      - OCSF Application Error (6008): error_type, error_message, stacktrace
      - OCSF Process Activity (1007): component identity, operational activity, status

    Used for WARNING, ERROR, and CRITICAL events that indicate operational issues.
    """

    # --- core ---
    time: Optional[str] = Field(
        None,
        description="ISO 8601 timestamp, added by formatter during serialization",
    )
    level: str  # "WARNING", "ERROR", "CRITICAL"
    event: str  # machine-friendly event name
    message: Optional[str] = None  # human-readable description

    # --- component / context ---
    component: Optional[str] = None  # "proxy", "backend_client", etc.
    session_id: Optional[str] = None  # if tied to an MCP session
    request_id: Optional[str] = None  # if tied to an MCP request
    backend_id: Optional[str] = None  # if backend-specific
    config_version: Optional[str] = None  # config active at the time

    # --- error details ---
    error_type: Optional[str] = None  # Exception class, e.g. TimeoutError
    error_message: Optional[str] = None  # Short error message
    stacktrace: Optional[str] = None  # Optional full traceback

    # --- additional structured details ---
    details: Optional[Dict[str, Any]] = None  # retry_count, timeout_ms, etc.

    class Config:
        extra = "allow"
