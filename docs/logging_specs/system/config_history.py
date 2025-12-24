from __future__ import annotations
from typing import Optional, Literal, Dict, Any
from pydantic import BaseModel, Field


class ConfigHistoryEvent(BaseModel):
    """
    One configuration history log entry (logs/system/config_history.jsonl).

    Captures the full lifecycle of configuration:
    - config_created: Initial configuration creation via CLI init
    - config_updated: Configuration updated via CLI commands
    - config_loaded: Configuration loaded at proxy startup
    - manual_change_detected: File modified outside of CLI (checksum mismatch)
    - config_validation_failed: Invalid JSON or schema validation error

    The design follows general security logging and configuration
    management guidance (e.g., OWASP logging recommendations,
    NIST SP 800-128 for security-focused configuration management,
    and NIST SP 800-92 / CIS Control 8 for audit log management),
    by recording when configuration changes occur, which version
    is active, and a snapshot sufficient to reconstruct the effective
    configuration during later analysis.
    """

    # --- core ---
    time: Optional[str] = Field(
        None,
        description="ISO 8601 timestamp, added by formatter during serialization",
    )
    event: Literal[
        "config_created",
        "config_updated",
        "config_loaded",
        "manual_change_detected",
        "config_validation_failed",
    ]
    message: Optional[str] = None  # human-readable description

    # --- versioning ---
    config_version: str  # version ID (e.g., "v1", "v2")
    previous_version: Optional[str] = None
    change_type: Literal[
        "initial_load",  # First time config is created
        "cli_update",  # CLI update command
        "manual_edit",  # Detected manual file edit
        "startup_load",  # Loading config on proxy startup
        "validation_error",  # Config failed validation
    ]

    # --- source / component ---
    component: Optional[str] = None  # e.g. "cli", "proxy", "config"
    config_path: Optional[str] = None  # path to the config file on disk
    source: Optional[str] = None  # e.g. "cli_init", "cli_update", "proxy_startup"

    # --- integrity ---
    checksum: str  # e.g. "sha256:abcd1234..."

    # --- snapshot ---
    snapshot_format: Literal["yaml", "json"] = "json"
    snapshot: Optional[str] = None  # full config content (optional for load events)

    # --- change details (for update events) ---
    changes: Optional[Dict[str, Dict[str, Any]]] = None  # {"path": {"old": x, "new": y}}

    # --- error details (for validation failures) ---
    error_type: Optional[str] = None  # e.g. "JSONDecodeError", "ValidationError"
    error_message: Optional[str] = None  # human-readable error

    class Config:
        extra = "forbid"
