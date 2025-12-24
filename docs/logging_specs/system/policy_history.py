from __future__ import annotations
from typing import Optional, Literal, Dict, Any
from pydantic import BaseModel, Field


class PolicyHistoryEvent(BaseModel):
    """
    One policy history log entry (logs/system/policy_history.jsonl).

    Captures the full lifecycle of policy configuration:
    - policy_created: Initial policy creation via CLI init
    - policy_loaded: Policy loaded at proxy startup
    - policy_updated: Policy updated (e.g., rule added/removed)
    - manual_change_detected: File modified outside of proxy (checksum mismatch)
    - policy_validation_failed: Invalid JSON or schema validation error

    The design mirrors ConfigHistoryEvent for consistency.
    """

    # --- core ---
    time: Optional[str] = Field(
        None,
        description="ISO 8601 timestamp, added by formatter during serialization",
    )
    event: Literal[
        "policy_created",
        "policy_loaded",
        "policy_updated",
        "manual_change_detected",
        "policy_validation_failed",
    ]
    message: Optional[str] = None  # human-readable description

    # --- versioning ---
    policy_version: str  # version ID (e.g., "v1", "v2")
    previous_version: Optional[str] = None
    change_type: Literal[
        "initial_creation",  # First time policy is created
        "startup_load",  # Loading policy on proxy startup
        "rule_update",  # Rules added/removed
        "manual_edit",  # Detected manual file edit
        "validation_error",  # Policy failed validation
    ]

    # --- source / component ---
    component: Optional[str] = None  # e.g. "cli", "proxy", "pep", "hitl"
    policy_path: Optional[str] = None  # path to policy.json on disk
    source: Optional[str] = None  # e.g. "cli_init", "proxy_startup", "hitl_handler"

    # --- integrity ---
    checksum: str  # e.g. "sha256:abcd1234..."

    # --- snapshot ---
    snapshot_format: Literal["json"] = "json"
    snapshot: Optional[str] = None  # full policy content (optional for load events)

    # --- rule details (for rule updates) ---
    rule_id: Optional[str] = None  # ID of added/removed rule
    rule_effect: Optional[str] = None  # "allow", "deny", "hitl"
    rule_conditions: Optional[Dict[str, Any]] = None  # conditions of added rule

    # --- error details (for validation failures) ---
    error_type: Optional[str] = None  # e.g. "JSONDecodeError", "ValidationError"
    error_message: Optional[str] = None  # human-readable error

    class Config:
        extra = "forbid"
