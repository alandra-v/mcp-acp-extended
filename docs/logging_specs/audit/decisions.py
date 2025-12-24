from __future__ import annotations
from typing import Optional, List, Literal
from pydantic import BaseModel, Field


class DecisionEvent(BaseModel):
    """
    One policy decision log entry (audit/decisions.jsonl).

    Records the outcome of a single ABAC policy evaluation for one MCP request.
    Includes rule-level attribution, summarized resource context, timing data,
    and optional human-in-the-loop (HITL) information.
    """

    # --- core ---
    time: Optional[str] = Field(
        None,
        description="ISO 8601 timestamp, added by formatter during serialization",
    )
    event: Literal["policy_decision"] = "policy_decision"

    # --- decision outcome ---
    decision: Literal["allow", "deny", "hitl"]
    matched_rules: List[str] = Field(default_factory=list)
    final_rule: str  # Rule ID that determined outcome, or "default", "discovery_bypass"

    # --- context summary (not full context for privacy) ---
    mcp_method: str
    tool_name: Optional[str] = None
    path: Optional[str] = None  # File path (from tool arguments)
    uri: Optional[str] = None  # Resource URI (from resources/read)
    scheme: Optional[str] = None  # URI scheme (file, https, s3, etc.)
    subject_id: Optional[str] = None  # Optional until auth is fully implemented
    backend_id: str  # Backend server ID (always known from config)
    is_mutating: bool = False  # Whether the action is mutating
    side_effects: Optional[List[str]] = None  # Tool side effects

    # --- policy ---
    policy_version: str  # Policy version for replay/forensics (always loaded)

    # --- performance ---
    policy_eval_ms: float  # Policy rule evaluation time
    policy_hitl_ms: Optional[float] = None  # HITL wait time (only for HITL decisions)
    policy_total_ms: float  # Total evaluation time (eval + HITL)

    # --- correlation ---
    request_id: str  # JSON-RPC request ID (every decision has a request)
    session_id: Optional[str] = None  # May not exist during initialize

    # --- HITL-specific fields (only when decision == "hitl") ---
    hitl_outcome: Optional[Literal["user_allowed", "user_denied", "timeout"]] = None

    class Config:
        extra = "forbid"
