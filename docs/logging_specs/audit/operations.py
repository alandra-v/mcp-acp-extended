from __future__ import annotations
from typing import Optional, Dict
from pydantic import BaseModel, Field


class SubjectIdentity(BaseModel):
    """
    Identity of the human user, derived from the OIDC token.
    """

    subject_id: str  # OIDC 'sub'
    subject_claims: Optional[Dict[str, str]] = None  # selected safe claims


class ArgumentsSummary(BaseModel):
    """
    Summary of MCP request arguments (without logging full sensitive payloads).
    """

    redacted: bool = True
    body_hash: Optional[str] = None  # SHA256 hex string
    payload_length: Optional[int] = None  # request size in bytes


class DurationInfo(BaseModel):
    """
    Duration measurement for this MCP operation.

    Measures total operation time from the proxy's perspective.
    """

    duration_ms: float = Field(..., description="Total operation duration in milliseconds")


class ResponseSummary(BaseModel):
    """
    Summary of MCP response metadata (without logging full payloads).
    """

    size_bytes: int = Field(..., description="Response payload size in bytes")
    body_hash: str = Field(..., description="SHA256 hash of response payload")


class OperationEvent(BaseModel):
    """
    One MCP operation log entry (audit/operations.jsonl).

    Captures security-relevant information about each MCP operation
    (who did what, when, with what outcome).
    """

    # --- core ---
    time: Optional[str] = Field(
        None,
        description="ISO 8601 timestamp, added by formatter during serialization",
    )
    session_id: str
    request_id: str
    method: str  # MCP method ("tools/call", ...)

    status: str  # "Success" or "Failure"
    error_code: Optional[int] = None  # MCP/JSON-RPC error code
    message: Optional[str] = None

    # --- identity ---
    subject: SubjectIdentity

    # --- client/backend info ---
    client_id: Optional[str] = None  # MCP client application name
    backend_id: str  # internal MCP backend identifier
    transport: Optional[str] = None  # "stdio" or "streamablehttp"

    # --- MCP details ---
    tool_name: Optional[str] = None  # only for tools/call
    file_path: Optional[str] = None
    file_extension: Optional[str] = None
    arguments_summary: Optional[ArgumentsSummary] = None

    # --- config ---
    config_version: Optional[str] = None

    # --- duration ---
    duration: DurationInfo

    # --- response metadata ---
    response_summary: Optional[ResponseSummary] = None

    class Config:
        extra = "forbid"
