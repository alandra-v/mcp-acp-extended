from __future__ import annotations
from typing import Optional, Dict, List, Literal
from pydantic import BaseModel, Field


class SubjectIdentity(BaseModel):
    """
    Identity of the human user, derived from the OIDC token.
    """

    subject_id: str  # OIDC 'sub'
    subject_claims: Optional[Dict[str, str]] = None  # selected safe claims


class OIDCInfo(BaseModel):
    """
    Details about the OIDC/OAuth token and provider, for authentication logs.
    """

    issuer: str  # OIDC 'iss'
    provider: Optional[str] = None  # friendly name, e.g. "google", "auth0"
    client_id: Optional[str] = None  # upstream client_id

    audience: Optional[List[str]] = None  # normalized 'aud' as list
    scopes: Optional[List[str]] = None  # token scopes, if available

    token_type: Optional[str] = None  # "access", "id", "proxy", etc.
    token_exp: Optional[str] = None  # ISO 8601 expiration time
    token_iat: Optional[str] = None  # ISO 8601 issued-at time
    token_expired: Optional[bool] = None  # whether expired at validation time


class DeviceHealthChecks(BaseModel):
    """
    Results of individual device health checks.
    """

    disk_encryption: Literal["pass", "fail", "skip"]
    firewall: Literal["pass", "fail", "skip"]


class AuthEvent(BaseModel):
    """
    One authentication log entry (audit/auth.jsonl).

    Records authentication events for Zero Trust compliance:
    - Token validation (success/failure)
    - Token refresh attempts
    - Session lifecycle (start/end)
    - Device health checks (pass/fail)

    Uses fail-closed handler - if auth logging fails, proxy shuts down.
    """

    # --- core ---
    time: Optional[str] = Field(
        None,
        description="ISO 8601 timestamp, added by formatter during serialization",
    )
    event: Literal[
        "token_validated",
        "token_invalid",
        "token_refreshed",
        "token_refresh_failed",
        "session_started",
        "session_ended",
        "device_health_passed",
        "device_health_failed",
    ]
    status: Literal["Success", "Failure"]

    # --- correlation ---
    session_id: Optional[str] = None  # MCP session ID (may not exist yet)
    request_id: Optional[str] = None  # JSON-RPC request ID (for per-request checks)

    # --- identity ---
    subject: Optional[SubjectIdentity] = None  # None if token couldn't be parsed

    # --- OIDC/OAuth details ---
    oidc: Optional[OIDCInfo] = None

    # --- device health (for device_health events) ---
    device_checks: Optional[DeviceHealthChecks] = None

    # --- context ---
    method: Optional[str] = None  # MCP method for per-request validation
    message: Optional[str] = None  # Human-readable status message

    # --- errors (for failure events) ---
    error_type: Optional[str] = None  # e.g. "TokenExpiredError"
    error_message: Optional[str] = None  # Detailed error message

    # --- session end details ---
    end_reason: Optional[Literal["normal", "timeout", "error", "auth_expired"]] = None

    class Config:
        extra = "forbid"
