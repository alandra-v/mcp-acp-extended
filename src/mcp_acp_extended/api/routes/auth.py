"""Authentication API endpoints.

Provides authentication management with full CLI parity:
- GET /api/auth/status - Check auth status and get user info
- POST /api/auth/login - Start device flow authentication
- GET /api/auth/login/poll - Poll for device flow completion
- POST /api/auth/logout - Local logout (clear keychain)
- POST /api/auth/logout-federated - Federated logout (Auth0)

Routes mounted at: /api/auth
"""

from __future__ import annotations

__all__ = ["router"]

import asyncio
import time
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Literal, cast

import httpx
from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel

from mcp_acp_extended.api.deps import OIDCConfigDep
from mcp_acp_extended.constants import OAUTH_CLIENT_TIMEOUT_SECONDS
from mcp_acp_extended.exceptions import AuthenticationError
from mcp_acp_extended.security.auth.device_flow import (
    DeviceCodeResponse,
    DeviceFlow,
    DeviceFlowDeniedError,
    DeviceFlowError,
    DeviceFlowExpiredError,
)
from mcp_acp_extended.security.auth.token_storage import (
    StoredToken,
    create_token_storage,
    get_token_storage_info,
)

if TYPE_CHECKING:
    from mcp_acp_extended.config import OIDCConfig
    from mcp_acp_extended.pips.auth.oidc_provider import OIDCIdentityProvider

router = APIRouter()


# =============================================================================
# Response Models
# =============================================================================


class AuthStatusResponse(BaseModel):
    """Authentication status response."""

    authenticated: bool
    subject_id: str | None = None
    email: str | None = None
    name: str | None = None
    token_expires_in_hours: float | None = None
    has_refresh_token: bool | None = None
    storage_backend: str | None = None


class DeviceFlowStartResponse(BaseModel):
    """Response when starting device flow."""

    user_code: str
    verification_uri: str
    verification_uri_complete: str | None = None
    expires_in: int
    interval: int
    poll_endpoint: str


class DeviceFlowPollResponse(BaseModel):
    """Response when polling device flow."""

    status: Literal["pending", "complete", "expired", "denied", "error"]
    message: str | None = None


class LogoutResponse(BaseModel):
    """Logout response."""

    status: str
    message: str


class FederatedLogoutResponse(BaseModel):
    """Federated logout response."""

    status: str
    logout_url: str
    message: str


# =============================================================================
# In-memory device flow state
# =============================================================================


class _DeviceFlowState:
    """Tracks an active device flow."""

    def __init__(self, device_code: DeviceCodeResponse, oidc_config: "OIDCConfig") -> None:
        self.device_code = device_code
        self.oidc_config = oidc_config
        self.created_at = time.monotonic()
        self.completed = False
        self.error: str | None = None
        self.error_type: str | None = None


# Device flow state storage (in-memory, keyed by user_code)
# Cleaned up on completion, expiry, or error
# Max 100 concurrent flows to prevent memory exhaustion
_device_flows: dict[str, _DeviceFlowState] = {}
_MAX_DEVICE_FLOWS = 100


# =============================================================================
# Helpers
# =============================================================================


def _cleanup_expired_flows() -> None:
    """Remove expired device flows from memory."""
    now = time.monotonic()
    expired = [
        code for code, state in _device_flows.items() if now - state.created_at > state.device_code.expires_in
    ]
    for code in expired:
        del _device_flows[code]


# =============================================================================
# Endpoints
# =============================================================================


def _unauthenticated_response() -> AuthStatusResponse:
    """Build standard unauthenticated response with storage info."""
    storage_info = get_token_storage_info()
    return AuthStatusResponse(
        authenticated=False,
        storage_backend=storage_info.get("backend"),
    )


def _get_identity_provider_optional(request: Request) -> "OIDCIdentityProvider | None":
    """Get identity provider from app state, or None if not available."""
    provider = getattr(request.app.state, "identity_provider", None)
    return cast("OIDCIdentityProvider | None", provider)


@router.get("/status")
async def get_auth_status(request: Request) -> AuthStatusResponse:
    """Get authentication status and user info.

    Returns current auth state including:
    - Whether user is authenticated
    - User info (subject_id, email, name) if authenticated
    - Token expiry and refresh token status
    - Storage backend info
    """
    provider = _get_identity_provider_optional(request)
    if provider is None or not provider.is_authenticated:
        return _unauthenticated_response()

    # Get identity and token info
    try:
        identity = await provider.get_identity()
        # Access internal token for expiry info (get_identity populates this)
        # TODO: Add public get_token_info() method to OIDCIdentityProvider
        token = provider._current_token

        expires_in_hours = None
        has_refresh = None
        if token:
            expires_in_hours = token.seconds_until_expiry / 3600
            has_refresh = bool(token.refresh_token)

        storage_info = get_token_storage_info()
        return AuthStatusResponse(
            authenticated=True,
            subject_id=identity.subject_id,
            email=identity.subject_claims.get("email"),
            name=identity.subject_claims.get("name"),
            token_expires_in_hours=expires_in_hours,
            has_refresh_token=has_refresh,
            storage_backend=storage_info.get("backend"),
        )
    except AuthenticationError:
        return _unauthenticated_response()


@router.post("/login")
async def start_login(oidc_config: OIDCConfigDep) -> DeviceFlowStartResponse:
    """Start device flow authentication.

    Initiates OAuth device authorization flow:
    1. Returns user_code and verification_uri
    2. User opens URL and enters code in browser
    3. Poll /api/auth/login/poll?code={user_code} for completion

    Returns verification URL and code for user to complete in browser.
    """
    # Cleanup expired flows
    _cleanup_expired_flows()

    # Prevent memory exhaustion from too many concurrent flows
    if len(_device_flows) >= _MAX_DEVICE_FLOWS:
        raise HTTPException(
            status_code=503,
            detail="Too many concurrent login attempts. Please try again later.",
        )

    # Start device flow (synchronous HTTP call, run in thread pool)
    try:
        device_code = await asyncio.to_thread(_request_device_code, oidc_config)
    except DeviceFlowError as e:
        raise HTTPException(status_code=502, detail=str(e))

    # Store flow state for polling
    _device_flows[device_code.user_code] = _DeviceFlowState(device_code, oidc_config)

    return DeviceFlowStartResponse(
        user_code=device_code.user_code,
        verification_uri=device_code.verification_uri,
        verification_uri_complete=device_code.verification_uri_complete,
        expires_in=device_code.expires_in,
        interval=device_code.interval,
        poll_endpoint=f"/api/auth/login/poll?code={device_code.user_code}",
    )


def _request_device_code(oidc_config: "OIDCConfig") -> DeviceCodeResponse:
    """Request device code (sync helper for thread pool)."""
    with DeviceFlow(oidc_config) as flow:
        return flow.request_device_code()


@router.get("/login/poll")
async def poll_login(
    code: str = Query(..., description="The user_code from /login"),
) -> DeviceFlowPollResponse:
    """Poll for device flow completion.

    Call repeatedly (respecting interval from /login response) until
    status is 'complete', 'expired', 'denied', or 'error'.

    On 'complete', tokens are automatically stored in keychain.
    """
    # Cleanup expired flows
    _cleanup_expired_flows()

    # Find flow state
    state = _device_flows.get(code)
    if state is None:
        return DeviceFlowPollResponse(
            status="expired",
            message="Device flow not found or expired. Start a new login.",
        )

    if state.completed:
        return DeviceFlowPollResponse(
            status="complete",
            message="Authentication successful. Tokens stored.",
        )

    if state.error:
        return DeviceFlowPollResponse(
            status=cast(Literal["expired", "denied", "error"], state.error_type or "error"),
            message=state.error,
        )

    # Poll token endpoint (single poll, not blocking loop)
    try:
        result = await asyncio.to_thread(_poll_token_once, state)

        if result == "pending":
            return DeviceFlowPollResponse(
                status="pending",
                message="Waiting for user to complete authentication...",
            )

        # Success - token was stored
        state.completed = True
        del _device_flows[code]  # Cleanup

        return DeviceFlowPollResponse(
            status="complete",
            message="Authentication successful. Tokens stored in keychain.",
        )

    except DeviceFlowExpiredError as e:
        state.error = str(e)
        state.error_type = "expired"
        del _device_flows[code]
        return DeviceFlowPollResponse(status="expired", message=str(e))

    except DeviceFlowDeniedError as e:
        state.error = str(e)
        state.error_type = "denied"
        del _device_flows[code]
        return DeviceFlowPollResponse(status="denied", message=str(e))

    except DeviceFlowError as e:
        state.error = str(e)
        state.error_type = "error"
        del _device_flows[code]
        return DeviceFlowPollResponse(status="error", message=str(e))


def _poll_token_once(state: _DeviceFlowState) -> str:
    """Poll token endpoint once (sync helper for thread pool).

    Returns:
        "pending" if still waiting, "complete" if tokens obtained.

    Raises:
        DeviceFlowError on error.
    """
    config = state.oidc_config
    device_code = state.device_code

    issuer = config.issuer.rstrip("/")
    token_url = f"{issuer}/oauth/token"

    with httpx.Client(timeout=OAUTH_CLIENT_TIMEOUT_SECONDS) as client:
        response = client.post(
            token_url,
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "device_code": device_code.device_code,
                "client_id": config.client_id,
            },
        )

        if response.status_code == 200:
            # Success - store tokens
            try:
                token_data = response.json()
            except Exception as e:
                raise DeviceFlowError(f"Invalid token response: {e}")

            now = datetime.now(timezone.utc)
            expires_in = token_data.get("expires_in", 86400)

            token = StoredToken(
                access_token=token_data["access_token"],
                refresh_token=token_data.get("refresh_token"),
                id_token=token_data.get("id_token"),
                expires_at=datetime.fromtimestamp(now.timestamp() + expires_in, tz=timezone.utc),
                issued_at=now,
            )

            # Store in keychain
            storage = create_token_storage(config)
            storage.save(token)

            return "complete"

        # Handle error responses
        try:
            error_data = response.json()
        except Exception:
            raise DeviceFlowError(f"Token request failed with status {response.status_code}")

        error = error_data.get("error", "")

        if error == "authorization_pending":
            return "pending"

        if error == "slow_down":
            return "pending"

        if error == "expired_token":
            raise DeviceFlowExpiredError("Device code expired. Please start a new login.")

        if error == "access_denied":
            raise DeviceFlowDeniedError("Authorization was denied.")

        # Unknown error
        error_desc = error_data.get("error_description", error)
        raise DeviceFlowError(f"Token request failed: {error_desc}")


@router.post("/logout")
async def logout(oidc_config: OIDCConfigDep) -> LogoutResponse:
    """Clear local authentication tokens from keychain.

    Removes tokens from OS keychain. You will need to run
    login again to use authenticated features.

    Note: Any running proxy will continue using cached tokens
    until restarted.
    """
    storage = create_token_storage(oidc_config)

    if not storage.exists():
        return LogoutResponse(
            status="not_authenticated",
            message="No stored credentials found.",
        )

    try:
        storage.delete()
        return LogoutResponse(
            status="logged_out",
            message="Local credentials cleared. Restart proxy to apply.",
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to clear credentials: {e}",
        )


@router.post("/logout-federated")
async def logout_federated(oidc_config: OIDCConfigDep) -> FederatedLogoutResponse:
    """Get federated logout URL (Auth0) and clear local credentials.

    Returns URL for browser to complete federated logout.
    Also clears local credentials from keychain.

    Open the returned logout_url in a browser to complete
    the logout from the identity provider (Auth0).
    """
    storage = create_token_storage(oidc_config)

    # Clear local credentials
    if storage.exists():
        try:
            storage.delete()
        except Exception:
            pass  # Best effort

    # Build Auth0 logout URL
    issuer = oidc_config.issuer.rstrip("/")
    logout_url = f"{issuer}/v2/logout?client_id={oidc_config.client_id}"

    return FederatedLogoutResponse(
        status="logged_out",
        logout_url=logout_url,
        message="Local credentials cleared. Open logout_url in browser to complete federated logout.",
    )
