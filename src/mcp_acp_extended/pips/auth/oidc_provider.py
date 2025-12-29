"""OIDC Identity Provider for keychain-based authentication (STDIO transport).

Pattern 1: STDIO Transport
- Token stored in OS keychain (via CLI `auth login`)
- Loaded at proxy startup
- Validated per-request with 60-second cache
- Auto-refreshed when expired

This provider implements the IdentityProvider protocol, making it interchangeable
with LocalIdentityProvider (Stage 1) and future HTTPIdentityProvider (Pattern 2).

Thread-safety: Uses asyncio.Lock to protect cache access during concurrent requests.

See docs/design/authentication_implementation.md for architecture details.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

from mcp_acp_extended.exceptions import AuthenticationError
from mcp_acp_extended.security.auth import (
    JWTValidator,
    StoredToken,
    TokenRefreshExpiredError,
    TokenStorage,
    ValidatedToken,
    create_token_storage,
    refresh_tokens,
)
from mcp_acp_extended.telemetry.models.audit import SubjectIdentity
from mcp_acp_extended.telemetry.system.system_logger import get_system_logger

if TYPE_CHECKING:
    from mcp_acp_extended.config import OIDCConfig

# Cache TTL for validated identity (Zero Trust with performance)
# Re-validates token every 60 seconds
IDENTITY_CACHE_TTL_SECONDS = 60


@dataclass
class _CachedIdentity:
    """Cached identity with expiration tracking."""

    identity: SubjectIdentity
    validated_token: ValidatedToken
    cached_at: float  # monotonic timestamp

    def is_expired(self, ttl: float = IDENTITY_CACHE_TTL_SECONDS) -> bool:
        """Check if cache has expired."""
        return time.monotonic() - self.cached_at > ttl


class OIDCIdentityProvider:
    """OIDC identity provider for STDIO transport (Pattern 1).

    Loads OAuth tokens from OS keychain, validates JWT per-request,
    and auto-refreshes when expired. Implements IdentityProvider protocol.

    Features:
    - Per-request validation with 60-second cache (Zero Trust)
    - Automatic token refresh when access_token expires
    - Rich SubjectIdentity with OIDC claims for policy evaluation
    - Concurrency-safe with asyncio.Lock protecting cache access

    Usage:
        provider = OIDCIdentityProvider(oidc_config)
        identity = await provider.get_identity()
        print(f"User: {identity.subject_id}")

    Raises:
        AuthenticationError: If not authenticated or token refresh fails.
    """

    def __init__(
        self,
        config: "OIDCConfig",
        token_storage: TokenStorage | None = None,
        jwt_validator: JWTValidator | None = None,
    ) -> None:
        """Initialize OIDC identity provider.

        Args:
            config: OIDC configuration (issuer, client_id, audience).
            token_storage: Token storage backend (default: auto-detect keychain/file).
            jwt_validator: JWT validator (default: create from config).
        """
        self._config = config
        self._storage = token_storage or create_token_storage(config)
        self._validator = jwt_validator or JWTValidator(config)
        self._cache: _CachedIdentity | None = None
        self._current_token: StoredToken | None = None
        self._logger = get_system_logger()
        # Lock protects cache read-modify-write operations
        self._lock = asyncio.Lock()

    async def get_identity(self) -> SubjectIdentity:
        """Get the current user's identity.

        Implements IdentityProvider protocol. Called per-request by middleware.

        Flow:
        1. Acquire lock for thread-safe cache access
        2. Check cache (60s TTL for Zero Trust with performance)
        3. Load token from keychain
        4. Validate JWT (signature, issuer, audience, expiry)
        5. If expired, try refresh
        6. Build SubjectIdentity with OIDC claims

        Returns:
            SubjectIdentity with subject_id and OIDC claims.

        Raises:
            AuthenticationError: If not authenticated, token invalid,
                or refresh fails (user must re-login).
        """
        async with self._lock:
            # Check cache first (Zero Trust with performance)
            # Inside lock to prevent concurrent cache invalidation
            if self._cache is not None and not self._cache.is_expired():
                return self._cache.identity

            # Load token from storage
            token = self._load_token()

            # Validate and potentially refresh
            validated = self._validate_token(token)

            # Build identity from validated claims
            identity = self._build_identity(validated)

            # Cache for next request
            self._cache = _CachedIdentity(
                identity=identity,
                validated_token=validated,
                cached_at=time.monotonic(),
            )

            return identity

    async def get_validated_token(self) -> ValidatedToken:
        """Get the validated token (for advanced use cases).

        Returns the full ValidatedToken with all claims, useful for
        audit logging or building full Subject objects.

        Returns:
            ValidatedToken with all OIDC claims.

        Raises:
            AuthenticationError: If not authenticated.
        """
        # Ensure identity is loaded/validated (populates cache)
        await self.get_identity()

        if self._cache is None:
            raise AuthenticationError("No validated token available")

        return self._cache.validated_token

    def _load_token(self) -> StoredToken:
        """Load token from storage.

        Returns:
            StoredToken from keychain/encrypted file.

        Raises:
            AuthenticationError: If no token stored (user not logged in).
        """
        token = self._storage.load()

        if token is None:
            raise AuthenticationError("Not authenticated. Run 'mcp-acp-extended auth login' to authenticate.")

        self._current_token = token
        return token

    def _validate_token(self, token: StoredToken) -> ValidatedToken:
        """Validate token, refreshing if expired.

        Args:
            token: Stored token to validate.

        Returns:
            ValidatedToken with verified claims.

        Raises:
            AuthenticationError: If validation fails and refresh not possible.
        """
        # Check if token is expired based on stored expiry
        if token.is_expired:
            self._logger.debug(
                {
                    "event": "token_expired_attempting_refresh",
                    "seconds_expired": -token.seconds_until_expiry,
                }
            )
            return self._refresh_and_validate(token)

        # Validate JWT (signature, issuer, audience, exp)
        try:
            validated = self._validator.validate(token.access_token)

            self._logger.debug(
                {
                    "event": "token_validated",
                    "subject_id": validated.subject_id,
                    "token_age_s": validated.token_age_seconds,
                }
            )

            return validated

        except AuthenticationError as e:
            # Token validation failed - check if it's expiry
            # Check the cause for jwt.ExpiredSignatureError (more robust than string matching)
            import jwt

            is_expiry = isinstance(e.__cause__, jwt.ExpiredSignatureError)
            if is_expiry:
                self._logger.debug(
                    {
                        "event": "token_validation_expired_attempting_refresh",
                        "error": str(e),
                    }
                )
                return self._refresh_and_validate(token)

            # Other validation error - re-raise
            raise

    def _refresh_and_validate(self, token: StoredToken) -> ValidatedToken:
        """Refresh token and validate the new one.

        Args:
            token: Expired token with refresh_token.

        Returns:
            ValidatedToken from refreshed access_token.

        Raises:
            AuthenticationError: If refresh fails (user must re-login).
        """
        if not token.refresh_token:
            raise AuthenticationError(
                "Token expired and no refresh token available. "
                "Run 'mcp-acp-extended auth login' to re-authenticate."
            )

        try:
            # Refresh tokens
            refreshed = refresh_tokens(self._config, token.refresh_token)

            # Save refreshed tokens to storage
            self._storage.save(refreshed)
            self._current_token = refreshed

            self._logger.info(
                {
                    "event": "token_refreshed",
                    "expires_in_seconds": refreshed.seconds_until_expiry,
                }
            )

            # Validate the new token
            return self._validator.validate(refreshed.access_token)

        except TokenRefreshExpiredError as e:
            # Refresh token has expired - user must re-authenticate
            raise AuthenticationError(
                "Session expired. Run 'mcp-acp-extended auth login' to re-authenticate."
            ) from e

    def _build_identity(self, validated: ValidatedToken) -> SubjectIdentity:
        """Build SubjectIdentity from validated token.

        Args:
            validated: Validated token with claims.

        Returns:
            SubjectIdentity for audit logging and policy evaluation.
        """
        # Extract safe claims for logging (no sensitive data)
        # SubjectIdentity.subject_claims is dict[str, str], so convert lists to comma-separated strings
        safe_claims: dict[str, str] = {
            "auth_type": "oidc",
            "issuer": validated.issuer,
        }

        # Store audience as comma-separated string
        if validated.audience:
            safe_claims["audience"] = ",".join(validated.audience)

        # Store scopes as comma-separated string
        if validated.scopes:
            safe_claims["scopes"] = ",".join(sorted(validated.scopes))

        # Add optional claims if present (explicitly convert to str for type safety)
        email = validated.claims.get("email")
        if email:
            safe_claims["email"] = str(email)
        name = validated.claims.get("name")
        if name:
            safe_claims["name"] = str(name)

        return SubjectIdentity(
            subject_id=validated.subject_id,
            subject_claims=safe_claims,
        )

    def clear_cache(self) -> None:
        """Clear the identity cache.

        Forces re-validation on next get_identity() call.
        Useful for testing or after token refresh.
        """
        self._cache = None

    def logout(self) -> None:
        """Clear stored tokens and cache.

        Call this to log out the user. They will need to run
        'mcp-acp-extended auth login' to re-authenticate.
        """
        self._storage.delete()
        self._cache = None
        self._current_token = None

    @property
    def is_authenticated(self) -> bool:
        """Check if user is authenticated (has stored token).

        Note: This doesn't validate the token, just checks if one exists.
        Use get_identity() to validate.

        Returns:
            True if token exists in storage.
        """
        return self._storage.exists()
