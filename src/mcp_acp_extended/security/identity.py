"""Identity providers for extracting user identity.

Supports two transport patterns:
- Pattern 1 (STDIO): OIDCIdentityProvider loads from keychain, validates JWT
- Pattern 2 (HTTP): HTTPIdentityProvider uses FastMCP get_access_token() [Future]
- Fallback: LocalIdentityProvider uses getpass.getuser() (development only)

The IdentityProvider protocol enables pluggable identity extraction,
allowing seamless swap between local and OAuth/OIDC authentication.

All identity providers are async to support:
- OIDC token validation (network calls to JWKS endpoint)
- Token refresh (network calls to token endpoint)
- Concurrency-safe cache access with asyncio.Lock

See docs/design/authentication_implementation.md for architecture details.
"""

from __future__ import annotations

import getpass
from typing import TYPE_CHECKING, Literal, Protocol, runtime_checkable

from mcp_acp_extended.telemetry.models.audit import SubjectIdentity

if TYPE_CHECKING:
    from mcp_acp_extended.config import AppConfig


@runtime_checkable
class IdentityProvider(Protocol):
    """Protocol for pluggable identity providers.

    Implementations provide user identity for audit logging and policy decisions.
    The middleware layer uses this protocol without knowing the concrete provider.

    Pattern 1 (STDIO): OIDCIdentityProvider - loads from keychain
    Pattern 2 (HTTP): HTTPIdentityProvider - uses get_access_token() [Future]
    Fallback: LocalIdentityProvider - uses local username

    All implementations must be async to support OIDC token operations.
    """

    async def get_identity(self) -> SubjectIdentity:
        """Get the current user's identity.

        Returns:
            SubjectIdentity with subject_id and optional claims.
        """
        ...


class LocalIdentityProvider:
    """Local user identity via getpass.getuser().

    Uses Python's cross-platform getpass.getuser() which:
    - Tries environment variables: LOGNAME -> USER -> LNAME -> USERNAME
    - Falls back to pwd.getpwuid(os.getuid()).pw_name on Unix
    - Works in containers, cron, systemd, SSH (unlike os.getlogin())

    Identity is cached at initialization since local username doesn't
    change during proxy lifetime.

    WARNING: This provider is for development/testing only.
    Production deployments MUST use OIDCIdentityProvider for Zero Trust.
    """

    def __init__(self) -> None:
        """Initialize and cache the local user identity."""
        self._cached = self._resolve_local_user()

    def _resolve_local_user(self) -> SubjectIdentity:
        """Resolve local username via getpass.getuser().

        Returns:
            SubjectIdentity with local username and auth_type claim.
        """
        username = getpass.getuser()
        return SubjectIdentity(
            subject_id=username,
            subject_claims={"auth_type": "local"},
        )

    async def get_identity(self) -> SubjectIdentity:
        """Get the cached local user identity.

        Async for protocol compatibility with OIDCIdentityProvider.
        Local identity is cached at init, so this is a fast synchronous return.

        Returns:
            SubjectIdentity with local username.
        """
        return self._cached


def create_identity_provider(
    config: "AppConfig | None" = None,
    transport: Literal["stdio", "http"] = "stdio",
) -> IdentityProvider:
    """Create the appropriate identity provider for the transport.

    Selects provider based on configuration and transport type:
    - If config.auth is configured: Use OIDC-based provider
    - If no auth configured: Use LocalIdentityProvider (development only)

    Args:
        config: Application configuration with auth settings.
        transport: Transport type ("stdio" or "http").

    Returns:
        IdentityProvider appropriate for the configuration:
        - stdio + auth: OIDCIdentityProvider (loads from keychain)
        - http + auth: HTTPIdentityProvider [Future]
        - no auth: LocalIdentityProvider (development fallback)

    Raises:
        AuthenticationError: If OIDC auth fails (no token, invalid, etc.)
    """
    # No config or no auth configured - use local identity (development only)
    if config is None or config.auth is None:
        return LocalIdentityProvider()

    # Auth configured - use OIDC provider based on transport
    if transport == "stdio":
        # Pattern 1: STDIO transport - load from keychain
        from mcp_acp_extended.pips.auth import OIDCIdentityProvider

        return OIDCIdentityProvider(config.auth.oidc)
    else:
        # Pattern 2: HTTP transport - use FastMCP get_access_token() [Future]
        # For now, fall back to local until HTTP support is implemented
        raise NotImplementedError(
            "HTTP transport authentication not yet implemented. "
            "Use STDIO transport or wait for future release."
        )
