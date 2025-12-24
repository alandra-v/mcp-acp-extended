"""Identity providers for extracting user identity.

Stage 1: LocalIdentityProvider uses getpass.getuser() for local username.
Stage 2+: OIDCIdentityProvider will extract from FastMCP JWT context.

The IdentityProvider protocol enables pluggable identity extraction,
allowing seamless swap between local and OAuth/OIDC authentication.
"""

from __future__ import annotations

import getpass
from typing import Protocol, runtime_checkable

from mcp_acp_extended.telemetry.models.audit import SubjectIdentity


@runtime_checkable
class IdentityProvider(Protocol):
    """Protocol for pluggable identity providers.

    Implementations provide user identity for audit logging and policy decisions.
    Stage 1 uses local username; Stage 2+ will use OIDC token claims.
    """

    def get_identity(self) -> SubjectIdentity:
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

    def get_identity(self) -> SubjectIdentity:
        """Get the cached local user identity.

        Returns:
            SubjectIdentity with local username.
        """
        return self._cached


def create_identity_provider() -> IdentityProvider:
    """Create the appropriate identity provider.

    Stage 1: Always returns LocalIdentityProvider.
    Stage 2+: Will check config and return OIDC provider if configured.

    Returns:
        IdentityProvider instance for the current configuration.
    """
    # Stage 1: Always use local identity
    # Stage 2+: Will check config.auth.provider and return appropriate provider
    return LocalIdentityProvider()
