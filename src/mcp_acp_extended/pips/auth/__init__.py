"""Authentication Policy Information Point.

This module contains identity providers that extract user identity from
authentication tokens for policy decisions (ABAC Subject).

Identity Providers:
- OIDCIdentityProvider: Pattern 1 (STDIO) - loads from keychain, validates JWT
- HTTPIdentityProvider: Pattern 2 (HTTP) - uses FastMCP get_access_token() [Future]

Authentication primitives (token storage, JWT validation) are in security/auth/.
Device health checks are in security/posture/.
Auth audit logging is in telemetry/audit/auth_logger.py.

See docs/design/authentication_implementation.md for architecture details.
"""

from mcp_acp_extended.pips.auth.claims import (
    build_subject_from_identity,
    build_subject_from_validated_token,
)
from mcp_acp_extended.pips.auth.oidc_provider import OIDCIdentityProvider

__all__ = [
    "OIDCIdentityProvider",
    "build_subject_from_identity",
    "build_subject_from_validated_token",
]
