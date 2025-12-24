"""Security module for identity, authentication, and authorization.

This module provides:
- Identity providers (local, OIDC in Stage 2+)
- Audit log integrity: fail-closed handlers and health monitoring
- Shutdown coordination for critical security failures

Note: Security exceptions are defined in mcp_acp_extended.exceptions
"""

from mcp_acp_extended.exceptions import (
    AuditFailure,
    CriticalSecurityFailure,
    IdentityVerificationFailure,
    PolicyEnforcementFailure,
)
from mcp_acp_extended.security.integrity import (
    FailClosedAuditHandler,
    get_emergency_audit_path,
    log_with_fallback,
    verify_audit_writable,
    write_emergency_audit,
)
from mcp_acp_extended.security.identity import (
    IdentityProvider,
    LocalIdentityProvider,
    create_identity_provider,
)
from mcp_acp_extended.security.shutdown import (
    ShutdownCoordinator,
    sync_emergency_shutdown,
)

__all__ = [
    # Identity
    "IdentityProvider",
    "LocalIdentityProvider",
    "create_identity_provider",
    # Audit integrity
    "FailClosedAuditHandler",
    "verify_audit_writable",
    # Emergency audit fallback
    "get_emergency_audit_path",
    "log_with_fallback",
    "write_emergency_audit",
    # Shutdown coordination
    "ShutdownCoordinator",
    "sync_emergency_shutdown",
    # Exceptions (re-exported from mcp_acp_extended.exceptions)
    "CriticalSecurityFailure",
    "AuditFailure",
    "PolicyEnforcementFailure",
    "IdentityVerificationFailure",
]
