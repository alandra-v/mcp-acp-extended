"""Security module for identity, authentication, and authorization.

This module provides:
- Authentication: token storage, JWT validation (security/auth/)
- Identity providers (local, OIDC in Stage 2+)
- Device health checks (disk encryption, SIP)
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
from mcp_acp_extended.security.auth import (
    DeviceCodeResponse,
    DeviceFlow,
    DeviceFlowDeniedError,
    DeviceFlowError,
    DeviceFlowExpiredError,
    DeviceFlowResult,
    EncryptedFileStorage,
    JWTValidator,
    KeychainStorage,
    StoredToken,
    TokenRefreshError,
    TokenRefreshExpiredError,
    TokenStorage,
    ValidatedToken,
    create_token_storage,
    get_token_storage_info,
    refresh_tokens,
    run_device_flow,
)
from mcp_acp_extended.security.posture import (
    DeviceHealthMonitor,
    DeviceHealthReport,
    check_device_health,
)
from mcp_acp_extended.security.identity import (
    IdentityProvider,
    LocalIdentityProvider,
    create_identity_provider,
)
from mcp_acp_extended.security.integrity import (
    FailClosedAuditHandler,
    get_emergency_audit_path,
    log_with_fallback,
    verify_audit_writable,
    write_emergency_audit,
)
from mcp_acp_extended.security.shutdown import (
    ShutdownCoordinator,
    sync_emergency_shutdown,
)

__all__ = [
    # Authentication (security/auth/)
    "StoredToken",
    "TokenStorage",
    "KeychainStorage",
    "EncryptedFileStorage",
    "create_token_storage",
    "get_token_storage_info",
    "JWTValidator",
    "ValidatedToken",
    "DeviceFlow",
    "DeviceCodeResponse",
    "DeviceFlowResult",
    "DeviceFlowError",
    "DeviceFlowExpiredError",
    "DeviceFlowDeniedError",
    "run_device_flow",
    "refresh_tokens",
    "TokenRefreshError",
    "TokenRefreshExpiredError",
    # Identity
    "IdentityProvider",
    "LocalIdentityProvider",
    "create_identity_provider",
    # Device health
    "DeviceHealthReport",
    "DeviceHealthMonitor",
    "check_device_health",
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
