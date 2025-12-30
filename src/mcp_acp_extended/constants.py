"""Application-wide constants for mcp-acp-extended.

Constants that define application behavior.
For user-configurable settings per deployment, see config.py.
"""

import os

from platformdirs import user_config_dir

# ============================================================================
# Protected Configuration Directory (Built-in Security)
# ============================================================================

# OS-specific config directory that MCP tools CANNOT access.
# This is a built-in protection that cannot be overridden by user policy.
# Prevents MCP tools from modifying policy, config, or audit logs.
#
# Platform-specific paths:
# - macOS: ~/Library/Application Support/mcp-acp-extended/
# - Linux: ~/.config/mcp-acp-extended/
# - Windows: %APPDATA%\mcp-acp-extended\
#
# Note: Resolved with os.path.realpath() to prevent symlink bypass.
PROTECTED_CONFIG_DIR: str = os.path.realpath(user_config_dir("mcp-acp-extended"))

# ============================================================================
# Transport Configuration
# ============================================================================

# Supported transport types for backend connections
SUPPORTED_TRANSPORTS: tuple[str, ...] = ("stdio", "streamablehttp")

# Default HTTP connection timeout (seconds)
# Used as default in HttpTransportConfig and CLI when user doesn't specify
DEFAULT_HTTP_TIMEOUT_SECONDS: int = 30

# Timeout validation range (seconds)
MIN_HTTP_TIMEOUT_SECONDS: int = 1
MAX_HTTP_TIMEOUT_SECONDS: int = 300  # 5 minutes

# Maximum timeout for HTTP health checks (seconds)
# Health checks use min(user_timeout, HEALTH_CHECK_TIMEOUT_SECONDS) to stay fast
HEALTH_CHECK_TIMEOUT_SECONDS: float = 10.0

# ============================================================================
# mTLS Certificate Monitoring
# ============================================================================

# Certificate expiry warning thresholds (days)
# Used by transport.py to warn operators about expiring certificates
CERT_EXPIRY_WARNING_DAYS: int = 14  # Warning if expires within 14 days
CERT_EXPIRY_CRITICAL_DAYS: int = 7  # Critical warning if expires within 7 days

# ============================================================================
# Audit Log Integrity Monitoring
# ============================================================================

# How often the background AuditHealthMonitor checks audit log integrity (seconds)
# This catches tampering during idle periods between requests (defense in depth)
AUDIT_HEALTH_CHECK_INTERVAL_SECONDS: float = 30.0

# How often the background DeviceHealthMonitor checks device posture (seconds)
# Device state can change during operation (e.g., user disables SIP)
# 5 minutes balances responsiveness with minimal overhead
DEVICE_HEALTH_CHECK_INTERVAL_SECONDS: float = 300.0

# Fail immediately on first health check failure (Zero Trust - fail fast)
# Transient issues are rare for device posture (FileVault/SIP don't flap)
DEFAULT_DEVICE_FAILURE_THRESHOLD: int = 1

# ============================================================================
# OAuth Device Flow (RFC 8628)
# ============================================================================

# Timeout for OAuth HTTP requests (device code, token polling, refresh)
# Used by device_flow.py and token_refresh.py
OAUTH_CLIENT_TIMEOUT_SECONDS: int = 30

# Default polling interval for device flow (seconds)
# Auth0 typically returns 5 in the device code response
DEVICE_FLOW_POLL_INTERVAL_SECONDS: int = 5

# Maximum time to wait for user to complete device flow authentication (seconds)
# 5 minutes is standard for device flows
DEVICE_FLOW_TIMEOUT_SECONDS: int = 300

# ============================================================================
# Authentication Caching (Zero Trust with Performance)
# ============================================================================

# Cache TTL for validated identity (seconds)
# Re-validates token every 60 seconds for Zero Trust with performance
IDENTITY_CACHE_TTL_SECONDS: int = 60

# JWKS (JSON Web Key Set) cache TTL (seconds)
# Shorter TTL reduces window for revoked key acceptance while still avoiding
# excessive requests to the JWKS endpoint (10 minutes)
JWKS_CACHE_TTL_SECONDS: int = 600

# ============================================================================
# Backend Transport Error Detection
# ============================================================================

# Base transport errors for detecting backend disconnection (STDIO-focused)
BASE_TRANSPORT_ERRORS: tuple[type[Exception], ...] = (
    BrokenPipeError,
    EOFError,
    ConnectionError,
    ConnectionResetError,
    ConnectionAbortedError,
)

# HTTP transport errors (httpx) - added at runtime if httpx is available
# These are combined with BASE_TRANSPORT_ERRORS into TRANSPORT_ERRORS
# See: _build_transport_errors() below


def _build_transport_errors() -> tuple[type[Exception], ...]:
    """Build complete tuple of transport error types including httpx if available.

    Returns:
        Tuple of exception types that indicate transport/connection failures.
    """
    errors: list[type[Exception]] = list(BASE_TRANSPORT_ERRORS)

    # Add HTTP transport errors (httpx) if available
    # httpx is a dependency of fastmcp's StreamableHttpTransport
    try:
        import httpx

        errors.extend(
            [
                httpx.ConnectError,
                httpx.RemoteProtocolError,
                httpx.ReadTimeout,
                httpx.ConnectTimeout,
                httpx.CloseError,
            ]
        )
    except ImportError:
        pass  # httpx not available, HTTP errors won't be detected by type

    return tuple(errors)


# Complete tuple of transport error types (includes httpx if available)
TRANSPORT_ERRORS: tuple[type[Exception], ...] = _build_transport_errors()

# ============================================================================
# HITL (Human-in-the-Loop) Configuration
# ============================================================================

# Default HITL dialog timeout (seconds)
# How long to wait for user to respond before auto-denying
#
# IMPORTANT: Client Timeout Considerations
# ----------------------------------------
# MCP clients (like Claude Desktop, custom integrations) have their own
# request timeouts. If the client timeout is shorter than the HITL timeout,
# the client will timeout before the user can respond, causing the request
# to fail even if the user later approves.
#
# Recommendations:
# 1. HITL timeout should be LESS than client request timeout
# 2. If using HITL with long timeouts, configure clients with longer timeouts
# 3. Consider DEFAULT_HTTP_TIMEOUT_SECONDS (30s) when setting HITL timeout
#
# Example conflict scenarios:
# - Client timeout: 30s, HITL timeout: 30s → Client times out during approval
# - Client timeout: 60s, HITL timeout: 30s → Safe, 30s buffer for user response
#
DEFAULT_HITL_TIMEOUT_SECONDS: int = 30

# HITL timeout validation range (seconds)
MIN_HITL_TIMEOUT_SECONDS: int = 5  # Minimum time for user to read and respond
MAX_HITL_TIMEOUT_SECONDS: int = 300  # 5 minutes max

# ============================================================================
# Approval Caching (HITL Fatigue Reduction)
# ============================================================================

# Default TTL for cached HITL approvals (seconds)
# After approval, user won't see dialog for same operation until TTL expires
DEFAULT_APPROVAL_TTL_SECONDS: int = 600  # 10 minutes

# Approval TTL validation range (seconds)
MIN_APPROVAL_TTL_SECONDS: int = 300  # 5 minutes minimum
MAX_APPROVAL_TTL_SECONDS: int = 900  # 15 minutes maximum

# ============================================================================
# File Metadata Extraction
# ============================================================================

# Common path-related argument names to check when extracting file paths
# Used by context/context.py and utils/logging/extractors.py
PATH_ARGUMENT_NAMES: tuple[str, ...] = (
    "path",
    "uri",
    "file_path",
    "filepath",
    "file",
    "filename",
)

# ============================================================================
# MCP Method Classification
# ============================================================================

# Discovery methods - metadata/listing operations that don't modify state
# These are allowed by default without explicit policy rules
# Category: DISCOVERY (vs ACTION which requires policy evaluation)
#
# NOTE: prompts/get is NOT included because it returns prompt content
# which could contain sensitive information. It requires policy evaluation.
DISCOVERY_METHODS: frozenset[str] = frozenset(
    {
        "initialize",
        "ping",
        "tools/list",
        "resources/list",
        "resources/templates/list",
        "prompts/list",
        # "prompts/get" - EXCLUDED: returns content, needs policy evaluation
        "notifications/initialized",
        "notifications/cancelled",
        "notifications/progress",
        "notifications/resources/list_changed",
        "notifications/tools/list_changed",
        "notifications/prompts/list_changed",
    }
)

# ============================================================================
# History Versioning
# ============================================================================

# Initial version for new history files
INITIAL_VERSION = "v1"
