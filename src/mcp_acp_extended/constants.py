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
# Recommended Paths
# ============================================================================

# Recommended log directory shown in init prompts (user can customize)
RECOMMENDED_LOG_DIR = "~/.mcp-acp-extended"

# Bootstrap log filename (used when config is invalid and log_dir unavailable)
BOOTSTRAP_LOG_FILENAME = "bootstrap.jsonl"

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
# Audit Log Integrity Monitoring
# ============================================================================

# How often the background AuditHealthMonitor checks audit log integrity (seconds)
# This catches tampering during idle periods between requests (defense in depth)
AUDIT_HEALTH_CHECK_INTERVAL_SECONDS: float = 30.0

# How often the background DeviceHealthMonitor checks device posture (seconds)
# Device state can change during operation (e.g., user disables SIP)
# 5 minutes balances responsiveness with minimal overhead
DEVICE_HEALTH_CHECK_INTERVAL_SECONDS: float = 300.0

# ============================================================================
# OAuth Device Flow (RFC 8628)
# ============================================================================

# Default polling interval for device flow (seconds)
# Auth0 typically returns 5 in the device code response
DEVICE_FLOW_POLL_INTERVAL_SECONDS: int = 5

# Maximum time to wait for user to complete device flow authentication (seconds)
# 5 minutes is standard for device flows
DEVICE_FLOW_TIMEOUT_SECONDS: int = 300

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

# String indicators for error message matching (fallback detection)
# Based on actual FastMCP, anyio, and httpx error messages
TRANSPORT_ERROR_INDICATORS: tuple[str, ...] = (
    # FastMCP client errors (client.py)
    "server session was closed unexpectedly",
    "failed to initialize server session",
    "client failed to connect",
    # anyio socket errors (_sockets.py)
    "all connection attempts failed",
    # STDIO transport errors
    "broken pipe",
    "eof",
    # httpx transport errors
    "connection refused",
    "connection reset",
    "connection closed",
    "remote disconnected",
)


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
# File Metadata Extraction
# ============================================================================

# Common path-related argument names to check when extracting file paths
PATH_ARGUMENT_NAMES: tuple[str, ...] = (
    "path",
    "uri",
    "file_path",
    "filepath",
    "file",
    "filename",
)

# Content-related argument names to redact during logging
CONTENT_ARGUMENT_NAMES: tuple[str, ...] = (
    "content",
    "data",
    "text",
    "body",
)

# MIME type hints for common file extensions
MIME_TYPE_HINTS: dict[str, str] = {
    ".txt": "text/plain",
    ".md": "text/markdown",
    ".json": "application/json",
    ".py": "text/x-python",
    ".js": "text/javascript",
    ".html": "text/html",
    ".css": "text/css",
    ".xml": "application/xml",
    ".yaml": "application/yaml",
    ".yml": "application/yaml",
}

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

# Action intent mapping - ONLY for methods where intent is a FACT
# For tools/call, we return None because we can't know what a tool does
METHOD_INTENTS: dict[str, str] = {
    "resources/read": "read",
}

# ============================================================================
# History Versioning
# ============================================================================

# Initial version for new history files
INITIAL_VERSION = "v1"

# ============================================================================
# Operation Inference Heuristics (UNTRUSTED)
# ============================================================================
# These help policy writers but should NOT be relied upon for security.
# Tool names may lie about what they actually do.

# Tool name patterns for read operation inference
READ_TOOL_PREFIXES: tuple[str, ...] = ("read_", "get_", "list_", "fetch_", "search_", "find_")
READ_TOOL_CONTAINS: tuple[str, ...] = ("_read", "_get", "_list", "_fetch", "_search")

# Tool name patterns for delete operation inference
DELETE_TOOL_PREFIXES: tuple[str, ...] = ("delete_", "remove_", "drop_", "clear_")
DELETE_TOOL_CONTAINS: tuple[str, ...] = ("_delete", "_remove", "_drop", "_clear")

# Tool name patterns for write operation inference
WRITE_TOOL_PREFIXES: tuple[str, ...] = (
    "write_",
    "create_",
    "edit_",
    "update_",
    "set_",
    "save_",
    "put_",
    "add_",
    "insert_",
    "append_",
)
WRITE_TOOL_CONTAINS: tuple[str, ...] = (
    "_write",
    "_create",
    "_edit",
    "_update",
    "_set",
    "_save",
    "_put",
    "_add",
    "_insert",
    "_append",
)
