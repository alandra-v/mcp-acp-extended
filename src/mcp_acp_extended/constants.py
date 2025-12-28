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

# CLI output separator line
CLI_SEPARATOR = "-" * 50

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
# Tool Side Effects Mapping
# ============================================================================

# Manual mapping of known tool side effects for policy decisions.
# This allows writing policies like "deny all tools with CODE_EXEC".
#
# Side effect values match SideEffect enum in context/resource.py:
# - Filesystem: fs_read, fs_write
# - Database: db_read, db_write
# - Network: network_egress, network_ingress
# - Execution: code_exec, process_spawn, sudo_elevate
# - Secrets: secrets_read, env_read, keychain_read
# - System: clipboard_read, clipboard_write, browser_open
# - Sensitive: screen_capture, audio_capture, camera_capture
# - Cloud: cloud_api, container_exec
# - Communication: email_send
#
# Note: Unknown tools have no side effects listed (empty set).
# This is conservative - unknown tools won't match side_effect rules.
TOOL_SIDE_EFFECTS: dict[str, frozenset[str]] = {
    # Shell/code execution - most dangerous
    "bash": frozenset({"code_exec", "fs_write", "fs_read", "network_egress", "process_spawn"}),
    "shell": frozenset({"code_exec", "fs_write", "fs_read", "network_egress", "process_spawn"}),
    "execute": frozenset({"code_exec"}),
    "run_command": frozenset({"code_exec", "fs_write", "fs_read", "process_spawn"}),
    "exec": frozenset({"code_exec"}),
    "eval": frozenset({"code_exec"}),
    "spawn": frozenset({"process_spawn"}),
    "fork": frozenset({"process_spawn"}),
    "subprocess": frozenset({"process_spawn", "code_exec"}),
    # Privilege escalation
    "sudo": frozenset({"sudo_elevate", "code_exec"}),
    "run_as_admin": frozenset({"sudo_elevate", "code_exec"}),
    "elevate": frozenset({"sudo_elevate"}),
    # File system - read
    "read_file": frozenset({"fs_read"}),
    "get_file": frozenset({"fs_read"}),
    "cat": frozenset({"fs_read"}),
    "head": frozenset({"fs_read"}),
    "tail": frozenset({"fs_read"}),
    "list_directory": frozenset({"fs_read"}),
    "list_files": frozenset({"fs_read"}),
    "ls": frozenset({"fs_read"}),
    "find_files": frozenset({"fs_read"}),
    "search_files": frozenset({"fs_read"}),
    "glob": frozenset({"fs_read"}),
    # File system - write
    "write_file": frozenset({"fs_write"}),
    "create_file": frozenset({"fs_write"}),
    "edit_file": frozenset({"fs_read", "fs_write"}),
    "update_file": frozenset({"fs_read", "fs_write"}),
    "append_file": frozenset({"fs_write"}),
    "delete_file": frozenset({"fs_write"}),
    "remove_file": frozenset({"fs_write"}),
    "mkdir": frozenset({"fs_write"}),
    "rmdir": frozenset({"fs_write"}),
    "move_file": frozenset({"fs_read", "fs_write"}),
    "copy_file": frozenset({"fs_read", "fs_write"}),
    "rename_file": frozenset({"fs_write"}),
    # Network - outbound
    "fetch_url": frozenset({"network_egress"}),
    "http_request": frozenset({"network_egress"}),
    "http_get": frozenset({"network_egress"}),
    "http_post": frozenset({"network_egress"}),
    "curl": frozenset({"network_egress"}),
    "wget": frozenset({"network_egress"}),
    "download": frozenset({"network_egress", "fs_write"}),
    "upload": frozenset({"network_egress", "fs_read"}),
    # Network - inbound (servers)
    "start_server": frozenset({"network_ingress"}),
    "listen": frozenset({"network_ingress"}),
    "bind_port": frozenset({"network_ingress"}),
    # Database
    "query_db": frozenset({"db_read"}),
    "query_database": frozenset({"db_read"}),
    "sql_query": frozenset({"db_read"}),
    "select": frozenset({"db_read"}),
    "execute_sql": frozenset({"db_read", "db_write"}),
    "insert": frozenset({"db_write"}),
    "update": frozenset({"db_write"}),
    "delete": frozenset({"db_write"}),
    # Secrets and credentials
    "get_secret": frozenset({"secrets_read"}),
    "read_secret": frozenset({"secrets_read"}),
    "get_credential": frozenset({"secrets_read"}),
    # Environment variables
    "get_env": frozenset({"env_read"}),
    "read_env": frozenset({"env_read"}),
    "getenv": frozenset({"env_read"}),
    "environ": frozenset({"env_read"}),
    # Keychain/keyring
    "get_keychain": frozenset({"keychain_read"}),
    "read_keychain": frozenset({"keychain_read"}),
    "get_keyring": frozenset({"keychain_read"}),
    "get_password": frozenset({"keychain_read", "secrets_read"}),
    # Clipboard
    "get_clipboard": frozenset({"clipboard_read"}),
    "read_clipboard": frozenset({"clipboard_read"}),
    "pbpaste": frozenset({"clipboard_read"}),
    "set_clipboard": frozenset({"clipboard_write"}),
    "write_clipboard": frozenset({"clipboard_write"}),
    "pbcopy": frozenset({"clipboard_write"}),
    "copy_to_clipboard": frozenset({"clipboard_write"}),
    # Browser
    "open_url": frozenset({"browser_open"}),
    "open_browser": frozenset({"browser_open"}),
    "browse": frozenset({"browser_open"}),
    "webbrowser": frozenset({"browser_open"}),
    # Screen/audio/camera capture
    "screenshot": frozenset({"screen_capture"}),
    "screen_capture": frozenset({"screen_capture"}),
    "record_screen": frozenset({"screen_capture"}),
    "record_audio": frozenset({"audio_capture"}),
    "microphone": frozenset({"audio_capture"}),
    "record_video": frozenset({"camera_capture"}),
    "camera": frozenset({"camera_capture"}),
    "webcam": frozenset({"camera_capture"}),
    # Cloud APIs
    "aws": frozenset({"cloud_api", "network_egress"}),
    "gcloud": frozenset({"cloud_api", "network_egress"}),
    "azure": frozenset({"cloud_api", "network_egress"}),
    "s3": frozenset({"cloud_api", "network_egress"}),
    "boto3": frozenset({"cloud_api", "network_egress"}),
    # Containers
    "docker_exec": frozenset({"container_exec", "code_exec"}),
    "kubectl_exec": frozenset({"container_exec", "code_exec"}),
    "docker_run": frozenset({"container_exec", "code_exec", "process_spawn"}),
    # Email
    "send_email": frozenset({"email_send", "network_egress"}),
    "send_mail": frozenset({"email_send", "network_egress"}),
    "smtp_send": frozenset({"email_send", "network_egress"}),
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

# Regex special characters that need escaping in glob-to-regex conversion
REGEX_SPECIAL_CHARS = ".^$+{}[]|()"

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
