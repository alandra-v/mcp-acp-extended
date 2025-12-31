"""Proxy server implementation using FastMCP and ProxyClient.

This module provides the core proxy functionality that forwards all MCP requests
from clients (via STDIO) to backend servers with bidirectional logging.

Supported backend transports:
- STDIO: Spawns backend server as a child process
- Streamable HTTP: Connects to an HTTP endpoint

This module is designed for programmatic use:
- Import create_proxy(config) to integrate into applications or CLI
- The CLI (cli.py) handles user interaction, startup messages, and error display

Security:
- Audit logs use fail-closed handlers that trigger shutdown if compromised
- Startup validation ensures audit logs are writable before accepting requests
"""

from __future__ import annotations

import asyncio
import os
from contextlib import asynccontextmanager
from typing import AsyncIterator, Literal

import uvicorn
from fastmcp import FastMCP
from fastmcp.server.middleware.rate_limiting import RateLimitingMiddleware

from mcp_acp_extended.config import AppConfig
from mcp_acp_extended.constants import (
    AUDIT_HEALTH_CHECK_INTERVAL_SECONDS,
    DEFAULT_API_PORT,
    DEVICE_HEALTH_CHECK_INTERVAL_SECONDS,
    PROTECTED_CONFIG_DIR,
)
from mcp_acp_extended.exceptions import AuditFailure, AuthenticationError, DeviceHealthError
from mcp_acp_extended.cli.startup_alerts import show_startup_error_popup
from mcp_acp_extended.pep import create_context_middleware, create_enforcement_middleware
from mcp_acp_extended.pips.auth import SessionManager
from mcp_acp_extended.security import create_identity_provider, SessionRateTracker
from mcp_acp_extended.security.posture import DeviceHealthMonitor, check_device_health
from mcp_acp_extended.security.integrity.audit_handler import verify_audit_writable
from mcp_acp_extended.security.integrity.audit_monitor import AuditHealthMonitor
from mcp_acp_extended.security.shutdown import ShutdownCoordinator, sync_emergency_shutdown
from mcp_acp_extended.telemetry.audit import create_audit_logging_middleware, create_auth_logger
from mcp_acp_extended.telemetry.models.audit import SubjectIdentity
from mcp_acp_extended.telemetry.debug.client_logger import (
    create_client_logging_middleware,
)
from mcp_acp_extended.telemetry.debug.logging_proxy_client import (
    create_logging_proxy_client,
)
from mcp_acp_extended.utils.logging.logging_context import get_session_id
from mcp_acp_extended.telemetry.system.system_logger import (
    configure_system_logger_file,
    get_system_logger,
)
from mcp_acp_extended.utils.config import (
    get_audit_log_path,
    get_auth_log_path,
    get_backend_log_path,
    get_client_log_path,
    get_decisions_log_path,
    get_log_dir,
    get_system_log_path,
)
from mcp_acp_extended.utils.policy import load_policy
from mcp_acp_extended.utils.transport import create_backend_transport


def create_proxy(
    config: AppConfig,
    config_version: str | None = None,
    policy_version: str | None = None,
) -> tuple[FastMCP, str]:
    """Create a transparent proxy that forwards all requests to backend.

    This function creates a FastMCP proxy server using ProxyClient to connect
    to a backend MCP server using the provided configuration.

    Transport selection (handled by create_backend_transport):
    - If config.backend.transport is set, use that transport (fail if unavailable)
    - If config.backend.transport is None, auto-detect:
      - Prefer Streamable HTTP if configured and reachable
      - Fall back to STDIO if HTTP unavailable or not configured

    Logging:
    - Audit logs (ALWAYS enabled): <log_dir>/mcp_acp_extended_logs/audit/operations.jsonl
    - Decision logs (ALWAYS enabled): <log_dir>/mcp_acp_extended_logs/audit/decisions.jsonl
    - Debug wire logs (when log_level == "DEBUG"):
      - Client<->Proxy: <log_dir>/mcp_acp_extended_logs/debug/client_wire.jsonl
      - Proxy<->Backend: <log_dir>/mcp_acp_extended_logs/debug/backend_wire.jsonl
    - All logs include correlation IDs (request_id, session_id)
    - JSONL format with ISO 8601 timestamps

    Middleware order (outer to inner):
    - Context: Sets up request context (request_id, session_id, tool_context)
    - Audit: Logs all operations including denials
    - Client logging: Wire-level debugging
    - Enforcement: Policy evaluation and blocking (innermost)

    Security - Device Health Check:
    - Runs at startup as a hard gate - proxy won't start if device is unhealthy
    - Checks disk encryption (FileVault) and device integrity (SIP) on macOS
    - Zero Trust: device posture must be verified before accepting requests

    Security - Health Monitors (Background):
    - Audit Health Monitor: Runs every 30 seconds to verify audit log integrity
    - Device Health Monitor: Runs every 5 minutes to verify device posture
    - Both trigger fail-closed shutdown if checks fail
    - Started automatically when proxy starts via lifespan context manager
    - Defense in depth: catches issues during idle periods between requests

    Args:
        config: Application configuration loaded from mcp_acp_extended_config.json.
        config_version: Current config version from config history (e.g., "v1").
        policy_version: Current policy version from policy history (e.g., "v1").

    Returns:
        Tuple of (FastMCP proxy instance, actual transport type used).
        Transport type is "stdio" or "streamablehttp".

    Raises:
        ValueError: If transport config is missing for selected transport.
        FileNotFoundError: If STDIO backend command is not found in PATH.
        PermissionError: If insufficient permissions to execute backend command.
        TimeoutError: If HTTP backend connection times out.
        ConnectionError: If HTTP backend is unreachable.
        RuntimeError: If backend server fails to start or initialize.
        AuditFailure: If audit logs cannot be written at startup.
        DeviceHealthError: If device health checks fail at startup.
    """
    # =========================================================================
    # PHASE 1: Startup Validation
    # Verify all prerequisites before accepting any requests (Zero Trust)
    # =========================================================================

    # Configure system logger file handler with user's log_dir
    configure_system_logger_file(get_system_log_path(config))

    # Validate audit logs are writable BEFORE starting
    # If this fails, we raise AuditFailure and don't start
    audit_path = get_audit_log_path(config)
    decisions_path = get_decisions_log_path(config)
    auth_log_path = get_auth_log_path(config)
    try:
        verify_audit_writable(audit_path)
        verify_audit_writable(decisions_path)
        verify_audit_writable(auth_log_path)
    except AuditFailure as e:
        # Show popup on macOS for users
        show_startup_error_popup(
            title="MCP ACP",
            message="Audit log failure.",
            detail=f"{e}\n\nCheck log directory permissions.",
        )
        raise

    # Run device health check (hard gate - proxy won't start if unhealthy)
    # Zero Trust: device posture must be verified before accepting any requests
    device_health = check_device_health()
    if not device_health.is_healthy:
        # Show popup on macOS for users
        show_startup_error_popup(
            title="MCP ACP",
            message="Device health check failed.",
            detail=f"{device_health}\n\nEnable FileVault and ensure SIP is enabled.",
        )
        raise DeviceHealthError(str(device_health))

    # =========================================================================
    # PHASE 2: Security Infrastructure
    # Create fail-closed shutdown system and background health monitors
    # =========================================================================

    # Create shutdown coordinator for fail-closed behavior
    log_dir = get_log_dir(config)
    system_logger = get_system_logger()
    shutdown_coordinator = ShutdownCoordinator(log_dir, system_logger)

    # Create shutdown callback with hybrid approach:
    # Try async coordinator if event loop is running, fall back to sync
    def on_audit_failure(reason: str) -> None:
        """Handle audit log integrity failure."""
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(
                shutdown_coordinator.initiate_shutdown(
                    failure_type=AuditFailure.failure_type,
                    reason=reason,
                    exit_code=AuditFailure.exit_code,
                    context={"source": "audit_handler"},
                )
            )
        except RuntimeError:
            # No event loop running - use sync fallback
            sync_emergency_shutdown(
                log_dir, AuditFailure.failure_type, reason, exit_code=AuditFailure.exit_code
            )

    # Create AuditHealthMonitor for background integrity checking
    # This runs periodic checks even during idle periods (defense in depth)
    audit_monitor = AuditHealthMonitor(
        audit_paths=[audit_path, decisions_path],
        shutdown_coordinator=shutdown_coordinator,
        check_interval_seconds=AUDIT_HEALTH_CHECK_INTERVAL_SECONDS,
    )

    # Create auth logger for authentication event audit trail
    auth_logger = create_auth_logger(auth_log_path, on_audit_failure)

    # Create DeviceHealthMonitor for periodic device posture verification
    # Device state can change during operation (e.g., user disables SIP)
    device_monitor = DeviceHealthMonitor(
        shutdown_coordinator=shutdown_coordinator,
        auth_logger=auth_logger,
        check_interval_seconds=DEVICE_HEALTH_CHECK_INTERVAL_SECONDS,
    )

    # =========================================================================
    # PHASE 3: Backend Connection
    # Establish connection to backend MCP server and create proxy
    # =========================================================================

    # Create backend transport (handles detection, validation, health checks)
    # Pass mTLS config for client certificate authentication to HTTP backends
    mtls_config = config.auth.mtls if config.auth else None
    transport, transport_type = create_backend_transport(config.backend, mtls_config)

    # Determine if debug wire logging is enabled
    debug_enabled = config.logging.log_level == "DEBUG"

    # Create LoggingProxyClient with transport (logs to backend_wire.jsonl)
    logging_backend_client = create_logging_proxy_client(
        transport,
        log_path=get_backend_log_path(config),
        transport_type=transport_type,
        debug_enabled=debug_enabled,
    )

    # Create proxy with logging-wrapped backend client
    proxy = FastMCP.as_proxy(
        logging_backend_client,
        name=config.proxy.name,
    )

    # Create session manager for user-bound sessions
    # Sessions use format <user_id>:<session_id> per MCP spec
    session_manager = SessionManager()

    # Create rate tracker for detecting runaway LLM loops
    # Uses defaults: 30 calls/tool/minute triggers HITL dialog
    # Created here so lifespan can cleanup on shutdown
    rate_tracker = SessionRateTracker()

    # =========================================================================
    # PHASE 4: Lifecycle Management
    # Define proxy lifespan: start/stop monitors, manage sessions
    # =========================================================================

    @asynccontextmanager
    async def proxy_lifespan(app: FastMCP) -> AsyncIterator[None]:
        """Manage proxy lifecycle: start/stop health monitors, log session."""
        # Note: app parameter required by FastMCP's _lifespan_manager
        session_identity: SubjectIdentity | None = None
        bound_session_id: str | None = None
        end_reason: Literal["normal", "timeout", "error", "auth_expired"] = "normal"

        try:
            await audit_monitor.start()
            await device_monitor.start()
        except Exception as e:
            # Log failure and re-raise - Zero Trust requires monitoring
            system_logger.error(
                {
                    "event": "health_monitor_start_failed",
                    "error": str(e),
                    "error_type": type(e).__name__,
                }
            )
            raise

        # Validate identity and create user-bound session
        api_server: uvicorn.Server | None = None
        api_task: asyncio.Task | None = None
        try:
            session_identity = await identity_provider.get_identity()
            # Create session bound to user identity (format: <user_id>:<session_id>)
            # This prevents session hijacking across users per MCP spec
            bound_session = session_manager.create_session(session_identity)
            bound_session_id = bound_session.bound_id
            auth_logger.log_session_started(
                bound_session_id=bound_session_id,
                subject=session_identity,
            )

            # Start management API server (shares memory for sessions/approvals)
            # Lazy import to avoid circular import (proxy -> api -> cli -> proxy)
            from mcp_acp_extended.api.server import create_api_app

            api_app = create_api_app()
            api_config = uvicorn.Config(
                api_app,
                host="127.0.0.1",
                port=DEFAULT_API_PORT,
                log_level="warning",  # Quiet - don't spam proxy logs
            )
            api_server = uvicorn.Server(api_config)
            api_task = asyncio.create_task(api_server.serve())
            system_logger.info(
                {
                    "event": "api_server_started",
                    "port": DEFAULT_API_PORT,
                    "url": f"http://127.0.0.1:{DEFAULT_API_PORT}",
                }
            )
        except AuthenticationError as e:
            # Auth failed at startup - log with placeholder (no user to bind to)
            import secrets

            auth_failed_id = f"auth_failed:{secrets.token_urlsafe(8)}"
            auth_logger.log_session_ended(
                bound_session_id=auth_failed_id,
                end_reason="auth_expired",
                error_type=type(e).__name__,
                error_message=str(e),
            )
            # Show popup on macOS for users
            show_startup_error_popup(
                title="MCP ACP",
                message="Not authenticated.",
                detail="Run in terminal:\n  mcp-acp-extended auth login\n\nThen restart your MCP client.",
            )
            raise

        try:
            yield
        except AuthenticationError as e:
            end_reason = "auth_expired"
            system_logger.critical(
                {
                    "event": "auth_failed_during_session",
                    "error": str(e),
                    "error_type": type(e).__name__,
                }
            )
            # No popup - this happens during operation, not before start
            # Error is logged to system log and auth.jsonl
            raise
        except Exception as e:
            end_reason = "error"
            system_logger.error(
                {
                    "event": "proxy_error",
                    "error": str(e),
                    "error_type": type(e).__name__,
                }
            )
            raise
        finally:
            # Stop API server first (graceful shutdown)
            if api_server is not None:
                api_server.should_exit = True
                if api_task is not None:
                    try:
                        await asyncio.wait_for(api_task, timeout=5.0)
                    except asyncio.TimeoutError:
                        api_task.cancel()
                    except asyncio.CancelledError:
                        pass
                system_logger.info({"event": "api_server_stopped"})

            await device_monitor.stop()
            await audit_monitor.stop()
            # Log session_ended with bound session ID and MCP session for correlation
            if bound_session_id:
                auth_logger.log_session_ended(
                    bound_session_id=bound_session_id,
                    mcp_session_id=get_session_id(),  # For correlation with operations/decisions
                    subject=session_identity,
                    end_reason=end_reason,
                )
                # Invalidate session in manager
                session_manager.invalidate_session(bound_session_id)
                # Clean up rate tracking data to prevent memory leak
                rate_tracker.clear()

            # Check if monitors crashed - if so, it's a fatal error
            # (Monitors trigger shutdown on crash via ShutdownCoordinator)
            if audit_monitor._crashed:
                system_logger.error(
                    {
                        "event": "audit_health_monitor_crash_detected",
                        "message": "Monitor crashed during shutdown check",
                    }
                )
            if device_monitor._crashed:
                system_logger.error(
                    {
                        "event": "device_health_monitor_crash_detected",
                        "message": "Monitor crashed during shutdown check",
                    }
                )

    # Set the lifespan on the proxy (replaces default_lifespan)
    # NOTE: _lifespan is a private API. FastMCP may change this in future versions.
    # If FastMCP adds a public lifespan parameter to as_proxy() or Settings, migrate to that.
    # Tested with FastMCP 2.x - verify after upgrades.
    proxy._lifespan = proxy_lifespan

    # =========================================================================
    # PHASE 5: Identity Provider
    # Create authentication provider for Zero Trust identity verification
    # =========================================================================

    # Create identity provider (Zero Trust - auth is mandatory)
    # OIDCIdentityProvider validates JWT from keychain
    # Raises AuthenticationError if auth not configured (no fallback)
    # Note: transport="stdio" because clients connect via STDIO (Claude Desktop).
    # transport_type is the BACKEND transport, not client transport.
    # Future: When HTTP client transport is added, this will need updating.
    try:
        identity_provider = create_identity_provider(config, transport="stdio", auth_logger=auth_logger)
    except AuthenticationError as e:
        # Show popup on macOS for users
        show_startup_error_popup(
            title="MCP ACP",
            message="Authentication not configured.",
            detail="Run in terminal:\n  mcp-acp-extended init\n\nThen restart your MCP client.",
        )
        raise

    # =========================================================================
    # PHASE 6: Middleware Chain
    # Register middleware in order: Context → Audit → Client → Enforcement
    # =========================================================================

    # Register context middleware (outermost - added first)
    # Sets up request_id, session_id, and tool_context for all downstream middleware
    context_middleware = create_context_middleware()
    proxy.add_middleware(context_middleware)

    # Register audit logging middleware (ALWAYS enabled)
    # Logs single event per operation to audit/operations.jsonl
    # Uses fail-closed handler that triggers shutdown if log is compromised
    audit_middleware = create_audit_logging_middleware(
        log_path=audit_path,
        shutdown_coordinator=shutdown_coordinator,
        shutdown_callback=on_audit_failure,
        backend_id=config.backend.server_name,
        identity_provider=identity_provider,
        transport=transport_type,
        config_version=config_version,
    )
    proxy.add_middleware(audit_middleware)

    # Register client logging middleware (logs to client_wire.jsonl)
    #
    # Note: We intentionally don't use FastMCP's ErrorHandlingMiddleware here.
    # Backend MCP errors are already properly formatted and forwarded as-is.
    # Proxy-level errors (transport failures, internal errors) surface as raw
    # exceptions - this is acceptable since they're rare and the raw messages
    # provide useful diagnostic context. See docs/architecture.md for details.
    client_middleware = create_client_logging_middleware(
        log_path=get_client_log_path(config),
        transport=transport_type,
        debug_enabled=debug_enabled,
    )
    proxy.add_middleware(client_middleware)

    # Load policy and register enforcement middleware (innermost - added last)
    # Evaluates policy and blocks denied requests before they reach the backend.
    # Logs every decision to audit/decisions.jsonl with fail-closed handler
    policy = load_policy()

    # Build protected directories tuple (config dir + log dir)
    # These paths are protected from MCP tool access - built-in security
    # Use os.path.realpath() to resolve ALL symlinks for security
    protected_dirs = (
        PROTECTED_CONFIG_DIR,
        os.path.realpath(log_dir),
    )

    # rate_tracker created earlier (before lifespan) for cleanup access
    enforcement_middleware = create_enforcement_middleware(
        policy=policy,
        protected_dirs=protected_dirs,
        identity_provider=identity_provider,
        backend_id=config.backend.server_name,
        log_path=decisions_path,
        shutdown_callback=on_audit_failure,
        policy_version=policy_version,
        rate_tracker=rate_tracker,
    )
    proxy.add_middleware(enforcement_middleware)

    # DoS protection: FastMCP's rate limiter as outermost layer
    # Token bucket: 10 req/s sustained, 50 burst capacity
    # This catches request flooding before any processing
    #
    # NOTE: Both rate limiters (this + SessionRateTracker) are unidirectional
    # (client → proxy only). Backend → proxy notifications bypass middleware
    # via ProxyClient handlers. Risk is low since backend can only spam during
    # active requests, and a malicious backend is a larger threat than spam.
    dos_rate_limiter = RateLimitingMiddleware(
        max_requests_per_second=10.0,
        burst_capacity=50,
        global_limit=True,  # Single limit for STDIO proxy
    )
    proxy.add_middleware(dos_rate_limiter)

    return proxy, transport_type
