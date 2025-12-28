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
from typing import AsyncIterator

from fastmcp import FastMCP

from mcp_acp_extended.config import AppConfig
from mcp_acp_extended.constants import AUDIT_HEALTH_CHECK_INTERVAL_SECONDS, PROTECTED_CONFIG_DIR
from mcp_acp_extended.pep import create_context_middleware, create_enforcement_middleware
from mcp_acp_extended.security import create_identity_provider
from mcp_acp_extended.security.integrity.audit_handler import verify_audit_writable
from mcp_acp_extended.security.integrity.audit_monitor import AuditHealthMonitor
from mcp_acp_extended.exceptions import AuditFailure
from mcp_acp_extended.security.shutdown import ShutdownCoordinator, sync_emergency_shutdown
from mcp_acp_extended.telemetry.audit import create_audit_logging_middleware
from mcp_acp_extended.telemetry.debug.client_logger import (
    create_client_logging_middleware,
)
from mcp_acp_extended.telemetry.debug.logging_proxy_client import (
    create_logging_proxy_client,
)
from mcp_acp_extended.telemetry.system.system_logger import (
    configure_system_logger_file,
    get_system_logger,
)
from mcp_acp_extended.utils.config import (
    get_audit_log_path,
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

    Security - Audit Health Monitor:
    - Background task that runs every 30 seconds to verify audit log integrity
    - Checks that audit log files still exist and haven't been replaced
    - Triggers fail-closed shutdown if any integrity check fails
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
    """
    # Configure system logger file handler with user's log_dir
    configure_system_logger_file(get_system_log_path(config))

    # Validate audit logs are writable BEFORE starting
    # If this fails, we raise AuditFailure and don't start
    audit_path = get_audit_log_path(config)
    decisions_path = get_decisions_log_path(config)
    verify_audit_writable(audit_path)
    verify_audit_writable(decisions_path)

    # Create shutdown coordinator for fail-closed behavior
    log_dir = get_log_dir(config)
    system_logger = get_system_logger()
    shutdown_coordinator = ShutdownCoordinator(log_dir, system_logger)

    # Create AuditHealthMonitor for background integrity checking
    # This runs periodic checks even during idle periods (defense in depth)
    audit_monitor = AuditHealthMonitor(
        audit_paths=[audit_path, decisions_path],
        shutdown_coordinator=shutdown_coordinator,
        check_interval_seconds=AUDIT_HEALTH_CHECK_INTERVAL_SECONDS,
    )

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

    # Create backend transport (handles detection, validation, health checks)
    transport, transport_type = create_backend_transport(config.backend)

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

    # Create lifespan context manager for audit health monitor
    # This starts the monitor when the proxy starts and stops it on shutdown
    @asynccontextmanager
    async def proxy_lifespan(app: FastMCP) -> AsyncIterator[None]:
        """Manage proxy lifecycle: start/stop audit health monitor."""
        # Note: app parameter required by FastMCP's _lifespan_manager
        try:
            await audit_monitor.start()
        except Exception as e:
            # Log failure and re-raise - Zero Trust requires monitoring
            system_logger.error(
                {
                    "event": "audit_health_monitor_start_failed",
                    "error": str(e),
                    "error_type": type(e).__name__,
                    "monitored_paths": [str(p) for p in audit_monitor.audit_paths],
                }
            )
            raise
        try:
            yield
        finally:
            await audit_monitor.stop()
            # Check if monitor crashed - if so, it's a fatal error
            # (The monitor itself triggers shutdown on crash via ShutdownCoordinator)
            if audit_monitor._crashed:
                system_logger.error(
                    {
                        "event": "audit_health_monitor_crash_detected",
                        "message": "Monitor crashed during shutdown check",
                    }
                )

    # Set the lifespan on the proxy (replaces default_lifespan)
    # NOTE: _lifespan is a private API. FastMCP may change this in future versions.
    # If FastMCP adds a public lifespan parameter to as_proxy() or Settings, migrate to that.
    # Tested with FastMCP 2.x - verify after upgrades.
    proxy._lifespan = proxy_lifespan

    # Create identity provider (Stage 1: local user via getpass.getuser())
    identity_provider = create_identity_provider()

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

    enforcement_middleware = create_enforcement_middleware(
        policy=policy,
        protected_dirs=protected_dirs,
        identity_provider=identity_provider,
        backend_id=config.backend.server_name,
        log_path=decisions_path,
        shutdown_callback=on_audit_failure,
        policy_version=policy_version,
    )
    proxy.add_middleware(enforcement_middleware)

    return proxy, transport_type
