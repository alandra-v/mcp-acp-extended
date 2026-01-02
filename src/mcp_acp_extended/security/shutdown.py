"""Graceful shutdown coordinator for critical security failures.

This module provides coordinated shutdown when security invariants are violated.
It ensures:
- Client receives clean error before disconnect
- Failure is logged to multiple destinations (defense in depth)
- Process terminates with correct exit code
- New requests are rejected during shutdown window
"""

from __future__ import annotations

import asyncio
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    import logging


def _write_crash_breadcrumb(
    log_dir: Path,
    failure_type: str,
    reason: str,
    exit_code: int,
    context: dict[str, Any] | None = None,
) -> None:
    """Write breadcrumb file with failure details.

    Location: <log_dir>/.last_crash
    Format:
        <timestamp>
        failure_type: <type>
        exit_code: <code>
        reason: <reason>
        context: <json>

    This format is:
    - Easy to parse programmatically (labeled fields)
    - Human-readable for operators
    - Minimal dependencies (simple text with one JSON field)

    Args:
        log_dir: Directory for breadcrumb file.
        failure_type: Category of failure (e.g., "audit_failure").
        reason: Human-readable description of the failure.
        exit_code: Process exit code (10=audit, 11=policy, 12=identity).
        context: Additional context for the failure.
    """
    import json

    try:
        log_dir.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass  # If we can't create dir, try writing anyway

    crash_file = log_dir / ".last_crash"
    timestamp = datetime.now(timezone.utc).isoformat()
    context_json = json.dumps(context) if context else "{}"
    crash_file.write_text(
        f"{timestamp}\n"
        f"failure_type: {failure_type}\n"
        f"exit_code: {exit_code}\n"
        f"reason: {reason}\n"
        f"context: {context_json}\n"
    )


class ShutdownCoordinator:
    """Coordinates graceful shutdown on critical security failures.

    Three audiences receive failure information:
    - Client (Claude Desktop): Clean MCP error before disconnect
    - Operator: Breadcrumb file + exit code + stderr
    - Auditor: Audit trail up to failure + system.jsonl

    Shutdown sequence:
    1. Set _shutdown_in_progress = True (reject new requests)
    2. Log to system.jsonl (best effort)
    3. Write breadcrumb file (best effort)
    4. Print to stderr (best effort)
    5. Schedule delayed exit (100ms for response to flush)
    6. Return control (caller raises MCP error to client)
    7. Background task calls os._exit() after delay
    """

    def __init__(self, log_dir: Path, system_logger: "logging.Logger") -> None:
        """Initialize the shutdown coordinator.

        Args:
            log_dir: Directory for breadcrumb file (e.g., ~/.../mcp_acp_extended_logs/)
            system_logger: System logger for critical events
        """
        self.log_dir = log_dir
        self.system_logger = system_logger
        self._shutdown_in_progress = False
        self._shutdown_reason: str | None = None
        self._shutdown_exit_code: int = 1

    @property
    def is_shutting_down(self) -> bool:
        """Check if shutdown is in progress.

        Middleware should check this and reject new requests during shutdown.
        """
        return self._shutdown_in_progress

    @property
    def shutdown_reason(self) -> str | None:
        """Get the reason for shutdown, if shutting down."""
        return self._shutdown_reason

    async def initiate_shutdown(
        self,
        failure_type: str,
        reason: str,
        exit_code: int,
        context: dict[str, Any] | None = None,
    ) -> None:
        """Initiate graceful shutdown sequence.

        This method:
        1. Sets shutdown flag to reject new requests
        2. Logs to system.jsonl and breadcrumb file
        3. Schedules delayed exit (100ms)
        4. Returns immediately so caller can raise MCP error

        Args:
            failure_type: Category of failure (e.g., "audit_failure")
            reason: Human-readable description
            exit_code: Process exit code (10=audit, 11=policy, 12=identity)
            context: Additional context for logging
        """
        if self._shutdown_in_progress:
            return  # Already shutting down, don't duplicate

        self._shutdown_in_progress = True
        self._shutdown_reason = reason
        self._shutdown_exit_code = exit_code
        print(f"[SHUTDOWN] Initiating shutdown: {reason}", file=sys.stderr, flush=True)

        # 1. Log to system.jsonl (best effort - may fail for same reason as audit)
        try:
            self.system_logger.critical(
                {
                    "event": "critical_security_failure",
                    "failure_type": failure_type,
                    "reason": reason,
                    "exit_code": exit_code,
                    "context": context,
                    "action": "shutdown_initiated",
                    "message": f"Proxy shutting down: {reason}",
                }
            )
        except Exception:
            pass  # Best effort - continue with other fallbacks

        # 2. Write breadcrumb file (best effort - simple text, likely to succeed)
        try:
            _write_crash_breadcrumb(self.log_dir, failure_type, reason, exit_code, context)
        except Exception:
            pass  # Best effort

        # 3. Print to stderr (best effort - may not be visible to operator)
        try:
            print(
                f"CRITICAL: Proxy shutting down - {failure_type}\n"
                f"  Reason: {reason}\n"
                f"  Exit code: {exit_code}",
                file=sys.stderr,
            )
        except Exception:
            pass  # Best effort

        # 4. Schedule delayed exit (allows MCP error response to flush)
        asyncio.create_task(self._delayed_exit())

    async def _delayed_exit(self) -> None:
        """Exit after delay to allow MCP error response to flush.

        100ms is conservative for a small JSON error response.
        Uses os._exit() which cannot be caught by exception handlers.
        """
        print("[SHUTDOWN] Waiting 100ms before exit...", file=sys.stderr, flush=True)
        await asyncio.sleep(0.1)  # 100ms
        print(f"[SHUTDOWN] Calling os._exit({self._shutdown_exit_code})", file=sys.stderr, flush=True)
        os._exit(self._shutdown_exit_code)


def sync_emergency_shutdown(
    log_dir: Path,
    failure_type: str,
    reason: str,
    exit_code: int,
) -> None:
    """Synchronous emergency shutdown when no event loop is available.

    This is a fallback for when the audit handler callback fires
    before the event loop is running or from a non-async context.

    Args:
        log_dir: Directory for breadcrumb file
        failure_type: Category of failure
        reason: Human-readable description
        exit_code: Process exit code
    """
    print(f"[SHUTDOWN-SYNC] Emergency shutdown: {reason}", file=sys.stderr, flush=True)

    # 1. Write breadcrumb file
    try:
        _write_crash_breadcrumb(log_dir, failure_type, reason, exit_code)
    except Exception:
        pass

    # 2. Print to stderr
    try:
        print(
            f"CRITICAL: Proxy shutting down - {failure_type}\n"
            f"  Reason: {reason}\n"
            f"  Exit code: {exit_code}",
            file=sys.stderr,
            flush=True,
        )
    except Exception:
        pass

    # 3. Exit immediately (no delay since we can't wait for response flush)
    print(f"[SHUTDOWN-SYNC] Calling os._exit({exit_code})", file=sys.stderr, flush=True)
    os._exit(exit_code)
