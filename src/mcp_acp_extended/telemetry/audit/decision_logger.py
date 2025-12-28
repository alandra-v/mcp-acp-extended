"""Decision logging for policy enforcement.

This module provides logging for policy decisions (ALLOW, DENY, HITL).
Logs are written to <log_dir>/mcp_acp_extended_logs/audit/decisions.jsonl.

Decision logs are ALWAYS enabled (not controlled by log_level).
"""

import logging
from pathlib import Path
from typing import Callable

from mcp_acp_extended.utils.logging.logger_setup import setup_failclosed_audit_logger


def create_decision_logger(
    log_path: Path,
    shutdown_callback: Callable[[str], None],
) -> logging.Logger:
    """Create logger for decision events with fail-closed integrity checking.

    Args:
        log_path: Path to decisions.jsonl file.
        shutdown_callback: Called if audit log integrity check fails.

    Returns:
        Configured logger instance with fail-closed handler.
    """
    return setup_failclosed_audit_logger(
        "mcp-acp-extended.audit.decisions",
        log_path,
        shutdown_callback=shutdown_callback,
        log_level=logging.INFO,
    )
