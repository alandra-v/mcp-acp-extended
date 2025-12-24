"""Policy history logging.

Logs policy lifecycle events to policy_history.jsonl:
- policy_created: Initial creation via CLI init
- policy_loaded: Loaded at proxy startup
- manual_change_detected: File modified outside of proxy
- policy_validation_failed: Invalid JSON or schema
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from mcp_acp_extended.constants import INITIAL_VERSION
from mcp_acp_extended.telemetry.models.system import PolicyHistoryEvent
from mcp_acp_extended.utils.file_helpers import (
    VersionInfo,
    get_history_logger,
    get_last_version_info,
    get_next_version,
)
from mcp_acp_extended.utils.policy import compute_policy_checksum

# Re-export for backwards compatibility
__all__ = [
    "VersionInfo",
    "get_next_version",
    "log_policy_created",
    "log_policy_loaded",
    "log_policy_validation_failed",
    "get_policy_history_path_from_config_dir",
]


def _get_last_policy_version_info(policy_history_path: Path) -> VersionInfo:
    """Get version info using policy_version field."""
    return get_last_version_info(policy_history_path, version_field="policy_version")


def _log_policy_history_event(
    policy_history_path: Path,
    event: PolicyHistoryEvent,
) -> None:
    """Log a PolicyHistoryEvent to policy_history.jsonl."""
    logger = get_history_logger(policy_history_path, "mcp-acp-extended.policy.history")
    log_data = event.model_dump(exclude={"time"}, exclude_none=True)
    logger.info(log_data)


def log_policy_created(
    policy_history_path: Path,
    policy_path: Path,
    policy_snapshot: dict[str, Any],
    source: str = "cli_init",
) -> str:
    """Log policy creation event with versioning.

    Called when a new policy is created via CLI init.
    If policy history exists (e.g., init --force), increments version.

    Args:
        policy_history_path: Path to policy_history.jsonl.
        policy_path: Path to the policy file (for checksum computation).
        policy_snapshot: Policy as dictionary.
        source: Source of creation (default: cli_init).

    Returns:
        str: The new policy version (e.g., "v1" or "v2" if overwriting).
    """
    checksum = compute_policy_checksum(policy_path)

    # Check for existing history (e.g., init --force overwrites)
    last_info = _get_last_policy_version_info(policy_history_path)
    if last_info.version is not None:
        # Overwriting existing policy - increment version
        new_version = get_next_version(last_info.version)
        previous_version = last_info.version
    else:
        # First time creation
        new_version = INITIAL_VERSION
        previous_version = None

    event = PolicyHistoryEvent(
        event="policy_created",
        message="Policy created",
        policy_version=new_version,
        previous_version=previous_version,
        change_type="initial_creation",
        component="cli",
        policy_path=str(policy_path),
        source=source,
        checksum=checksum,
        snapshot_format="json",
        snapshot=json.dumps(policy_snapshot, indent=2),
    )

    _log_policy_history_event(policy_history_path, event)
    return new_version


def log_policy_loaded(
    policy_history_path: Path,
    policy_path: Path,
    policy_snapshot: dict[str, Any],
    component: str = "proxy",
    source: str = "proxy_startup",
) -> tuple[str, bool]:
    """Log policy loaded event, detecting manual changes.

    Compares current checksum with last logged checksum.
    If different, logs manual_change_detected first.

    Args:
        policy_history_path: Path to policy_history.jsonl.
        policy_path: Path to the policy file.
        policy_snapshot: Policy as dictionary.
        component: Component loading policy (default: proxy).
        source: Source of load (default: proxy_startup).

    Returns:
        Tuple of (current_version, manual_change_detected).
    """
    current_checksum = compute_policy_checksum(policy_path)
    last_info = _get_last_policy_version_info(policy_history_path)

    manual_change = False
    current_version = last_info.version or INITIAL_VERSION

    # Check for manual edit (checksum changed but not through our logging)
    if last_info.checksum is not None and last_info.checksum != current_checksum:
        manual_change = True
        current_version = get_next_version(last_info.version)

        # Log manual change detected
        manual_event = PolicyHistoryEvent(
            event="manual_change_detected",
            message="Policy file modified outside of proxy",
            policy_version=current_version,
            previous_version=last_info.version,
            change_type="manual_edit",
            component=component,
            policy_path=str(policy_path),
            source="file_change",
            checksum=current_checksum,
            snapshot_format="json",
            snapshot=json.dumps(policy_snapshot, indent=2),
        )
        _log_policy_history_event(policy_history_path, manual_event)

    # Log policy loaded
    loaded_event = PolicyHistoryEvent(
        event="policy_loaded",
        message="Policy loaded",
        policy_version=current_version,
        previous_version=None,  # Not applicable for loaded events
        change_type="startup_load",
        component=component,
        policy_path=str(policy_path),
        source=source,
        checksum=current_checksum,
        snapshot_format="json",
        snapshot=None,  # Don't duplicate snapshot for load events
    )
    _log_policy_history_event(policy_history_path, loaded_event)

    return current_version, manual_change


def log_policy_validation_failed(
    policy_history_path: Path,
    policy_path: Path,
    error_type: str,
    error_message: str,
    component: str = "policy",
    source: str = "load_policy",
) -> None:
    """Log policy validation failure event.

    Called when policy fails to load due to invalid JSON or schema.

    Args:
        policy_history_path: Path to policy_history.jsonl.
        policy_path: Path to the policy file.
        error_type: Type of error (e.g., "JSONDecodeError", "ValidationError").
        error_message: Human-readable error message.
        component: Component that detected error.
        source: Source of validation attempt.
    """
    # Try to compute checksum even for invalid policy
    try:
        checksum = compute_policy_checksum(policy_path)
    except (OSError, FileNotFoundError):
        checksum = "sha256:unknown"

    last_info = _get_last_policy_version_info(policy_history_path)

    event = PolicyHistoryEvent(
        event="policy_validation_failed",
        message=f"Policy validation failed: {error_type}",
        policy_version=last_info.version or "unknown",
        previous_version=None,
        change_type="validation_error",
        component=component,
        policy_path=str(policy_path),
        source=source,
        checksum=checksum,
        snapshot_format="json",
        snapshot=None,
        error_type=error_type,
        error_message=error_message,
    )

    _log_policy_history_event(policy_history_path, event)


def get_policy_history_path_from_config_dir() -> Path:
    """Get policy history path in config directory (fallback location).

    Used when we can't read log_dir from config (e.g., validation failure).

    Returns:
        Path to policy_history.jsonl in config directory.
    """
    from mcp_acp_extended.utils.policy import get_policy_dir

    return get_policy_dir() / "mcp_acp_extended_logs" / "system" / "policy_history.jsonl"
