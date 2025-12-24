"""Configuration history logging.

Logs configuration lifecycle events to config_history.jsonl:
- config_created: Initial creation via CLI init
- config_loaded: Loaded at proxy startup
- config_updated: Updated via CLI commands
- manual_change_detected: File modified outside of CLI
- config_validation_failed: Invalid JSON or schema
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from mcp_acp_extended.constants import INITIAL_VERSION
from mcp_acp_extended.telemetry.models.system import ConfigHistoryEvent
from mcp_acp_extended.utils.config.config_helpers import compute_config_checksum
from mcp_acp_extended.utils.file_helpers import (
    VersionInfo,
    get_history_logger,
    get_last_version_info,
    get_next_version,
)

# Re-export for backwards compatibility
__all__ = [
    "VersionInfo",
    "get_next_version",
    "detect_config_changes",
    "log_config_created",
    "log_config_loaded",
    "log_config_updated",
    "log_config_validation_failed",
]


def _get_last_config_version_info(config_history_path: Path) -> VersionInfo:
    """Get version info using config_version field."""
    return get_last_version_info(config_history_path, version_field="config_version")


def _log_config_history_event(
    config_history_path: Path,
    event: ConfigHistoryEvent,
) -> None:
    """Log a ConfigHistoryEvent to config_history.jsonl."""
    logger = get_history_logger(config_history_path, "mcp-acp-extended.config.history")
    log_data = event.model_dump(exclude={"time"}, exclude_none=True)
    logger.info(log_data)


def detect_config_changes(
    old_config: dict[str, Any],
    new_config: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    """Detect changes between two configuration snapshots.

    Performs a deep comparison and returns a dictionary of changes with
    dotted paths as keys (e.g., "logging.log_level").

    Args:
        old_config: Previous configuration snapshot.
        new_config: New configuration snapshot.

    Returns:
        dict: Dictionary mapping changed paths to {"old": ..., "new": ...}

    Example:
        >>> detect_config_changes(
        ...     {"logging": {"log_level": "INFO"}},
        ...     {"logging": {"log_level": "DEBUG"}}
        ... )
        {"logging.log_level": {"old": "INFO", "new": "DEBUG"}}
    """
    changes: dict[str, dict[str, Any]] = {}

    def compare_dicts(old: dict[str, Any], new: dict[str, Any], path: str = "") -> None:
        """Recursively compare dictionaries and record changes."""
        # Check for changed or removed keys
        for key in old:
            current_path = f"{path}.{key}" if path else key
            if key not in new:
                changes[current_path] = {"old": old[key], "new": None}
            elif isinstance(old[key], dict) and isinstance(new[key], dict):
                compare_dicts(old[key], new[key], current_path)
            elif old[key] != new[key]:
                changes[current_path] = {"old": old[key], "new": new[key]}

        # Check for added keys
        for key in new:
            if key not in old:
                current_path = f"{path}.{key}" if path else key
                changes[current_path] = {"old": None, "new": new[key]}

    compare_dicts(old_config, new_config)
    return changes


def log_config_created(
    config_history_path: Path,
    config_path: Path,
    config_snapshot: dict[str, Any],
    source: str = "cli_init",
) -> str:
    """Log config creation event with versioning.

    Called when a new configuration is created via CLI init.
    If config history exists (e.g., init --force), increments version.

    Args:
        config_history_path: Path to config_history.jsonl.
        config_path: Path to the config file (for checksum computation).
        config_snapshot: Configuration as dictionary.
        source: Source of creation (default: cli_init).

    Returns:
        str: The new config version (e.g., "v1" or "v2" if overwriting).
    """
    checksum = compute_config_checksum(config_path)

    # Check for existing history (e.g., init --force overwrites)
    last_info = _get_last_config_version_info(config_history_path)
    if last_info.version is not None:
        # Overwriting existing config - increment version
        new_version = get_next_version(last_info.version)
        previous_version = last_info.version
    else:
        # First time creation
        new_version = INITIAL_VERSION
        previous_version = None

    event = ConfigHistoryEvent(
        event="config_created",
        message="Configuration created",
        config_version=new_version,
        previous_version=previous_version,
        change_type="initial_load",
        component="cli",
        config_path=str(config_path),
        source=source,
        checksum=checksum,
        snapshot_format="json",
        snapshot=json.dumps(config_snapshot, indent=2),
    )

    _log_config_history_event(config_history_path, event)
    return new_version


def log_config_loaded(
    config_history_path: Path,
    config_path: Path,
    config_snapshot: dict[str, Any],
    component: str = "proxy",
    source: str = "proxy_startup",
) -> tuple[str, bool]:
    """Log config loaded event, detecting manual changes.

    Compares current checksum with last logged checksum.
    If different, logs manual_change_detected first.

    Args:
        config_history_path: Path to config_history.jsonl.
        config_path: Path to the config file.
        config_snapshot: Configuration as dictionary.
        component: Component loading config (default: proxy).
        source: Source of load (default: proxy_startup).

    Returns:
        Tuple of (current_version, manual_change_detected).
    """
    current_checksum = compute_config_checksum(config_path)
    last_info = _get_last_config_version_info(config_history_path)

    manual_change = False
    current_version = last_info.version or INITIAL_VERSION

    # Check for manual edit (checksum changed but not through our logging)
    if last_info.checksum is not None and last_info.checksum != current_checksum:
        manual_change = True
        current_version = get_next_version(last_info.version)

        # Log manual change detected
        manual_event = ConfigHistoryEvent(
            event="manual_change_detected",
            message="Configuration file modified outside of CLI",
            config_version=current_version,
            previous_version=last_info.version,
            change_type="manual_edit",
            component=component,
            config_path=str(config_path),
            source="file_change",
            checksum=current_checksum,
            snapshot_format="json",
            snapshot=json.dumps(config_snapshot, indent=2),
        )
        _log_config_history_event(config_history_path, manual_event)

    # Log config loaded
    loaded_event = ConfigHistoryEvent(
        event="config_loaded",
        message="Configuration loaded",
        config_version=current_version,
        previous_version=None,  # Not applicable for loaded events
        change_type="startup_load",
        component=component,
        config_path=str(config_path),
        source=source,
        checksum=current_checksum,
        snapshot_format="json",
        snapshot=None,  # Don't duplicate snapshot for load events
    )
    _log_config_history_event(config_history_path, loaded_event)

    return current_version, manual_change


def log_config_updated(
    config_history_path: Path,
    config_path: Path,
    old_config: dict[str, Any],
    new_config: dict[str, Any],
    source: str = "cli_update",
) -> str | None:
    """Log config update event with detected changes.

    Args:
        config_history_path: Path to config_history.jsonl.
        config_path: Path to the config file.
        old_config: Previous configuration snapshot.
        new_config: New configuration snapshot.
        source: Source of update (default: cli_update).

    Returns:
        str: New version number, or None if no changes detected.
    """
    changes = detect_config_changes(old_config, new_config)

    if not changes:
        # No changes, don't log
        return None

    last_info = _get_last_config_version_info(config_history_path)
    new_version = get_next_version(last_info.version)
    checksum = compute_config_checksum(config_path)

    event = ConfigHistoryEvent(
        event="config_updated",
        message=f"Configuration updated ({len(changes)} change(s))",
        config_version=new_version,
        previous_version=last_info.version,
        change_type="cli_update",
        component="cli",
        config_path=str(config_path),
        source=source,
        checksum=checksum,
        snapshot_format="json",
        snapshot=json.dumps(new_config, indent=2),
        changes=changes,
    )

    _log_config_history_event(config_history_path, event)
    return new_version


def log_config_validation_failed(
    config_history_path: Path,
    config_path: Path,
    error_type: str,
    error_message: str,
    component: str = "config",
    source: str = "load_from_files",
) -> None:
    """Log config validation failure event.

    Called when configuration fails to load due to invalid JSON or schema.

    Note on log location:
        When validation fails, we cannot read log_dir from the invalid config.
        The caller (cli.py) uses a fallback location in the config directory:
            <config_dir>/mcp_acp_extended_logs/system/config_history.jsonl
        instead of the normal location:
            <log_dir>/mcp_acp_extended_logs/system/config_history.jsonl

        This ensures validation failures are always logged to a predictable
        location even when the config is corrupt or missing required fields.

    Args:
        config_history_path: Path to config_history.jsonl (may be fallback path).
        config_path: Path to the config file.
        error_type: Type of error (e.g., "JSONDecodeError", "ValidationError").
        error_message: Human-readable error message.
        component: Component that detected error.
        source: Source of validation attempt.
    """
    # Try to compute checksum even for invalid config
    try:
        checksum = compute_config_checksum(config_path)
    except (OSError, FileNotFoundError):
        checksum = "sha256:unknown"

    last_info = _get_last_config_version_info(config_history_path)

    event = ConfigHistoryEvent(
        event="config_validation_failed",
        message=f"Configuration validation failed: {error_type}",
        config_version=last_info.version or "unknown",
        previous_version=None,
        change_type="validation_error",
        component=component,
        config_path=str(config_path),
        source=source,
        checksum=checksum,
        snapshot_format="json",
        snapshot=None,
        error_type=error_type,
        error_message=error_message,
    )

    _log_config_history_event(config_history_path, event)
