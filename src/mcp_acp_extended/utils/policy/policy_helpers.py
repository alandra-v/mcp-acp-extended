"""Policy loader - load and save policy configuration.

This module provides functions to load policy.json from the config directory
and save policy changes (e.g., when user adds "Always Deny" rules via HITL).

Features:
- Secure file permissions (0o700 for directory, 0o600 for file)
- Detailed validation error messages
- SHA256 checksum for integrity verification
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from pydantic import ValidationError

from mcp_acp_extended.pdp.policy import PolicyConfig, create_default_policy
from mcp_acp_extended.utils.file_helpers import (
    compute_file_checksum,
    get_app_dir,
    set_secure_permissions,
)

# Re-export for convenience
__all__ = [
    "get_policy_dir",
    "get_policy_path",
    "compute_policy_checksum",
    "load_policy",
    "save_policy",
    "policy_exists",
    "create_default_policy_file",
]


def get_policy_dir() -> Path:
    """Get the OS-appropriate config directory for policy files.

    Uses the same directory as mcp_acp_extended_config.json:
    - macOS: ~/Library/Application Support/mcp-acp-extended
    - Linux: ~/.config/mcp-acp-extended (XDG compliant)
    - Windows: C:\\Users\\<user>\\AppData\\Roaming\\mcp-acp-extended

    Returns:
        Path to the config directory.
    """
    return get_app_dir()


def get_policy_path() -> Path:
    """Get the full path to the policy file.

    Returns:
        Path to policy.json in the config directory.
    """
    return get_policy_dir() / "policy.json"


def compute_policy_checksum(policy_path: Path) -> str:
    """Compute SHA256 checksum of policy file content.

    Used for integrity verification and detecting manual edits.

    Args:
        policy_path: Path to the policy file.

    Returns:
        str: Checksum in format "sha256:<hex_digest>".

    Raises:
        FileNotFoundError: If policy file doesn't exist.
        OSError: If policy file cannot be read.
    """
    return compute_file_checksum(policy_path)


def load_policy(path: Path | None = None) -> PolicyConfig:
    """Load policy configuration from file.

    Args:
        path: Path to policy.json. If None, uses default location.

    Returns:
        PolicyConfig loaded from file.

    Raises:
        FileNotFoundError: If policy file does not exist.
        ValueError: If policy file contains invalid JSON or schema.
    """
    policy_path = path or get_policy_path()

    if not policy_path.exists():
        raise FileNotFoundError(
            f"Policy file not found at {policy_path}.\n" "Run 'mcp-acp-extended init' to create a policy file."
        )

    try:
        with policy_path.open() as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in policy file {policy_path}: {e}") from e
    except OSError as e:
        raise ValueError(f"Could not read policy file {policy_path}: {e}") from e

    try:
        return PolicyConfig.model_validate(data)
    except ValidationError as e:
        # Format detailed error messages like AppConfig does
        errors = []
        for error in e.errors():
            loc = ".".join(str(x) for x in error["loc"])
            msg = error["msg"]
            errors.append(f"  - {loc}: {msg}")

        raise ValueError(
            f"Invalid policy configuration in {policy_path}:\n"
            + "\n".join(errors)
            + "\n\nEdit the policy file or run 'mcp-acp-extended init' to recreate."
        ) from e


def save_policy(policy: PolicyConfig, path: Path | None = None) -> None:
    """Save policy configuration to file atomically.

    Uses atomic write pattern: write to temp file, then rename.
    This prevents file corruption if write fails midway.

    Creates parent directories if they don't exist.
    Sets secure permissions (0o700 on directory, 0o600 on file).

    Args:
        policy: PolicyConfig to save.
        path: Path to save to. If None, uses default location.
    """
    policy_path = path or get_policy_path()

    # Ensure parent directory exists with secure permissions
    policy_path.parent.mkdir(parents=True, exist_ok=True)
    set_secure_permissions(policy_path.parent, is_directory=True)

    # Convert to dict and format as JSON
    data = policy.model_dump(mode="json")
    content = json.dumps(data, indent=2) + "\n"  # Trailing newline

    # Atomic write: write to temp file in same directory, then rename
    # Same directory ensures rename is atomic (same filesystem)
    fd, temp_path = tempfile.mkstemp(
        dir=policy_path.parent,
        prefix=".policy_",
        suffix=".tmp",
    )
    try:
        # Write content to temp file
        with os.fdopen(fd, "w") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())  # Ensure data is on disk

        # Set secure permissions on temp file before rename
        os.chmod(temp_path, 0o600)

        # Atomic rename (overwrites existing file atomically)
        os.replace(temp_path, policy_path)

    except Exception:
        # Clean up temp file on failure
        try:
            os.unlink(temp_path)
        except OSError:
            pass
        raise


def policy_exists(path: Path | None = None) -> bool:
    """Check if policy file exists.

    Args:
        path: Path to check. If None, uses default location.

    Returns:
        True if policy file exists.
    """
    policy_path = path or get_policy_path()
    return policy_path.exists()


def create_default_policy_file(path: Path | None = None) -> PolicyConfig:
    """Create a default policy file if it doesn't exist.

    Args:
        path: Path to create. If None, uses default location.

    Returns:
        The PolicyConfig that was created.

    Raises:
        FileExistsError: If policy file already exists.
    """
    policy_path = path or get_policy_path()

    if policy_path.exists():
        raise FileExistsError(f"Policy file already exists: {policy_path}")

    policy = create_default_policy()
    save_policy(policy, policy_path)
    return policy
