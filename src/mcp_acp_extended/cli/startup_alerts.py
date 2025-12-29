"""Startup error alerts for macOS.

Displays native macOS alert dialogs for pre-start failures.
Used by proxy.py and CLI commands when startup fails due to
configuration, authentication, or device health issues.

Non-blocking on other platforms (returns immediately).
"""

from __future__ import annotations

import platform
import subprocess

__all__ = [
    "show_startup_error_popup",
]

# Timeout for AppleScript dialogs (seconds)
# User has 30 seconds to acknowledge the dialog before it auto-closes
_DIALOG_TIMEOUT_SECONDS = 30


def _escape_applescript_string(s: str) -> str:
    """Escape a string for safe use in AppleScript.

    Escapes backslashes, double quotes, and control characters to prevent
    AppleScript injection and ensure proper dialog rendering.

    Args:
        s: The string to escape.

    Returns:
        Escaped string safe for AppleScript interpolation.
    """
    # Replace control characters with spaces (they could break dialog rendering)
    s = s.replace("\n", " ")
    s = s.replace("\r", " ")
    s = s.replace("\t", " ")
    # Escape backslashes (order matters - must be before quotes)
    s = s.replace("\\", "\\\\")
    # Escape double quotes
    s = s.replace('"', '\\"')
    return s


def show_startup_error_popup(
    title: str = "MCP ACP",
    message: str = "Startup failed.",
    detail: str = "Check logs for details.",
) -> bool:
    """Show a startup error popup on macOS.

    Displays a native macOS alert dialog when proxy startup fails.
    Used for pre-start failures (auth, config, device health, etc.).
    Non-blocking on other platforms (returns immediately).

    Args:
        title: Alert title (default: "MCP ACP").
        message: Main message text describing the failure.
        detail: Additional detail text (e.g., command to run to fix).

    Returns:
        True if popup was shown, False if not on macOS or osascript failed.
    """
    if platform.system() != "Darwin":
        # Not macOS - can't show native popup
        return False

    # Escape strings for AppleScript
    safe_title = _escape_applescript_string(title)
    safe_message = _escape_applescript_string(message)
    safe_detail = _escape_applescript_string(detail)

    # Build AppleScript command
    script = f"""
    display alert "{safe_title}" message "{safe_message}

{safe_detail}" as critical buttons {{"OK"}} default button "OK"
    """

    try:
        subprocess.run(
            ["osascript", "-e", script],
            capture_output=True,
            timeout=_DIALOG_TIMEOUT_SECONDS,
        )
        return True
    except (subprocess.SubprocessError, OSError):
        # osascript failed or not available
        return False
