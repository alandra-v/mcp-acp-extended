"""AppleScript utilities for macOS dialog handling.

Provides safe string escaping and output parsing for AppleScript dialogs.
Used by HITL (Human-in-the-Loop) approval flows and auth error notifications.
"""

from __future__ import annotations

import platform
import re
import subprocess

__all__ = [
    "escape_applescript_string",
    "parse_applescript_record",
    "show_auth_error_popup",
]


def escape_applescript_string(s: str) -> str:
    """Escape a string for safe use in AppleScript.

    Escapes backslashes, double quotes, and control characters to prevent
    AppleScript injection and ensure proper dialog rendering.

    Args:
        s: The string to escape.

    Returns:
        Escaped string safe for AppleScript interpolation.

    Example:
        >>> escape_applescript_string('Path: /tmp/test"file')
        'Path: /tmp/test\\\\"file'
        >>> escape_applescript_string('line1\\nline2')
        'line1 line2'
    """
    # Replace control characters with spaces (they could break dialog rendering)
    # Do this first before escaping backslashes
    s = s.replace("\n", " ")
    s = s.replace("\r", " ")
    s = s.replace("\t", " ")
    # Escape backslashes (order matters - must be before quotes)
    s = s.replace("\\", "\\\\")
    # Escape double quotes
    s = s.replace('"', '\\"')
    return s


def parse_applescript_record(output: str) -> dict[str, str]:
    """Parse AppleScript record output into a dictionary.

    AppleScript returns records like: {button returned:"Allow", gave up:false}
    This parser handles the format robustly, accounting for potential spacing
    variations in future macOS versions.

    Args:
        output: Raw osascript stdout output.

    Returns:
        Dictionary of key-value pairs from the record.
        Values are returned as strings (e.g., "true", "false", "Allow").

    Example:
        >>> parse_applescript_record('{button returned:"Allow", gave up:false}')
        {'button returned': 'Allow', 'gave up': 'false'}
    """
    result: dict[str, str] = {}

    # Match key:value pairs where value is either quoted or unquoted
    # Pattern handles: key:"quoted value" or key:unquoted_value
    pattern = r'(\w+(?:\s+\w+)*)\s*:\s*(?:"([^"]*)"|(\w+))'

    for match in re.finditer(pattern, output):
        key = match.group(1)
        # Value is either in group 2 (quoted) or group 3 (unquoted)
        value = match.group(2) if match.group(2) is not None else match.group(3)
        result[key] = value

    return result


def show_auth_error_popup(
    title: str = "Authentication Required",
    message: str = "Your session has expired.",
    detail: str = "Run 'mcp-acp-extended auth login' to re-authenticate.",
) -> bool:
    """Show an authentication error popup on macOS.

    Displays a native macOS alert dialog when authentication fails.
    Non-blocking on other platforms (returns immediately).

    Args:
        title: Alert title (default: "Authentication Required").
        message: Main message text.
        detail: Additional detail text (e.g., command to run).

    Returns:
        True if popup was shown, False if not on macOS or osascript failed.

    Example:
        >>> show_auth_error_popup()  # doctest: +SKIP
        True
    """
    if platform.system() != "Darwin":
        # Not macOS - can't show native popup
        return False

    # Escape strings for AppleScript
    safe_title = escape_applescript_string(title)
    safe_message = escape_applescript_string(message)
    safe_detail = escape_applescript_string(detail)

    # Build AppleScript command
    script = f"""
    display alert "{safe_title}" message "{safe_message}

{safe_detail}" as critical buttons {{"OK"}} default button "OK"
    """

    try:
        subprocess.run(
            ["osascript", "-e", script],
            capture_output=True,
            timeout=30,  # Don't hang forever
        )
        return True
    except (subprocess.SubprocessError, OSError):
        # osascript failed or not available
        return False
