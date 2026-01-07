"""API client helper for CLI commands that need runtime proxy data.

Provides a simple interface for CLI commands to call the proxy's HTTP API.
Used by runtime commands (status, sessions, approvals) that need data from
the running proxy.

File-based commands (logs, policy show, config show) should read files
directly instead of using this module.
"""

from __future__ import annotations

__all__ = [
    "APIError",
    "ProxyNotRunningError",
    "api_request",
    "get_api_connection",
]

import json
from typing import Any

import click
import httpx

from mcp_acp_extended.api.security import read_manager_file
from mcp_acp_extended.constants import DEFAULT_HTTP_TIMEOUT_SECONDS


class ProxyNotRunningError(click.ClickException):
    """Raised when proxy is not running (no manager.json)."""

    def __init__(self) -> None:
        super().__init__("Proxy not running.\n" "Start it with: mcp-acp-extended start")


class APIError(click.ClickException):
    """Raised when API request fails."""

    def __init__(self, message: str, status_code: int | None = None) -> None:
        if status_code:
            super().__init__(f"API error ({status_code}): {message}")
        else:
            super().__init__(f"API error: {message}")
        self.status_code = status_code


def get_api_connection() -> tuple[str, dict[str, str]]:
    """Get API base URL and auth headers.

    Reads connection info from ~/.mcp-acp-extended/manager.json which is
    written by the proxy on startup.

    Returns:
        Tuple of (base_url, headers) for making API requests.

    Raises:
        ProxyNotRunningError: If manager.json doesn't exist (proxy not running).
    """
    manager = read_manager_file()
    if not manager:
        raise ProxyNotRunningError()

    port = manager["port"]
    token = manager["token"]

    base_url = f"http://127.0.0.1:{port}"
    headers = {"Authorization": f"Bearer {token}"}

    return base_url, headers


def api_request(
    method: str,
    endpoint: str,
    *,
    json_data: dict[str, Any] | None = None,
    params: dict[str, Any] | None = None,
    timeout: float = DEFAULT_HTTP_TIMEOUT_SECONDS,
) -> dict[str, Any] | list[Any]:
    """Make an authenticated API request to the running proxy.

    Args:
        method: HTTP method (GET, POST, DELETE, etc.)
        endpoint: API endpoint path (e.g., "/api/control/status")
        json_data: Optional JSON body for POST/PUT requests.
        params: Optional query parameters.
        timeout: Request timeout in seconds.

    Returns:
        Parsed JSON response.

    Raises:
        ProxyNotRunningError: If proxy is not running.
        APIError: If request fails or returns error status.
    """
    base_url, headers = get_api_connection()

    try:
        with httpx.Client(timeout=timeout) as client:
            response = client.request(
                method,
                f"{base_url}{endpoint}",
                headers=headers,
                json=json_data,
                params=params,
            )
            response.raise_for_status()

            # Handle 204 No Content
            if response.status_code == 204:
                return {}

            result = response.json()
            if isinstance(result, (dict, list)):
                return result
            # Unexpected JSON type - wrap in dict
            return {"value": result}

    except httpx.ConnectError as e:
        # Proxy not reachable even though manager.json exists
        raise APIError(f"Cannot connect to proxy: {e}") from e
    except httpx.HTTPStatusError as e:
        # API returned error status
        try:
            detail = e.response.json().get("detail", str(e))
        except (json.JSONDecodeError, KeyError):
            detail = str(e)
        raise APIError(detail, e.response.status_code) from e
    except httpx.HTTPError as e:
        raise APIError(str(e)) from e
