"""Transport utilities for backend connection.

Handles transport selection, health checks, and creation.
Supports STDIO (local process) and Streamable HTTP (remote URL) transports.
"""

import asyncio
from typing import TYPE_CHECKING, Literal

from fastmcp.client.transports import ClientTransport, StdioTransport, StreamableHttpTransport
from fastmcp.server.proxy import ProxyClient

from mcp_acp_extended.constants import HEALTH_CHECK_TIMEOUT_SECONDS, TRANSPORT_ERRORS

if TYPE_CHECKING:
    from mcp_acp_extended.config import BackendConfig, HttpTransportConfig, StdioTransportConfig


def check_http_health(url: str, timeout: float = HEALTH_CHECK_TIMEOUT_SECONDS) -> None:
    """Check if an HTTP endpoint is reachable.

    Tests connectivity by attempting an MCP initialize handshake.

    Args:
        url: The backend URL to test.
        timeout: Connection timeout in seconds (default: HEALTH_CHECK_TIMEOUT_SECONDS).

    Raises:
        TimeoutError: If connection times out.
        ConnectionError: If connection fails.
    """
    try:
        asyncio.get_running_loop()
        in_async_context = True
    except RuntimeError:
        in_async_context = False

    if in_async_context:
        import concurrent.futures

        with concurrent.futures.ThreadPoolExecutor() as executor:
            future = executor.submit(asyncio.run, _check_async(url, timeout))
            future.result()
    else:
        asyncio.run(_check_async(url, timeout))


def create_backend_transport(
    backend_config: "BackendConfig",
) -> tuple[ClientTransport, Literal["streamablehttp", "stdio"]]:
    """Create backend transport with auto-detection and health checks.

    Transport selection logic:
    1. If transport explicitly set: use it (validate config exists, check HTTP health)
    2. If transport is None (auto-detect):
       - Both configured: try HTTP first, fall back to STDIO if unreachable
       - HTTP only: use HTTP (fail if unreachable)
       - STDIO only: use STDIO
       - Neither: raise error

    Args:
        backend_config: Backend configuration.

    Returns:
        Tuple of (transport_instance, transport_type).

    Raises:
        ValueError: If no transport configured or config missing.
        TimeoutError: If HTTP backend times out.
        ConnectionError: If HTTP backend unreachable.
    """
    http_config = backend_config.http
    stdio_config = backend_config.stdio
    explicit_transport = backend_config.transport

    # Determine transport type
    if explicit_transport is not None:
        # Explicit selection - validate config exists
        if explicit_transport == "streamablehttp":
            if http_config is None:
                raise ValueError(
                    "Streamable HTTP transport selected but http configuration is missing. "
                    "Run 'mcp-acp-extended init' to configure the backend URL."
                )
            check_http_health(http_config.url, min(http_config.timeout, HEALTH_CHECK_TIMEOUT_SECONDS))
        elif explicit_transport == "stdio" and stdio_config is None:
            raise ValueError(
                "STDIO transport selected but stdio configuration is missing. "
                "Run 'mcp-acp-extended init' to configure the backend command."
            )
        transport_type = explicit_transport
    else:
        # Auto-detect
        transport_type = _auto_detect(http_config, stdio_config)

    # Create transport
    if transport_type == "streamablehttp":
        if http_config is None:
            raise ValueError(
                "Internal error: HTTP transport selected but http_config is None. "
                "This indicates a bug in transport selection logic."
            )
        transport: ClientTransport = StreamableHttpTransport(url=http_config.url)
    else:
        if stdio_config is None:
            raise ValueError(
                "Internal error: STDIO transport selected but stdio_config is None. "
                "This indicates a bug in transport selection logic."
            )
        transport = StdioTransport(
            command=stdio_config.command,
            args=stdio_config.args,
        )

    return transport, transport_type


def _auto_detect(
    http_config: "HttpTransportConfig | None",
    stdio_config: "StdioTransportConfig | None",
) -> Literal["streamablehttp", "stdio"]:
    """Auto-detect transport based on available configs.

    Priority: HTTP (if reachable) > STDIO > error.

    Args:
        http_config: HTTP transport config, or None if not configured.
        stdio_config: STDIO transport config, or None if not configured.

    Returns:
        Transport type to use ("streamablehttp" or "stdio").

    Raises:
        ValueError: If neither transport is configured.
        TimeoutError: If HTTP-only and connection times out.
        ConnectionError: If HTTP-only and server unreachable.
    """
    has_http = http_config is not None
    has_stdio = stdio_config is not None

    if has_http and has_stdio:
        # Both available - try HTTP, fall back to STDIO
        try:
            check_http_health(http_config.url, min(http_config.timeout, HEALTH_CHECK_TIMEOUT_SECONDS))
            return "streamablehttp"
        except (TimeoutError, ConnectionError):
            return "stdio"

    if has_http:
        # HTTP only - must be reachable
        check_http_health(http_config.url, min(http_config.timeout, HEALTH_CHECK_TIMEOUT_SECONDS))
        return "streamablehttp"

    if has_stdio:
        return "stdio"

    raise ValueError("No transport configured. Run 'mcp-acp-extended init' to configure a backend server.")


async def _check_async(url: str, timeout: float) -> None:
    """Test HTTP endpoint connectivity (async implementation).

    Creates a temporary MCP client connection to verify the endpoint
    responds to the MCP initialize handshake.

    Args:
        url: Backend URL to test.
        timeout: Connection timeout in seconds.

    Raises:
        TimeoutError: If connection times out.
        ConnectionError: If connection fails for any reason.
    """
    transport = StreamableHttpTransport(url=url)
    client = ProxyClient(transport)

    try:
        async with asyncio.timeout(timeout):
            async with client:
                pass
    except asyncio.TimeoutError as e:
        raise TimeoutError(f"Connection to {url} timed out after {timeout}s") from e
    except ConnectionRefusedError as e:
        raise ConnectionError(f"Connection refused by {url}") from e
    except TRANSPORT_ERRORS as e:
        # Known transport/network errors (httpx, connection issues, etc.)
        raise ConnectionError(f"Failed to connect to {url}: {type(e).__name__}: {e}") from e
    except RuntimeError as e:
        # fastmcp wraps transport errors in RuntimeError
        raise ConnectionError(f"Failed to connect to {url}") from e
    except OSError as e:
        # General OS-level network errors (socket errors, DNS failures, etc.)
        raise ConnectionError(f"Failed to connect to {url}: {type(e).__name__}: {e}") from e
