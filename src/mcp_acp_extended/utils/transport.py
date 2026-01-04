"""Transport utilities for backend connection.

Handles transport selection, health checks, and creation.
Supports STDIO (local process) and Streamable HTTP (remote URL) transports.
Includes mTLS support for secure proxy-to-backend authentication.
"""

import asyncio
import logging
import ssl
import time
from typing import TYPE_CHECKING, Literal

from fastmcp.client.transports import ClientTransport, StdioTransport, StreamableHttpTransport
from fastmcp.server.proxy import ProxyClient

from mcp_acp_extended.constants import (
    BACKEND_RETRY_BACKOFF_MULTIPLIER,
    BACKEND_RETRY_INITIAL_DELAY,
    BACKEND_RETRY_MAX_ATTEMPTS,
    HEALTH_CHECK_TIMEOUT_SECONDS,
    TRANSPORT_ERRORS,
)
from mcp_acp_extended.security.mtls import (
    SSLCertificateError,
    SSLHandshakeError,
    _check_certificate_expiry,
    _validate_certificates,
    create_mtls_client_factory,
    get_certificate_expiry_info,
    validate_mtls_config,
)

if TYPE_CHECKING:
    from mcp_acp_extended.config import BackendConfig, HttpTransportConfig, MTLSConfig, StdioTransportConfig

logger = logging.getLogger(__name__)

# Re-export mTLS functions for backwards compatibility
__all__ = [
    "SSLCertificateError",
    "SSLHandshakeError",
    "_check_certificate_expiry",
    "_validate_certificates",
    "check_http_health",
    "check_http_health_with_retry",
    "create_backend_transport",
    "create_mtls_client_factory",
    "get_certificate_expiry_info",
    "validate_mtls_config",
]


# =============================================================================
# Health Checks
# =============================================================================


def check_http_health(
    url: str,
    timeout: float = HEALTH_CHECK_TIMEOUT_SECONDS,
    mtls_config: "MTLSConfig | None" = None,
) -> None:
    """Check if an HTTP endpoint is reachable.

    Tests connectivity by attempting an MCP initialize handshake.

    Args:
        url: The backend URL to test.
        timeout: Connection timeout in seconds (default: HEALTH_CHECK_TIMEOUT_SECONDS).
        mtls_config: Optional mTLS configuration for client certificate auth.

    Raises:
        TimeoutError: If connection times out.
        ConnectionError: If connection fails.
        FileNotFoundError: If mTLS certificate files don't exist.
        ValueError: If mTLS certificates are invalid.
    """
    try:
        asyncio.get_running_loop()
        in_async_context = True
    except RuntimeError:
        in_async_context = False

    if in_async_context:
        import concurrent.futures

        with concurrent.futures.ThreadPoolExecutor() as executor:
            future = executor.submit(asyncio.run, _check_async(url, timeout, mtls_config))
            future.result()
    else:
        asyncio.run(_check_async(url, timeout, mtls_config))


def check_http_health_with_retry(
    url: str,
    timeout: float = HEALTH_CHECK_TIMEOUT_SECONDS,
    mtls_config: "MTLSConfig | None" = None,
    max_attempts: int = BACKEND_RETRY_MAX_ATTEMPTS,
) -> None:
    """Check HTTP endpoint with retry and exponential backoff.

    Retries connection attempts with exponential backoff until the backend
    is reachable or max_attempts is exceeded. Used at startup to wait for
    backends that may start after the proxy.

    SSL-specific errors (SSLCertificateError, SSLHandshakeError) are NOT retried
    as they indicate configuration issues that won't resolve on their own.

    Args:
        url: The backend URL to test.
        timeout: Per-attempt connection timeout (default: HEALTH_CHECK_TIMEOUT_SECONDS).
        mtls_config: Optional mTLS configuration for client certificate auth.
        max_attempts: Maximum connection attempts (default: 3).

    Raises:
        TimeoutError: If backend not reachable after max_attempts.
        SSLCertificateError: If SSL certificate validation fails.
        SSLHandshakeError: If SSL handshake fails (e.g., client cert required).
        ConnectionError: If connection fails for non-retryable reasons.
        FileNotFoundError: If mTLS certificate files don't exist.
        ValueError: If mTLS certificates are invalid.
    """
    delay = BACKEND_RETRY_INITIAL_DELAY
    last_error: Exception | None = None
    is_https = url.lower().startswith("https://")

    for attempt in range(1, max_attempts + 1):
        try:
            check_http_health(url, timeout, mtls_config)
            # Success - backend is up
            if attempt > 1:
                logger.warning(f"Backend connected on attempt {attempt}: {url}")
            return
        except (SSLCertificateError, SSLHandshakeError) as e:
            # SSL errors are not retryable - fail immediately with clear message
            raise
        except (TimeoutError, ConnectionError) as e:
            last_error = e

            if attempt >= max_attempts:
                # No more retries - provide context-aware error message
                if is_https and mtls_config is None:
                    # HTTPS without mTLS configured - likely requires client cert
                    raise ConnectionError(
                        f"SSL/TLS connection failed: {url}. "
                        "The server may require mTLS (client certificate authentication). "
                        "Configure mTLS in your config or run 'mcp-acp-extended init'."
                    ) from e
                raise TimeoutError(f"Backend not reachable after {max_attempts} attempts: {url}") from e

            # Log retry attempt
            logger.warning(
                f"Waiting for backend at {url} (attempt {attempt}/{max_attempts}, retrying in {delay:.0f}s)..."
            )
            time.sleep(delay)

            # Exponential backoff
            delay = delay * BACKEND_RETRY_BACKOFF_MULTIPLIER


def create_backend_transport(
    backend_config: "BackendConfig",
    mtls_config: "MTLSConfig | None" = None,
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
        mtls_config: Optional mTLS configuration for client certificate auth.

    Returns:
        Tuple of (transport_instance, transport_type).

    Raises:
        ValueError: If no transport configured or config missing.
        TimeoutError: If HTTP backend times out.
        ConnectionError: If HTTP backend unreachable.
        FileNotFoundError: If mTLS certificate files don't exist.
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
            # Use retry loop - wait for backend to become available
            check_http_health_with_retry(
                http_config.url, min(http_config.timeout, HEALTH_CHECK_TIMEOUT_SECONDS), mtls_config
            )
        elif explicit_transport == "stdio" and stdio_config is None:
            raise ValueError(
                "STDIO transport selected but stdio configuration is missing. "
                "Run 'mcp-acp-extended init' to configure the backend command."
            )
        transport_type = explicit_transport
    else:
        # Auto-detect
        transport_type = _auto_detect(http_config, stdio_config, mtls_config)

    # Create transport
    if transport_type == "streamablehttp":
        if http_config is None:
            raise ValueError(
                "Internal error: HTTP transport selected but http_config is None. "
                "This indicates a bug in transport selection logic."
            )
        # Create mTLS client factory if configured AND URL is https://
        # mTLS only applies to HTTPS connections
        httpx_client_factory = None
        if mtls_config is not None and http_config.url.lower().startswith("https://"):
            httpx_client_factory = create_mtls_client_factory(mtls_config)

        transport: ClientTransport = StreamableHttpTransport(
            url=http_config.url,
            httpx_client_factory=httpx_client_factory,
        )
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
    mtls_config: "MTLSConfig | None" = None,
) -> Literal["streamablehttp", "stdio"]:
    """Auto-detect transport based on available configs.

    Priority: HTTP (if reachable after retry) > STDIO > error.

    Uses retry loop with exponential backoff (up to 30s) before falling back
    to STDIO or failing. This allows the proxy to start before the backend.

    Args:
        http_config: HTTP transport config, or None if not configured.
        stdio_config: STDIO transport config, or None if not configured.
        mtls_config: Optional mTLS configuration for client certificate auth.

    Returns:
        Transport type to use ("streamablehttp" or "stdio").

    Raises:
        ValueError: If neither transport is configured.
        TimeoutError: If HTTP-only and connection times out after retries.
        ConnectionError: If HTTP-only and server unreachable after retries.
    """
    has_http = http_config is not None
    has_stdio = stdio_config is not None

    if has_http and has_stdio:
        # Both available - retry HTTP, fall back to STDIO on timeout
        try:
            check_http_health_with_retry(
                http_config.url, min(http_config.timeout, HEALTH_CHECK_TIMEOUT_SECONDS), mtls_config
            )
            return "streamablehttp"
        except (TimeoutError, ConnectionError):
            logger.warning(f"HTTP backend not available, falling back to STDIO")
            return "stdio"

    if has_http:
        # HTTP only - retry, then fail
        check_http_health_with_retry(
            http_config.url, min(http_config.timeout, HEALTH_CHECK_TIMEOUT_SECONDS), mtls_config
        )
        return "streamablehttp"

    if has_stdio:
        return "stdio"

    raise ValueError("No transport configured. Run 'mcp-acp-extended init' to configure a backend server.")


async def _check_async(
    url: str,
    timeout: float,
    mtls_config: "MTLSConfig | None" = None,
) -> None:
    """Test HTTP endpoint connectivity (async implementation).

    Creates a temporary MCP client connection to verify the endpoint
    responds to the MCP initialize handshake.

    Args:
        url: Backend URL to test.
        timeout: Connection timeout in seconds.
        mtls_config: Optional mTLS configuration for client certificate auth.

    Raises:
        TimeoutError: If connection times out.
        SSLCertificateError: If SSL certificate validation fails.
        SSLHandshakeError: If SSL handshake fails (e.g., client cert rejected).
        ConnectionError: If connection fails for other reasons.
        FileNotFoundError: If mTLS certificate files don't exist.
        ValueError: If mTLS certificates are invalid.
    """
    # Create mTLS client factory if configured AND URL is https://
    # mTLS only applies to HTTPS connections
    httpx_client_factory = None
    if mtls_config is not None and url.lower().startswith("https://"):
        httpx_client_factory = create_mtls_client_factory(mtls_config)

    transport = StreamableHttpTransport(url=url, httpx_client_factory=httpx_client_factory)
    client = ProxyClient(transport)

    try:
        async with asyncio.timeout(timeout):
            async with client:
                pass
    except asyncio.TimeoutError as e:
        raise TimeoutError(f"Connection to {url} timed out after {timeout}s") from e
    except ConnectionRefusedError as e:
        raise ConnectionError(f"Backend refused connection: {url}") from e
    except ssl.SSLCertVerificationError as e:
        # Server certificate validation failed
        raise SSLCertificateError(
            f"SSL certificate verification failed for {url}: {e}. " "Check your CA bundle configuration."
        ) from e
    except ssl.SSLError as e:
        # General SSL error - often client cert rejected or handshake failure
        error_msg = str(e).lower()
        if "certificate" in error_msg or "verify" in error_msg:
            raise SSLCertificateError(f"SSL certificate error for {url}: {e}") from e
        elif "handshake" in error_msg or "alert" in error_msg:
            raise SSLHandshakeError(
                f"SSL handshake failed for {url}: {e}. "
                "The server may have rejected your client certificate."
            ) from e
        else:
            raise SSLHandshakeError(f"SSL error connecting to {url}: {e}") from e
    except TRANSPORT_ERRORS as e:
        # Known transport/network errors (httpx, connection issues, etc.)
        error_str = str(e).lower()
        if "ssl" in error_str or "certificate" in error_str:
            raise SSLHandshakeError(f"SSL error connecting to {url}: {e}") from e
        raise ConnectionError(f"Backend unreachable: {url} ({type(e).__name__}: {e})") from e
    except RuntimeError as e:
        # fastmcp wraps transport errors in RuntimeError
        error_str = str(e).lower()
        if "ssl" in error_str or "certificate" in error_str:
            raise SSLHandshakeError(f"SSL error connecting to {url}: {e}") from e
        # Check for empty error on HTTPS - likely mTLS required but not configured
        if url.lower().startswith("https://") and (not error_str or "client failed to connect:" in error_str):
            if mtls_config is None:
                raise ConnectionError(
                    f"Backend connection failed: {url}. "
                    "The server may require mTLS (client certificate). "
                    "Configure mTLS in your config or run 'mcp-acp-extended init'."
                ) from e
            else:
                raise ConnectionError(
                    f"Backend connection failed: {url}. "
                    "Check that your mTLS certificates are valid and accepted by the server."
                ) from e
        raise ConnectionError(f"Backend connection failed: {url} ({e})") from e
    except OSError as e:
        # General OS-level network errors (socket errors, DNS failures, etc.)
        raise ConnectionError(f"Network error connecting to {url}: {type(e).__name__}: {e}") from e
