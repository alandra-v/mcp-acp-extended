"""Transport utilities for backend connection.

Handles transport selection, health checks, and creation.
Supports STDIO (local process) and Streamable HTTP (remote URL) transports.
Includes mTLS support for secure proxy-to-backend authentication.
"""

import asyncio
import logging
import ssl
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Literal

import httpx
from cryptography import x509
from fastmcp.client.transports import ClientTransport, StdioTransport, StreamableHttpTransport
from fastmcp.server.proxy import ProxyClient

from mcp_acp_extended.constants import (
    CERT_EXPIRY_CRITICAL_DAYS,
    CERT_EXPIRY_WARNING_DAYS,
    HEALTH_CHECK_TIMEOUT_SECONDS,
    TRANSPORT_ERRORS,
)

if TYPE_CHECKING:
    from mcp.shared._httpx_utils import McpHttpClientFactory

    from mcp_acp_extended.config import BackendConfig, HttpTransportConfig, MTLSConfig, StdioTransportConfig

logger = logging.getLogger(__name__)


# =============================================================================
# mTLS Support
# =============================================================================


def create_mtls_client_factory(
    mtls_config: "MTLSConfig",
) -> "McpHttpClientFactory":
    """Create an httpx client factory with mTLS certificates.

    The returned factory creates httpx.AsyncClient instances configured with
    client certificates for mutual TLS authentication to backend servers.

    Args:
        mtls_config: mTLS configuration with certificate paths.

    Returns:
        Factory callable that creates configured httpx.AsyncClient instances.

    Raises:
        FileNotFoundError: If any certificate file doesn't exist.
        ValueError: If certificates are invalid PEM format.
    """
    # Resolve and validate paths
    cert_path = Path(mtls_config.client_cert_path).expanduser().resolve()
    key_path = Path(mtls_config.client_key_path).expanduser().resolve()
    ca_path = Path(mtls_config.ca_bundle_path).expanduser().resolve()

    # Check files exist
    if not cert_path.exists():
        raise FileNotFoundError(f"mTLS client certificate not found: {cert_path}")
    if not key_path.exists():
        raise FileNotFoundError(f"mTLS client key not found: {key_path}")
    if not ca_path.exists():
        raise FileNotFoundError(f"mTLS CA bundle not found: {ca_path}")

    # Validate certificates are valid PEM format
    _validate_certificates(cert_path, key_path, ca_path)

    def factory(
        headers: dict[str, str] | None = None,
        timeout: httpx.Timeout | None = None,
        auth: httpx.Auth | None = None,
    ) -> httpx.AsyncClient:
        """Create httpx client with mTLS certificates.

        This signature matches McpHttpClientFactory Protocol from mcp.shared._httpx_utils.

        Args:
            headers: Optional headers to pass to the client.
            timeout: Optional timeout configuration.
            auth: Optional httpx auth handler.

        Returns:
            Configured httpx.AsyncClient with mTLS certificates.
        """
        # Create SSL context with CA bundle for server verification
        ssl_context = ssl.create_default_context(cafile=str(ca_path))
        # Load client certificate and key for mTLS
        ssl_context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))

        return httpx.AsyncClient(
            verify=ssl_context,
            headers=headers,
            timeout=timeout,
            auth=auth,
        )

    return factory


def _validate_certificates(cert_path: Path, key_path: Path, ca_path: Path) -> None:
    """Validate certificate files are valid PEM format.

    Creates an SSL context to verify the certificates can be loaded together.
    Also checks certificate expiry and logs warnings if expiring soon.

    Args:
        cert_path: Path to client certificate.
        key_path: Path to client private key.
        ca_path: Path to CA bundle.

    Raises:
        ValueError: If certificates are invalid or don't match.
    """
    try:
        ctx = ssl.create_default_context()
        ctx.load_cert_chain(str(cert_path), str(key_path))
        ctx.load_verify_locations(str(ca_path))
    except ssl.SSLError as e:
        raise ValueError(f"Invalid mTLS certificates: {e}") from e

    # Check certificate expiry
    _check_certificate_expiry(cert_path)


def _check_certificate_expiry(cert_path: Path) -> int | None:
    """Check if certificate is expired or expiring soon.

    Logs a warning if certificate expires within CERT_EXPIRY_WARNING_DAYS.
    Logs a critical warning if expires within CERT_EXPIRY_CRITICAL_DAYS.
    Raises an error if certificate is already expired.

    Args:
        cert_path: Path to certificate file.

    Returns:
        Days until expiry, or None if could not determine.

    Raises:
        ValueError: If certificate is already expired.
    """
    try:
        cert_pem = cert_path.read_bytes()
        cert = x509.load_pem_x509_certificate(cert_pem)

        now = datetime.now(timezone.utc)
        expires_at = cert.not_valid_after_utc
        days_until_expiry = (expires_at - now).days

        if days_until_expiry < 0:
            raise ValueError(
                f"mTLS client certificate has expired (expired {-days_until_expiry} days ago). "
                f"Certificate: {cert_path}"
            )

        if days_until_expiry <= CERT_EXPIRY_CRITICAL_DAYS:
            logger.critical(
                "CRITICAL: mTLS client certificate expires in %d days (on %s). "
                "Renew immediately! Certificate: %s",
                days_until_expiry,
                expires_at.strftime("%Y-%m-%d"),
                cert_path,
            )
        elif days_until_expiry <= CERT_EXPIRY_WARNING_DAYS:
            logger.warning(
                "mTLS client certificate expires in %d days (on %s). "
                "Consider renewing soon. Certificate: %s",
                days_until_expiry,
                expires_at.strftime("%Y-%m-%d"),
                cert_path,
            )

        return days_until_expiry
    except ValueError:
        # Re-raise ValueError (our expiry errors)
        raise
    except Exception as e:
        # Log but don't fail for other parsing errors - SSL validation already passed
        logger.warning("Could not check certificate expiry for %s: %s", cert_path, e)
        return None


def get_certificate_expiry_info(cert_path: str | Path) -> dict[str, str | int | None]:
    """Get certificate expiry information for display.

    Args:
        cert_path: Path to certificate file.

    Returns:
        Dictionary with expiry info:
        - expires_at: ISO format expiry date
        - days_until_expiry: Days remaining (negative if expired)
        - status: "valid", "warning", "critical", or "expired"
        - error: Error message if parsing failed
    """
    path = Path(cert_path).expanduser().resolve()

    if not path.exists():
        return {"error": f"Certificate not found: {path}"}

    try:
        cert_pem = path.read_bytes()
        cert = x509.load_pem_x509_certificate(cert_pem)

        now = datetime.now(timezone.utc)
        expires_at = cert.not_valid_after_utc
        days_until_expiry = (expires_at - now).days

        if days_until_expiry < 0:
            status = "expired"
        elif days_until_expiry <= CERT_EXPIRY_CRITICAL_DAYS:
            status = "critical"
        elif days_until_expiry <= CERT_EXPIRY_WARNING_DAYS:
            status = "warning"
        else:
            status = "valid"

        return {
            "expires_at": expires_at.isoformat(),
            "days_until_expiry": days_until_expiry,
            "status": status,
        }
    except Exception as e:
        return {"error": str(e)}


def validate_mtls_config(
    cert_path: str,
    key_path: str,
    ca_path: str,
) -> list[str]:
    """Validate mTLS certificate files for user feedback.

    Checks that all files exist, are valid PEM format, and the cert/key match.
    Returns a list of error messages (empty if valid).

    This is designed for use during interactive init to give users helpful feedback.

    Args:
        cert_path: Path to client certificate.
        key_path: Path to client private key.
        ca_path: Path to CA bundle.

    Returns:
        List of error messages. Empty list means all files are valid.
    """
    errors: list[str] = []

    # Resolve paths
    cert = Path(cert_path).expanduser().resolve()
    key = Path(key_path).expanduser().resolve()
    ca = Path(ca_path).expanduser().resolve()

    # Check files exist
    if not cert.exists():
        errors.append(f"Client certificate not found: {cert}")
    if not key.exists():
        errors.append(f"Client private key not found: {key}")
    if not ca.exists():
        errors.append(f"CA bundle not found: {ca}")

    # If any files missing, return early
    if errors:
        return errors

    # Validate PEM format and cert/key match
    try:
        _validate_certificates(cert, key, ca)
    except ValueError as e:
        errors.append(str(e))
        return errors

    # Check expiry
    expiry_info = get_certificate_expiry_info(cert)
    if "error" in expiry_info:
        errors.append(f"Could not check certificate expiry: {expiry_info['error']}")
    elif expiry_info.get("status") == "expired":
        days_value = expiry_info.get("days_until_expiry", 0)
        days = abs(int(days_value)) if days_value is not None else 0
        errors.append(f"Certificate has expired ({days} days ago)")

    return errors


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
            check_http_health(
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

    Priority: HTTP (if reachable) > STDIO > error.

    Args:
        http_config: HTTP transport config, or None if not configured.
        stdio_config: STDIO transport config, or None if not configured.
        mtls_config: Optional mTLS configuration for client certificate auth.

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
            check_http_health(
                http_config.url, min(http_config.timeout, HEALTH_CHECK_TIMEOUT_SECONDS), mtls_config
            )
            return "streamablehttp"
        except (TimeoutError, ConnectionError):
            return "stdio"

    if has_http:
        # HTTP only - must be reachable
        check_http_health(
            http_config.url, min(http_config.timeout, HEALTH_CHECK_TIMEOUT_SECONDS), mtls_config
        )
        return "streamablehttp"

    if has_stdio:
        return "stdio"

    raise ValueError("No transport configured. Run 'mcp-acp-extended init' to configure a backend server.")


class SSLCertificateError(ConnectionError):
    """SSL certificate validation failed (wrong CA, expired server cert, etc.)."""

    pass


class SSLHandshakeError(ConnectionError):
    """SSL/TLS handshake failed (client cert rejected, protocol mismatch, etc.)."""

    pass


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
