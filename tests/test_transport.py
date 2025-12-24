"""Tests for transport utilities.

Tests use the AAA pattern (Arrange-Act-Assert) for clarity.
"""

from unittest.mock import patch

import pytest
from fastmcp.client.transports import StdioTransport, StreamableHttpTransport

from mcp_acp_extended.config import BackendConfig, HttpTransportConfig, StdioTransportConfig
from mcp_acp_extended.utils.transport import create_backend_transport


# --- Fixtures ---


@pytest.fixture
def stdio_config() -> StdioTransportConfig:
    return StdioTransportConfig(command="echo", args=["hello"])


@pytest.fixture
def http_config() -> HttpTransportConfig:
    return HttpTransportConfig(url="http://localhost:3000/mcp")


@pytest.fixture
def backend_stdio_only(stdio_config: StdioTransportConfig) -> BackendConfig:
    return BackendConfig(server_name="test", transport=None, stdio=stdio_config)


@pytest.fixture
def backend_http_only(http_config: HttpTransportConfig) -> BackendConfig:
    return BackendConfig(server_name="test", transport=None, http=http_config)


@pytest.fixture
def backend_both(stdio_config: StdioTransportConfig, http_config: HttpTransportConfig) -> BackendConfig:
    return BackendConfig(server_name="test", transport=None, stdio=stdio_config, http=http_config)


# --- Explicit Transport Selection ---


class TestExplicitTransport:
    """Tests for explicit transport selection."""

    def test_explicit_stdio_returns_stdio(self, stdio_config: StdioTransportConfig):
        # Arrange
        config = BackendConfig(server_name="test", transport="stdio", stdio=stdio_config)

        # Act
        transport, transport_type = create_backend_transport(config)

        # Assert
        assert isinstance(transport, StdioTransport)
        assert transport_type == "stdio"

    def test_explicit_stdio_without_config_raises(self):
        # Arrange
        config = BackendConfig(server_name="test", transport="stdio", stdio=None)

        # Act & Assert
        with pytest.raises(ValueError, match="stdio configuration is missing"):
            create_backend_transport(config)

    def test_explicit_http_returns_http_when_reachable(self, http_config: HttpTransportConfig):
        # Arrange
        config = BackendConfig(server_name="test", transport="streamablehttp", http=http_config)

        # Act
        with patch("mcp_acp_extended.utils.transport.check_http_health"):
            transport, transport_type = create_backend_transport(config)

        # Assert
        assert isinstance(transport, StreamableHttpTransport)
        assert transport_type == "streamablehttp"

    def test_explicit_http_without_config_raises(self):
        # Arrange
        config = BackendConfig(server_name="test", transport="streamablehttp", http=None)

        # Act & Assert
        with pytest.raises(ValueError, match="http configuration is missing"):
            create_backend_transport(config)

    def test_explicit_http_raises_when_unreachable(self, http_config: HttpTransportConfig):
        # Arrange
        config = BackendConfig(server_name="test", transport="streamablehttp", http=http_config)

        # Act & Assert
        with patch(
            "mcp_acp_extended.utils.transport.check_http_health",
            side_effect=ConnectionError("refused"),
        ):
            with pytest.raises(ConnectionError):
                create_backend_transport(config)

    def test_explicit_http_raises_on_timeout(self, http_config: HttpTransportConfig):
        """Explicit HTTP selection fails on timeout (no fallback)."""
        # Arrange
        config = BackendConfig(server_name="test", transport="streamablehttp", http=http_config)

        # Act & Assert
        with patch(
            "mcp_acp_extended.utils.transport.check_http_health",
            side_effect=TimeoutError("timed out"),
        ):
            with pytest.raises(TimeoutError):
                create_backend_transport(config)


# --- Auto-detect Transport ---


class TestAutoDetect:
    """Tests for auto-detect transport selection."""

    def test_stdio_only_returns_stdio(self, backend_stdio_only: BackendConfig):
        # Act
        transport, transport_type = create_backend_transport(backend_stdio_only)

        # Assert
        assert isinstance(transport, StdioTransport)
        assert transport_type == "stdio"

    def test_http_only_returns_http_when_reachable(self, backend_http_only: BackendConfig):
        # Act
        with patch("mcp_acp_extended.utils.transport.check_http_health"):
            transport, transport_type = create_backend_transport(backend_http_only)

        # Assert
        assert isinstance(transport, StreamableHttpTransport)
        assert transport_type == "streamablehttp"

    def test_http_only_raises_when_unreachable(self, backend_http_only: BackendConfig):
        # Act & Assert
        with patch(
            "mcp_acp_extended.utils.transport.check_http_health",
            side_effect=ConnectionError("refused"),
        ):
            with pytest.raises(ConnectionError):
                create_backend_transport(backend_http_only)

    def test_http_only_raises_on_timeout(self, backend_http_only: BackendConfig):
        # Act & Assert
        with patch(
            "mcp_acp_extended.utils.transport.check_http_health",
            side_effect=TimeoutError("timed out"),
        ):
            with pytest.raises(TimeoutError):
                create_backend_transport(backend_http_only)

    def test_both_prefers_http_when_reachable(self, backend_both: BackendConfig):
        # Act
        with patch("mcp_acp_extended.utils.transport.check_http_health"):
            transport, transport_type = create_backend_transport(backend_both)

        # Assert
        assert isinstance(transport, StreamableHttpTransport)
        assert transport_type == "streamablehttp"

    def test_both_falls_back_to_stdio_when_http_unreachable(self, backend_both: BackendConfig):
        # Act
        with patch(
            "mcp_acp_extended.utils.transport.check_http_health",
            side_effect=ConnectionError("refused"),
        ):
            transport, transport_type = create_backend_transport(backend_both)

        # Assert
        assert isinstance(transport, StdioTransport)
        assert transport_type == "stdio"

    def test_neither_configured_raises(self):
        # Arrange
        config = BackendConfig(server_name="test", transport=None)

        # Act & Assert
        with pytest.raises(ValueError, match="No transport configured"):
            create_backend_transport(config)

    def test_both_falls_back_to_stdio_on_timeout(self, backend_both: BackendConfig):
        """Auto-detect falls back to STDIO when HTTP times out."""
        # Act
        with patch(
            "mcp_acp_extended.utils.transport.check_http_health",
            side_effect=TimeoutError("timed out"),
        ):
            transport, transport_type = create_backend_transport(backend_both)

        # Assert
        assert isinstance(transport, StdioTransport)
        assert transport_type == "stdio"


# --- Transport Creation ---


class TestTransportCreation:
    """Tests for transport object creation."""

    def test_stdio_transport_has_correct_command(self, stdio_config: StdioTransportConfig):
        # Arrange
        config = BackendConfig(server_name="test", transport="stdio", stdio=stdio_config)

        # Act
        transport, _ = create_backend_transport(config)

        # Assert
        assert transport.command == "echo"
        assert transport.args == ["hello"]

    def test_http_transport_has_correct_url(self, http_config: HttpTransportConfig):
        # Arrange
        config = BackendConfig(server_name="test", transport="streamablehttp", http=http_config)

        # Act
        with patch("mcp_acp_extended.utils.transport.check_http_health"):
            transport, _ = create_backend_transport(config)

        # Assert
        assert transport.url == "http://localhost:3000/mcp"
