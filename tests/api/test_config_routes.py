"""Unit tests for config API routes.

Tests the configuration management endpoints.
Uses AAA pattern (Arrange-Act-Assert) for clarity.
"""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from mcp_acp_extended.api.routes.config import _build_config_response, router
from mcp_acp_extended.api.schemas import (
    AuthConfigResponse,
    BackendConfigResponse,
    ConfigResponse,
    ConfigUpdateRequest,
    LoggingConfigResponse,
    LoggingConfigUpdate,
    ProxyConfigResponse,
)


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def mock_config():
    """Create a mock AppConfig with auth."""
    config = MagicMock()
    config.backend.server_name = "test-server"
    config.backend.transport = "stdio"
    config.logging.log_dir = "/tmp/logs"
    config.logging.log_level = "INFO"
    config.logging.include_payloads = False
    config.proxy.name = "test-proxy"

    # Auth config with OIDC
    config.auth = MagicMock()
    config.auth.oidc = MagicMock()
    config.auth.oidc.issuer = "https://auth.example.com"
    config.auth.mtls = None

    return config


@pytest.fixture
def mock_config_no_auth():
    """Create a mock AppConfig without auth."""
    config = MagicMock()
    config.backend.server_name = "test-server"
    config.backend.transport = "stdio"
    config.logging.log_dir = "/tmp/logs"
    config.logging.log_level = "INFO"
    config.logging.include_payloads = False
    config.proxy.name = "test-proxy"
    config.auth = None
    return config


@pytest.fixture
def app(mock_config):
    """Create a test FastAPI app with config router and mocked state."""
    app = FastAPI()
    app.include_router(router, prefix="/api/config")
    # Set app.state.config for dependency injection
    app.state.config = mock_config
    return app


@pytest.fixture
def client(app):
    """Create a test client."""
    return TestClient(app)


# =============================================================================
# Tests: GET /api/config
# =============================================================================


class TestGetConfig:
    """Tests for GET /api/config endpoint."""

    def test_returns_config_with_auth(self, client, mock_config):
        """Given config with auth, returns redacted config."""
        # Arrange
        with patch(
            "mcp_acp_extended.api.routes.config.get_config_path",
            return_value=Path("/config/app.json"),
        ):
            # Act
            response = client.get("/api/config")

        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["backend"]["server_name"] == "test-server"
        assert data["logging"]["log_dir"] == "/tmp/logs"
        assert data["auth"]["oidc_issuer"] == "https://auth.example.com"
        assert data["auth"]["has_mtls"] is False
        assert data["requires_restart_for_changes"] is True

    def test_returns_config_without_auth(self, mock_config_no_auth):
        """Given config without auth, returns null auth."""
        # Arrange
        app = FastAPI()
        app.include_router(router, prefix="/api/config")
        app.state.config = mock_config_no_auth
        client = TestClient(app)

        with patch(
            "mcp_acp_extended.api.routes.config.get_config_path",
            return_value=Path("/config/app.json"),
        ):
            # Act
            response = client.get("/api/config")

        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["auth"] is None

    def test_redacts_sensitive_fields(self, client, mock_config):
        """Config response does not include client_id, secrets, etc."""
        # Arrange
        with patch(
            "mcp_acp_extended.api.routes.config.get_config_path",
            return_value=Path("/config/app.json"),
        ):
            # Act
            response = client.get("/api/config")

        # Assert
        data = response.json()
        # Auth should only have oidc_issuer and has_mtls, not secrets
        assert "client_id" not in data.get("auth", {})
        assert "client_secret" not in data.get("auth", {})


# =============================================================================
# Tests: PUT /api/config
# =============================================================================


class TestUpdateConfig:
    """Tests for PUT /api/config endpoint."""

    def test_updates_logging_config(self, client, tmp_path):
        """Given logging updates, saves and returns updated config."""
        # Arrange
        mock_config = MagicMock()
        mock_config.model_dump.return_value = {
            "backend": {"server_name": "test", "transport": "stdio"},
            "logging": {"log_dir": "/tmp/logs", "log_level": "INFO", "include_payloads": False},
            "proxy": {"name": "test"},
            "auth": None,
        }
        mock_config.save_to_file = MagicMock()

        # Configure new_config mock for response building
        new_config = MagicMock()
        new_config.backend.server_name = "test"
        new_config.backend.transport = "stdio"
        new_config.logging.log_dir = "/tmp/logs"
        new_config.logging.log_level = "DEBUG"
        new_config.logging.include_payloads = True
        new_config.proxy.name = "test"
        new_config.auth = None
        new_config.save_to_file = MagicMock()

        config_path = tmp_path / "config.json"

        with patch("mcp_acp_extended.config.AppConfig.load_from_files", return_value=mock_config):
            with patch("mcp_acp_extended.config.AppConfig.model_validate", return_value=new_config):
                with patch(
                    "mcp_acp_extended.api.routes.config.get_config_path",
                    return_value=config_path,
                ):
                    # Act
                    response = client.put(
                        "/api/config",
                        json={"logging": {"log_level": "DEBUG", "include_payloads": True}},
                    )

        # Assert
        assert response.status_code == 200
        data = response.json()
        assert "Restart proxy" in data["message"]

    def test_returns_404_when_config_missing(self, client, tmp_path):
        """Given missing config file, returns 404."""
        # Arrange
        with patch(
            "mcp_acp_extended.config.AppConfig.load_from_files",
            side_effect=FileNotFoundError,
        ):
            with patch(
                "mcp_acp_extended.api.routes.config.get_config_path",
                return_value=tmp_path / "missing.json",
            ):
                # Act
                response = client.put("/api/config", json={"logging": {"log_level": "DEBUG"}})

        # Assert
        assert response.status_code == 404

    def test_empty_update_is_valid(self, client, tmp_path):
        """Given empty update, returns current config."""
        # Arrange
        mock_config = MagicMock()
        mock_config.model_dump.return_value = {
            "backend": {"server_name": "test", "transport": "stdio"},
            "logging": {"log_dir": "/tmp", "log_level": "INFO", "include_payloads": False},
            "proxy": {"name": "test"},
        }
        mock_config.save_to_file = MagicMock()
        mock_config.backend.server_name = "test"
        mock_config.backend.transport = "stdio"
        mock_config.logging.log_dir = "/tmp"
        mock_config.logging.log_level = "INFO"
        mock_config.logging.include_payloads = False
        mock_config.proxy.name = "test"
        mock_config.auth = None

        with patch("mcp_acp_extended.config.AppConfig.load_from_files", return_value=mock_config):
            with patch("mcp_acp_extended.config.AppConfig.model_validate", return_value=mock_config):
                with patch(
                    "mcp_acp_extended.api.routes.config.get_config_path",
                    return_value=tmp_path / "config.json",
                ):
                    # Act
                    response = client.put("/api/config", json={})

        # Assert
        assert response.status_code == 200


# =============================================================================
# Tests: Helper Functions
# =============================================================================


class TestBuildConfigResponse:
    """Tests for _build_config_response helper."""

    def test_builds_response_with_auth(self, mock_config):
        """Given config with auth, builds complete response."""
        # Arrange
        with patch(
            "mcp_acp_extended.api.routes.config.get_config_path",
            return_value=Path("/test/config.json"),
        ):
            # Act
            response = _build_config_response(mock_config)

        # Assert
        assert isinstance(response, ConfigResponse)
        assert response.backend.server_name == "test-server"
        assert response.logging.log_level == "INFO"
        assert response.auth is not None
        assert response.auth.oidc_issuer == "https://auth.example.com"
        assert response.config_path == "/test/config.json"

    def test_builds_response_without_auth(self, mock_config_no_auth):
        """Given config without auth, builds response with null auth."""
        # Arrange
        with patch(
            "mcp_acp_extended.api.routes.config.get_config_path",
            return_value=Path("/test/config.json"),
        ):
            # Act
            response = _build_config_response(mock_config_no_auth)

        # Assert
        assert response.auth is None

    def test_detects_mtls_presence(self, mock_config):
        """Given config with mTLS, sets has_mtls to True."""
        # Arrange
        mock_config.auth.mtls = MagicMock()  # mTLS present

        with patch(
            "mcp_acp_extended.api.routes.config.get_config_path",
            return_value=Path("/test/config.json"),
        ):
            # Act
            response = _build_config_response(mock_config)

        # Assert
        assert response.auth.has_mtls is True


# =============================================================================
# Tests: Response Models
# =============================================================================


class TestResponseModels:
    """Tests for response model serialization."""

    def test_backend_config_response(self):
        """BackendConfigResponse serializes correctly."""
        # Act
        response = BackendConfigResponse(
            server_name="test-server",
            transport="stdio",
        )
        data = response.model_dump()

        # Assert
        assert data["server_name"] == "test-server"
        assert data["transport"] == "stdio"

    def test_logging_config_response(self):
        """LoggingConfigResponse serializes correctly."""
        # Act
        response = LoggingConfigResponse(
            log_dir="/var/log",
            log_level="DEBUG",
            include_payloads=True,
        )
        data = response.model_dump()

        # Assert
        assert data["log_dir"] == "/var/log"
        assert data["include_payloads"] is True

    def test_auth_config_response(self):
        """AuthConfigResponse serializes correctly."""
        # Act
        response = AuthConfigResponse(
            oidc_issuer="https://auth.example.com",
            has_mtls=False,
        )
        data = response.model_dump()

        # Assert
        assert data["oidc_issuer"] == "https://auth.example.com"
        assert data["has_mtls"] is False

    def test_proxy_config_response(self):
        """ProxyConfigResponse serializes correctly."""
        # Act
        response = ProxyConfigResponse(name="my-proxy")
        data = response.model_dump()

        # Assert
        assert data["name"] == "my-proxy"


# =============================================================================
# Tests: Update Models
# =============================================================================


class TestUpdateModels:
    """Tests for update model validation."""

    def test_logging_update_partial(self):
        """LoggingConfigUpdate allows partial updates."""
        # Act
        update = LoggingConfigUpdate(log_level="DEBUG")

        # Assert
        assert update.log_level == "DEBUG"
        assert update.log_dir is None
        assert update.include_payloads is None

    def test_config_update_request_empty(self):
        """ConfigUpdateRequest allows empty update."""
        # Act
        update = ConfigUpdateRequest()

        # Assert
        assert update.logging is None
        assert update.backend is None
        assert update.proxy is None

    def test_config_update_request_with_logging(self):
        """ConfigUpdateRequest with logging updates."""
        # Act
        update = ConfigUpdateRequest(logging=LoggingConfigUpdate(log_level="DEBUG", include_payloads=True))

        # Assert
        assert update.logging is not None
        assert update.logging.log_level == "DEBUG"
