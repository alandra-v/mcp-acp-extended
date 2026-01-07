"""Unit tests for CLI API client.

Tests the HTTP client used by CLI commands to communicate with the proxy.
"""

import json
from unittest.mock import MagicMock, patch

import httpx
import pytest

from mcp_acp_extended.cli.api_client import (
    APIError,
    ProxyNotRunningError,
    api_request,
    get_api_connection,
)


class TestProxyNotRunningError:
    """Tests for ProxyNotRunningError exception."""

    def test_has_helpful_message(self):
        """Error message suggests how to start proxy."""
        error = ProxyNotRunningError()

        assert "not running" in str(error).lower()
        assert "start" in str(error).lower()

    def test_is_click_exception(self):
        """Exception inherits from ClickException."""
        import click

        error = ProxyNotRunningError()

        assert isinstance(error, click.ClickException)


class TestAPIError:
    """Tests for APIError exception."""

    def test_includes_status_code_in_message(self):
        """Error message includes status code."""
        error = APIError("Not found", status_code=404)

        assert "404" in str(error)
        assert "Not found" in str(error)

    def test_stores_status_code(self):
        """Status code is accessible as attribute."""
        error = APIError("Error", status_code=500)

        assert error.status_code == 500

    def test_without_status_code(self):
        """Works without status code."""
        error = APIError("Connection failed")

        assert error.status_code is None
        assert "Connection failed" in str(error)

    def test_is_click_exception(self):
        """Exception inherits from ClickException."""
        import click

        error = APIError("test")

        assert isinstance(error, click.ClickException)


class TestGetApiConnection:
    """Tests for get_api_connection function."""

    def test_returns_url_and_headers_from_manager_file(self, tmp_path):
        """Given valid manager.json, returns base URL and auth headers."""
        manager_data = {
            "port": 8765,
            "token": "test-token-123",
            "started_at": "2024-01-01T00:00:00",
        }

        with patch(
            "mcp_acp_extended.cli.api_client.read_manager_file",
            return_value=manager_data,
        ):
            base_url, headers = get_api_connection()

        assert base_url == "http://127.0.0.1:8765"
        assert headers["Authorization"] == "Bearer test-token-123"

    def test_raises_when_manager_file_missing(self):
        """Given no manager.json, raises ProxyNotRunningError."""
        with patch(
            "mcp_acp_extended.cli.api_client.read_manager_file",
            return_value=None,
        ):
            with pytest.raises(ProxyNotRunningError):
                get_api_connection()

    def test_uses_port_from_manager_file(self):
        """Uses port from manager.json, not hardcoded."""
        manager_data = {"port": 9999, "token": "token"}

        with patch(
            "mcp_acp_extended.cli.api_client.read_manager_file",
            return_value=manager_data,
        ):
            base_url, _ = get_api_connection()

        assert "9999" in base_url


class TestApiRequest:
    """Tests for api_request function."""

    @pytest.fixture
    def mock_manager(self):
        """Mock the manager file reader."""
        with patch(
            "mcp_acp_extended.cli.api_client.read_manager_file",
            return_value={"port": 8765, "token": "test-token"},
        ):
            yield

    def test_get_request_success(self, mock_manager):
        """Given successful GET request, returns parsed JSON."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"status": "ok", "data": [1, 2, 3]}

        with patch("httpx.Client") as mock_client:
            mock_client.return_value.__enter__.return_value.request.return_value = mock_response

            result = api_request("GET", "/api/test")

        assert result == {"status": "ok", "data": [1, 2, 3]}

    def test_post_request_with_json_body(self, mock_manager):
        """Given POST with JSON body, sends correct request."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"created": True}

        with patch("httpx.Client") as mock_client:
            client_instance = mock_client.return_value.__enter__.return_value
            client_instance.request.return_value = mock_response

            result = api_request("POST", "/api/create", json_data={"name": "test"})

            # Verify request was made with JSON body
            call_args = client_instance.request.call_args
            assert call_args[1]["json"] == {"name": "test"}

    def test_handles_204_no_content(self, mock_manager):
        """Given 204 response, returns empty dict."""
        mock_response = MagicMock()
        mock_response.status_code = 204

        with patch("httpx.Client") as mock_client:
            mock_client.return_value.__enter__.return_value.request.return_value = mock_response

            result = api_request("DELETE", "/api/item/1")

        assert result == {}

    def test_raises_on_connection_error(self, mock_manager):
        """Given connection error, raises APIError."""
        with patch("httpx.Client") as mock_client:
            mock_client.return_value.__enter__.return_value.request.side_effect = httpx.ConnectError(
                "Connection refused"
            )

            with pytest.raises(APIError) as exc_info:
                api_request("GET", "/api/test")

            assert "connect" in str(exc_info.value).lower()

    def test_raises_on_http_error(self, mock_manager):
        """Given HTTP error status, raises APIError with status code."""
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_response.json.return_value = {"detail": "Resource not found"}

        error = httpx.HTTPStatusError(
            "Not Found",
            request=MagicMock(),
            response=mock_response,
        )

        with patch("httpx.Client") as mock_client:
            mock_client.return_value.__enter__.return_value.request.return_value = mock_response
            mock_response.raise_for_status.side_effect = error

            with pytest.raises(APIError) as exc_info:
                api_request("GET", "/api/missing")

            assert exc_info.value.status_code == 404
            assert "Resource not found" in str(exc_info.value)

    def test_includes_auth_header(self, mock_manager):
        """Request includes Authorization header from manager.json."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {}

        with patch("httpx.Client") as mock_client:
            client_instance = mock_client.return_value.__enter__.return_value
            client_instance.request.return_value = mock_response

            api_request("GET", "/api/test")

            call_args = client_instance.request.call_args
            assert "Authorization" in call_args[1]["headers"]
            assert call_args[1]["headers"]["Authorization"] == "Bearer test-token"

    def test_uses_correct_base_url(self, mock_manager):
        """Request uses base URL from manager.json."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {}

        with patch("httpx.Client") as mock_client:
            client_instance = mock_client.return_value.__enter__.return_value
            client_instance.request.return_value = mock_response

            api_request("GET", "/api/test")

            call_args = client_instance.request.call_args
            assert call_args[0][1] == "http://127.0.0.1:8765/api/test"

    def test_passes_query_params(self, mock_manager):
        """Given params dict, passes as query parameters."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"entries": []}

        with patch("httpx.Client") as mock_client:
            client_instance = mock_client.return_value.__enter__.return_value
            client_instance.request.return_value = mock_response

            api_request("GET", "/api/logs", params={"limit": 50, "offset": 10})

            call_args = client_instance.request.call_args
            assert call_args[1]["params"] == {"limit": 50, "offset": 10}

    def test_respects_custom_timeout(self, mock_manager):
        """Given custom timeout, uses it for request."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {}

        with patch("httpx.Client") as mock_client:
            api_request("GET", "/api/test", timeout=60.0)

            # Verify client was created with custom timeout
            mock_client.assert_called_once()
            call_kwargs = mock_client.call_args[1]
            assert call_kwargs["timeout"] == 60.0

    def test_raises_proxy_not_running_when_no_manager(self):
        """Given no manager.json, raises ProxyNotRunningError."""
        with patch(
            "mcp_acp_extended.cli.api_client.read_manager_file",
            return_value=None,
        ):
            with pytest.raises(ProxyNotRunningError):
                api_request("GET", "/api/test")

    def test_extracts_detail_from_error_response(self, mock_manager):
        """Given error with detail field, extracts it for message."""
        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.json.return_value = {"detail": "Invalid input data"}

        error = httpx.HTTPStatusError(
            "Bad Request",
            request=MagicMock(),
            response=mock_response,
        )

        with patch("httpx.Client") as mock_client:
            mock_client.return_value.__enter__.return_value.request.return_value = mock_response
            mock_response.raise_for_status.side_effect = error

            with pytest.raises(APIError) as exc_info:
                api_request("POST", "/api/data", json_data={})

            assert "Invalid input data" in str(exc_info.value)

    def test_handles_non_json_error_response(self, mock_manager):
        """Given error without JSON body, uses status text."""
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.json.side_effect = json.JSONDecodeError("", "", 0)

        error = httpx.HTTPStatusError(
            "Internal Server Error",
            request=MagicMock(),
            response=mock_response,
        )

        with patch("httpx.Client") as mock_client:
            mock_client.return_value.__enter__.return_value.request.return_value = mock_response
            mock_response.raise_for_status.side_effect = error

            with pytest.raises(APIError) as exc_info:
                api_request("GET", "/api/test")

            assert exc_info.value.status_code == 500

    def test_supports_all_http_methods(self, mock_manager):
        """Supports GET, POST, PUT, DELETE methods."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {}

        with patch("httpx.Client") as mock_client:
            client_instance = mock_client.return_value.__enter__.return_value
            client_instance.request.return_value = mock_response

            for method in ["GET", "POST", "PUT", "DELETE"]:
                api_request(method, "/api/test")

                call_args = client_instance.request.call_args
                assert call_args[0][0] == method
