"""Unit tests for API security module.

Tests token management, validation, and security middleware.
"""

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from starlette.responses import JSONResponse

from mcp_acp_extended.api.security import (
    ALLOWED_HOSTS,
    ALLOWED_ORIGINS,
    MAX_REQUEST_SIZE,
    SecurityMiddleware,
    delete_manager_file,
    generate_token,
    is_valid_token_format,
    read_manager_file,
    validate_token,
    write_manager_file,
)


class TestGenerateToken:
    """Tests for generate_token function."""

    def test_generates_64_char_hex_string(self):
        """Token is 64 hex characters (32 bytes)."""
        token = generate_token()

        assert len(token) == 64
        assert all(c in "0123456789abcdef" for c in token)

    def test_generates_unique_tokens(self):
        """Each call generates unique token."""
        tokens = {generate_token() for _ in range(100)}

        assert len(tokens) == 100  # All unique

    def test_token_is_lowercase_hex(self):
        """Token uses lowercase hex characters."""
        token = generate_token()

        assert token == token.lower()


class TestIsValidTokenFormat:
    """Tests for is_valid_token_format function."""

    def test_valid_token(self):
        """Given valid 64-char hex token, returns True."""
        token = "a" * 64

        assert is_valid_token_format(token) is True

    def test_rejects_short_token(self):
        """Given token < 64 chars, returns False."""
        token = "a" * 63

        assert is_valid_token_format(token) is False

    def test_rejects_long_token(self):
        """Given token > 64 chars, returns False."""
        token = "a" * 65

        assert is_valid_token_format(token) is False

    def test_rejects_non_hex_characters(self):
        """Given token with non-hex chars, returns False."""
        token = "g" * 64  # 'g' is not hex

        assert is_valid_token_format(token) is False

    def test_rejects_empty_string(self):
        """Given empty string, returns False."""
        assert is_valid_token_format("") is False

    def test_accepts_uppercase_hex(self):
        """Given uppercase hex, returns True (case-insensitive)."""
        token = "A" * 64

        assert is_valid_token_format(token) is True

    def test_accepts_mixed_case(self):
        """Given mixed case hex, returns True."""
        token = "aAbBcCdDeEfF" + "0123456789" * 5 + "ab"

        assert is_valid_token_format(token) is True

    def test_rejects_special_characters(self):
        """Given token with special chars, returns False."""
        token = "a" * 32 + "<script>" + "a" * 24

        assert is_valid_token_format(token) is False


class TestValidateToken:
    """Tests for validate_token function."""

    def test_matching_tokens_return_true(self):
        """Given matching tokens, returns True."""
        token = generate_token()

        assert validate_token(token, token) is True

    def test_different_tokens_return_false(self):
        """Given different tokens, returns False."""
        token1 = generate_token()
        token2 = generate_token()

        assert validate_token(token1, token2) is False

    def test_empty_tokens_match(self):
        """Given both empty strings, returns True."""
        assert validate_token("", "") is True

    def test_timing_safe_comparison(self):
        """Validates using hmac.compare_digest (constant time)."""
        # This is more of a behavioral test - the function should not
        # short-circuit on first difference
        token = "a" * 64
        wrong = "b" * 64

        # Both should take similar time (hard to test directly)
        assert validate_token(token, wrong) is False


class TestWriteManagerFile:
    """Tests for write_manager_file function."""

    def test_writes_json_with_port_and_token(self, tmp_path):
        """Creates manager.json with port, token, and timestamp."""
        manager_file = tmp_path / ".mcp-acp-extended" / "manager.json"

        with patch("mcp_acp_extended.api.security.MANAGER_FILE", manager_file):
            write_manager_file(port=8765, token="test-token")

        assert manager_file.exists()
        data = json.loads(manager_file.read_text())
        assert data["port"] == 8765
        assert data["token"] == "test-token"
        assert "started_at" in data

    def test_creates_parent_directory(self, tmp_path):
        """Creates parent directory if it doesn't exist."""
        manager_file = tmp_path / "new_dir" / "manager.json"

        with patch("mcp_acp_extended.api.security.MANAGER_FILE", manager_file):
            write_manager_file(port=8765, token="test-token")

        assert manager_file.parent.exists()

    def test_sets_restrictive_permissions(self, tmp_path):
        """Sets file permissions to 0o600 (owner read/write only)."""
        manager_file = tmp_path / ".mcp-acp-extended" / "manager.json"

        with patch("mcp_acp_extended.api.security.MANAGER_FILE", manager_file):
            write_manager_file(port=8765, token="test-token")

        # Check file mode (last 3 octal digits)
        mode = manager_file.stat().st_mode & 0o777
        assert mode == 0o600


class TestDeleteManagerFile:
    """Tests for delete_manager_file function."""

    def test_deletes_existing_file(self, tmp_path):
        """Deletes manager.json if it exists."""
        manager_file = tmp_path / "manager.json"
        manager_file.write_text("{}")

        with patch("mcp_acp_extended.api.security.MANAGER_FILE", manager_file):
            delete_manager_file()

        assert not manager_file.exists()

    def test_handles_missing_file(self, tmp_path):
        """Does not raise if file doesn't exist."""
        manager_file = tmp_path / "nonexistent.json"

        with patch("mcp_acp_extended.api.security.MANAGER_FILE", manager_file):
            delete_manager_file()  # Should not raise

        assert not manager_file.exists()


class TestReadManagerFile:
    """Tests for read_manager_file function."""

    def test_reads_existing_file(self, tmp_path):
        """Returns dict from valid manager.json."""
        manager_file = tmp_path / "manager.json"
        data = {"port": 8765, "token": "test-token", "started_at": "2024-01-01T00:00:00"}
        manager_file.write_text(json.dumps(data))

        with patch("mcp_acp_extended.api.security.MANAGER_FILE", manager_file):
            result = read_manager_file()

        assert result == data

    def test_returns_none_for_missing_file(self, tmp_path):
        """Returns None if file doesn't exist."""
        manager_file = tmp_path / "nonexistent.json"

        with patch("mcp_acp_extended.api.security.MANAGER_FILE", manager_file):
            result = read_manager_file()

        assert result is None

    def test_returns_none_for_invalid_json(self, tmp_path):
        """Returns None if file contains invalid JSON."""
        manager_file = tmp_path / "manager.json"
        manager_file.write_text("not valid json")

        with patch("mcp_acp_extended.api.security.MANAGER_FILE", manager_file):
            result = read_manager_file()

        assert result is None


class TestSecurityMiddleware:
    """Tests for SecurityMiddleware."""

    @pytest.fixture
    def app_with_middleware(self):
        """Create app with security middleware."""
        app = FastAPI()
        token = "a" * 64

        @app.get("/api/test")
        async def test_endpoint():
            return {"status": "ok"}

        @app.post("/api/mutate")
        async def mutate_endpoint():
            return {"status": "mutated"}

        @app.get("/api/approvals/pending")
        async def sse_endpoint():
            return {"status": "sse"}

        @app.get("/public")
        async def public_endpoint():
            return {"status": "public"}

        app.add_middleware(SecurityMiddleware, token=token)
        return app, token

    @pytest.fixture
    def client(self, app_with_middleware):
        """Create test client."""
        app, _ = app_with_middleware
        return TestClient(app, raise_server_exceptions=False)

    def test_rejects_invalid_host(self, client):
        """Given invalid host header, returns 403."""
        response = client.get("/api/test", headers={"host": "evil.com"})

        assert response.status_code == 403
        assert "host" in response.json()["error"].lower()

    def test_accepts_localhost(self, client, app_with_middleware):
        """Given localhost host header, accepts request."""
        _, token = app_with_middleware

        response = client.get(
            "/api/test",
            headers={"host": "localhost:8765", "authorization": f"Bearer {token}"},
        )

        assert response.status_code == 200

    def test_accepts_127_0_0_1(self, client, app_with_middleware):
        """Given 127.0.0.1 host header, accepts request."""
        _, token = app_with_middleware

        response = client.get(
            "/api/test",
            headers={"host": "127.0.0.1:8765", "authorization": f"Bearer {token}"},
        )

        assert response.status_code == 200

    def test_rejects_invalid_origin(self, client, app_with_middleware):
        """Given invalid origin header, returns 403."""
        _, token = app_with_middleware

        response = client.get(
            "/api/test",
            headers={
                "host": "localhost:8765",
                "origin": "http://evil.com",
                "authorization": f"Bearer {token}",
            },
        )

        assert response.status_code == 403
        assert "origin" in response.json()["error"].lower()

    def test_accepts_allowed_origin(self, client, app_with_middleware):
        """Given allowed origin, accepts request."""
        _, token = app_with_middleware

        response = client.get(
            "/api/test",
            headers={
                "host": "localhost:8765",
                "origin": "http://localhost:8765",
                "authorization": f"Bearer {token}",
            },
        )

        assert response.status_code == 200

    def test_requires_auth_for_api_endpoints(self, client):
        """Given no auth header for /api/*, returns 401."""
        response = client.get("/api/test", headers={"host": "localhost:8765"})

        assert response.status_code == 401

    def test_accepts_valid_bearer_token(self, client, app_with_middleware):
        """Given valid bearer token, accepts request."""
        _, token = app_with_middleware

        response = client.get(
            "/api/test",
            headers={"host": "localhost:8765", "authorization": f"Bearer {token}"},
        )

        assert response.status_code == 200

    def test_rejects_invalid_bearer_token(self, client):
        """Given invalid bearer token, returns 401."""
        response = client.get(
            "/api/test",
            headers={"host": "localhost:8765", "authorization": "Bearer wrong-token"},
        )

        assert response.status_code == 401

    def test_requires_origin_for_mutations(self, client):
        """Given POST without origin or token, returns 403."""
        response = client.post("/api/mutate", headers={"host": "localhost:8765"})

        assert response.status_code == 403

    def test_allows_mutation_with_valid_token_no_origin(self, client, app_with_middleware):
        """Given POST with valid token but no origin, accepts (CLI access)."""
        _, token = app_with_middleware

        response = client.post(
            "/api/mutate",
            headers={"host": "localhost:8765", "authorization": f"Bearer {token}"},
        )

        assert response.status_code == 200

    def test_rejects_oversized_request(self, client, app_with_middleware):
        """Given request exceeding size limit, returns 413."""
        _, token = app_with_middleware

        # Create content larger than MAX_REQUEST_SIZE
        response = client.post(
            "/api/mutate",
            headers={
                "host": "localhost:8765",
                "authorization": f"Bearer {token}",
                "content-length": str(MAX_REQUEST_SIZE + 1),
            },
            content=b"x",
        )

        assert response.status_code == 413

    def test_sse_endpoint_same_origin_no_token(self, client):
        """Given SSE endpoint with same-origin (no origin header), accepts."""
        # Same-origin requests don't send Origin header
        response = client.get(
            "/api/approvals/pending",
            headers={"host": "localhost:8765"},
        )

        assert response.status_code == 200

    def test_sse_endpoint_cross_origin_with_token_param(self, client, app_with_middleware):
        """Given SSE endpoint with token query param, accepts."""
        _, token = app_with_middleware

        response = client.get(
            f"/api/approvals/pending?token={token}",
            headers={"host": "localhost:8765", "origin": "http://localhost:3000"},
        )

        assert response.status_code == 200

    def test_adds_security_headers(self, client, app_with_middleware):
        """Response includes security headers."""
        _, token = app_with_middleware

        response = client.get(
            "/api/test",
            headers={"host": "localhost:8765", "authorization": f"Bearer {token}"},
        )

        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert response.headers["X-Frame-Options"] == "DENY"
        assert "Content-Security-Policy" in response.headers
        assert response.headers["Cache-Control"] == "no-store"

    def test_non_api_endpoints_bypass_auth(self, client):
        """Given non-API endpoint, does not require auth."""
        response = client.get("/public", headers={"host": "localhost:8765"})

        assert response.status_code == 200


class TestAllowedHostsAndOrigins:
    """Tests for security constants."""

    def test_allowed_hosts_includes_localhost_variants(self):
        """ALLOWED_HOSTS includes common localhost names."""
        assert "localhost" in ALLOWED_HOSTS
        assert "127.0.0.1" in ALLOWED_HOSTS
        assert "[::1]" in ALLOWED_HOSTS

    def test_allowed_origins_includes_production_and_dev(self):
        """ALLOWED_ORIGINS includes production and dev origins."""
        # Production
        assert "http://localhost:8765" in ALLOWED_ORIGINS
        assert "http://127.0.0.1:8765" in ALLOWED_ORIGINS
        # Development (Vite)
        assert "http://localhost:3000" in ALLOWED_ORIGINS
        assert "http://127.0.0.1:3000" in ALLOWED_ORIGINS
