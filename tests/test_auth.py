"""Tests for authentication infrastructure.

Tests cover:
- Token storage (StoredToken model, EncryptedFileStorage)
- JWT validation (ValidatedToken model, JWTValidator with test keys)
- Device flow (DeviceCodeResponse parsing, DeviceFlow with mocked HTTP)
- Device health (DeviceHealthReport model, check functions with mocked subprocess)
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from mcp_acp_extended.config import OIDCConfig
from mcp_acp_extended.exceptions import AuthenticationError
from mcp_acp_extended.security.auth.device_flow import (
    DeviceCodeResponse,
    DeviceFlow,
    DeviceFlowDeniedError,
    DeviceFlowError,
    DeviceFlowExpiredError,
)
from mcp_acp_extended.security.auth.jwt_validator import (
    JWTValidator,
    ValidatedToken,
)
from mcp_acp_extended.security.auth.token_storage import (
    EncryptedFileStorage,
    StoredToken,
    create_token_storage,
)
from mcp_acp_extended.security.posture.device import (
    DeviceHealthReport,
    check_device_health,
)


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def oidc_config() -> OIDCConfig:
    """Valid OIDC configuration for tests."""
    return OIDCConfig(
        issuer="https://test.auth0.com",
        client_id="test-client-id",
        audience="https://api.test.com",
        scopes=["openid", "profile", "email", "offline_access"],
    )


@pytest.fixture
def stored_token() -> StoredToken:
    """Valid stored token for tests."""
    now = datetime.now(timezone.utc)
    return StoredToken(
        access_token="test-access-token",
        refresh_token="test-refresh-token",
        id_token="test-id-token",
        expires_at=now + timedelta(hours=1),
        issued_at=now,
    )


@pytest.fixture
def expired_token() -> StoredToken:
    """Expired stored token for tests."""
    now = datetime.now(timezone.utc)
    return StoredToken(
        access_token="expired-access-token",
        refresh_token="expired-refresh-token",
        expires_at=now - timedelta(hours=1),
        issued_at=now - timedelta(hours=2),
    )


@pytest.fixture
def rsa_key_pair() -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """Generate RSA key pair for JWT signing."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key


@pytest.fixture
def valid_jwt(oidc_config: OIDCConfig, rsa_key_pair: tuple) -> str:
    """Create a valid JWT for testing."""
    private_key, _ = rsa_key_pair
    now = datetime.now(timezone.utc)

    payload = {
        "sub": "auth0|12345",
        "iss": oidc_config.issuer,
        "aud": oidc_config.audience,
        "exp": int((now + timedelta(hours=1)).timestamp()),
        "iat": int(now.timestamp()),
        "scope": "openid profile email",
    }

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    return jwt.encode(payload, private_key_pem, algorithm="RS256")


# ============================================================================
# StoredToken Tests
# ============================================================================


class TestStoredToken:
    """Tests for StoredToken model."""

    def test_is_expired_returns_false_for_valid_token(self, stored_token: StoredToken):
        """Valid token should not be expired."""
        assert stored_token.is_expired is False

    def test_is_expired_returns_true_for_expired_token(self, expired_token: StoredToken):
        """Expired token should be expired."""
        assert expired_token.is_expired is True

    def test_seconds_until_expiry_positive_for_valid_token(self, stored_token: StoredToken):
        """Valid token should have positive seconds until expiry."""
        assert stored_token.seconds_until_expiry > 0
        assert stored_token.seconds_until_expiry <= 3600  # 1 hour

    def test_seconds_until_expiry_negative_for_expired_token(self, expired_token: StoredToken):
        """Expired token should have negative seconds until expiry."""
        assert expired_token.seconds_until_expiry < 0

    def test_serialization_roundtrip(self, stored_token: StoredToken):
        """Token should survive JSON serialization roundtrip."""
        json_str = stored_token.to_json()
        restored = StoredToken.from_json(json_str)

        assert restored.access_token == stored_token.access_token
        assert restored.refresh_token == stored_token.refresh_token
        assert restored.id_token == stored_token.id_token
        assert restored.expires_at == stored_token.expires_at
        assert restored.issued_at == stored_token.issued_at

    def test_optional_fields_can_be_none(self):
        """Optional fields (refresh_token, id_token) can be None."""
        now = datetime.now(timezone.utc)
        token = StoredToken(
            access_token="access",
            expires_at=now + timedelta(hours=1),
            issued_at=now,
        )
        assert token.refresh_token is None
        assert token.id_token is None


# ============================================================================
# ValidatedToken Tests
# ============================================================================


class TestValidatedToken:
    """Tests for ValidatedToken model."""

    def test_token_age_seconds(self):
        """token_age_seconds should return time since issued."""
        now = datetime.now(timezone.utc)
        token = ValidatedToken(
            subject_id="user123",
            issuer="https://issuer.com",
            audience=["api"],
            scopes=frozenset(["read"]),
            expires_at=now + timedelta(hours=1),
            issued_at=now - timedelta(minutes=5),
            auth_time=None,
            claims={},
        )

        # Should be approximately 300 seconds (5 minutes)
        age = token.token_age_seconds
        assert 299 <= age <= 301

    def test_auth_age_seconds_when_present(self):
        """auth_age_seconds should return time since auth_time."""
        now = datetime.now(timezone.utc)
        token = ValidatedToken(
            subject_id="user123",
            issuer="https://issuer.com",
            audience=["api"],
            scopes=frozenset(),
            expires_at=now + timedelta(hours=1),
            issued_at=now,
            auth_time=now - timedelta(minutes=10),
            claims={},
        )

        age = token.auth_age_seconds
        assert age is not None
        assert 599 <= age <= 601

    def test_auth_age_seconds_none_when_missing(self):
        """auth_age_seconds should be None when auth_time not set."""
        now = datetime.now(timezone.utc)
        token = ValidatedToken(
            subject_id="user123",
            issuer="https://issuer.com",
            audience=["api"],
            scopes=frozenset(),
            expires_at=now + timedelta(hours=1),
            issued_at=now,
            auth_time=None,
            claims={},
        )

        assert token.auth_age_seconds is None


# ============================================================================
# EncryptedFileStorage Tests
# ============================================================================


class TestEncryptedFileStorage:
    """Tests for EncryptedFileStorage backend."""

    def test_save_and_load_roundtrip(self, tmp_path: Path, stored_token: StoredToken):
        """Token should survive save/load cycle."""
        # Patch the storage path to use temp directory
        with patch.object(
            EncryptedFileStorage,
            "_storage_path",
            tmp_path / "tokens.enc",
            create=True,
        ):
            storage = EncryptedFileStorage()
            storage._storage_path = tmp_path / "tokens.enc"

            storage.save(stored_token)
            loaded = storage.load()

            assert loaded is not None
            assert loaded.access_token == stored_token.access_token
            assert loaded.refresh_token == stored_token.refresh_token

    def test_load_returns_none_when_no_file(self, tmp_path: Path):
        """load() should return None when no token file exists."""
        storage = EncryptedFileStorage()
        storage._storage_path = tmp_path / "nonexistent.enc"

        assert storage.load() is None

    def test_exists_returns_false_when_no_file(self, tmp_path: Path):
        """exists() should return False when no file."""
        storage = EncryptedFileStorage()
        storage._storage_path = tmp_path / "nonexistent.enc"

        assert storage.exists() is False

    def test_exists_returns_true_after_save(self, tmp_path: Path, stored_token: StoredToken):
        """exists() should return True after saving."""
        storage = EncryptedFileStorage()
        storage._storage_path = tmp_path / "tokens.enc"

        storage.save(stored_token)
        assert storage.exists() is True

    def test_delete_removes_file(self, tmp_path: Path, stored_token: StoredToken):
        """delete() should remove the token file."""
        storage = EncryptedFileStorage()
        storage._storage_path = tmp_path / "tokens.enc"

        storage.save(stored_token)
        assert storage.exists() is True

        storage.delete()
        assert storage.exists() is False

    def test_delete_silent_when_no_file(self, tmp_path: Path):
        """delete() should not raise when file doesn't exist."""
        storage = EncryptedFileStorage()
        storage._storage_path = tmp_path / "nonexistent.enc"

        # Should not raise
        storage.delete()

    def test_file_has_secure_permissions(self, tmp_path: Path, stored_token: StoredToken):
        """Saved file should have 0o600 permissions."""
        storage = EncryptedFileStorage()
        storage._storage_path = tmp_path / "tokens.enc"

        storage.save(stored_token)

        mode = storage._storage_path.stat().st_mode & 0o777
        assert mode == 0o600


# ============================================================================
# DeviceCodeResponse Tests
# ============================================================================


class TestDeviceCodeResponse:
    """Tests for DeviceCodeResponse parsing."""

    def test_from_response_parses_all_fields(self):
        """Should parse all fields from Auth0 response."""
        data = {
            "device_code": "device-code-123",
            "user_code": "HDFC-LQRT",
            "verification_uri": "https://test.auth0.com/activate",
            "verification_uri_complete": "https://test.auth0.com/activate?user_code=HDFC-LQRT",
            "expires_in": 900,
            "interval": 5,
        }

        response = DeviceCodeResponse.from_response(data)

        assert response.device_code == "device-code-123"
        assert response.user_code == "HDFC-LQRT"
        assert response.verification_uri == "https://test.auth0.com/activate"
        assert response.verification_uri_complete is not None
        assert response.expires_in == 900
        assert response.interval == 5

    def test_from_response_handles_missing_optional_fields(self):
        """Should handle missing optional fields with defaults."""
        data = {
            "device_code": "device-code-123",
            "user_code": "HDFC-LQRT",
            "verification_uri": "https://test.auth0.com/activate",
            "expires_in": 900,
        }

        response = DeviceCodeResponse.from_response(data)

        assert response.verification_uri_complete is None
        assert response.interval == 5  # Default


# ============================================================================
# DeviceFlow Tests (with mocked HTTP)
# ============================================================================


class TestDeviceFlow:
    """Tests for DeviceFlow with mocked HTTP client."""

    def test_request_device_code_success(self, oidc_config: OIDCConfig):
        """Should request device code from Auth0."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "device_code": "device-code-123",
            "user_code": "HDFC-LQRT",
            "verification_uri": "https://test.auth0.com/activate",
            "expires_in": 900,
            "interval": 5,
        }
        mock_response.raise_for_status = MagicMock()

        mock_client = MagicMock(spec=httpx.Client)
        mock_client.post.return_value = mock_response

        flow = DeviceFlow(oidc_config, http_client=mock_client)
        response = flow.request_device_code()

        assert response.user_code == "HDFC-LQRT"
        mock_client.post.assert_called_once()

    def test_request_device_code_http_error(self, oidc_config: OIDCConfig):
        """Should raise DeviceFlowError on HTTP error."""
        mock_client = MagicMock(spec=httpx.Client)
        mock_client.post.side_effect = httpx.HTTPError("Connection failed")

        flow = DeviceFlow(oidc_config, http_client=mock_client)

        with pytest.raises(DeviceFlowError, match="HTTP error"):
            flow.request_device_code()

    def test_poll_for_token_success(self, oidc_config: OIDCConfig):
        """Should return token when user completes auth."""
        device_code = DeviceCodeResponse(
            device_code="device-code-123",
            user_code="HDFC-LQRT",
            verification_uri="https://test.auth0.com/activate",
            verification_uri_complete=None,
            expires_in=900,
            interval=0,  # No delay for tests
        )

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "access_token": "access-token-123",
            "refresh_token": "refresh-token-123",
            "id_token": "id-token-123",
            "expires_in": 86400,
        }

        mock_client = MagicMock(spec=httpx.Client)
        mock_client.post.return_value = mock_response

        flow = DeviceFlow(oidc_config, http_client=mock_client)

        with patch("time.sleep"):  # Skip sleep
            result = flow.poll_for_token(device_code, timeout=10)

        assert result.token.access_token == "access-token-123"
        assert result.user_code == "HDFC-LQRT"

    def test_poll_for_token_authorization_pending(self, oidc_config: OIDCConfig):
        """Should continue polling on authorization_pending."""
        device_code = DeviceCodeResponse(
            device_code="device-code-123",
            user_code="HDFC-LQRT",
            verification_uri="https://test.auth0.com/activate",
            verification_uri_complete=None,
            expires_in=900,
            interval=0,
        )

        # First response: pending, second: success
        pending_response = MagicMock()
        pending_response.status_code = 400
        pending_response.json.return_value = {"error": "authorization_pending"}

        success_response = MagicMock()
        success_response.status_code = 200
        success_response.json.return_value = {
            "access_token": "access-token-123",
            "expires_in": 86400,
        }

        mock_client = MagicMock(spec=httpx.Client)
        mock_client.post.side_effect = [pending_response, success_response]

        flow = DeviceFlow(oidc_config, http_client=mock_client)

        with patch("time.sleep"):
            result = flow.poll_for_token(device_code, timeout=10)

        assert result.token.access_token == "access-token-123"
        assert mock_client.post.call_count == 2

    def test_poll_for_token_access_denied(self, oidc_config: OIDCConfig):
        """Should raise DeviceFlowDeniedError on access_denied."""
        device_code = DeviceCodeResponse(
            device_code="device-code-123",
            user_code="HDFC-LQRT",
            verification_uri="https://test.auth0.com/activate",
            verification_uri_complete=None,
            expires_in=900,
            interval=0,
        )

        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.json.return_value = {"error": "access_denied"}

        mock_client = MagicMock(spec=httpx.Client)
        mock_client.post.return_value = mock_response

        flow = DeviceFlow(oidc_config, http_client=mock_client)

        with patch("time.sleep"):
            with pytest.raises(DeviceFlowDeniedError):
                flow.poll_for_token(device_code, timeout=10)

    def test_poll_for_token_expired(self, oidc_config: OIDCConfig):
        """Should raise DeviceFlowExpiredError on expired_token."""
        device_code = DeviceCodeResponse(
            device_code="device-code-123",
            user_code="HDFC-LQRT",
            verification_uri="https://test.auth0.com/activate",
            verification_uri_complete=None,
            expires_in=900,
            interval=0,
        )

        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.json.return_value = {"error": "expired_token"}

        mock_client = MagicMock(spec=httpx.Client)
        mock_client.post.return_value = mock_response

        flow = DeviceFlow(oidc_config, http_client=mock_client)

        with patch("time.sleep"):
            with pytest.raises(DeviceFlowExpiredError):
                flow.poll_for_token(device_code, timeout=10)


# ============================================================================
# DeviceHealthReport Tests
# ============================================================================


class TestDeviceHealthReport:
    """Tests for DeviceHealthReport model."""

    def test_is_healthy_all_pass(self):
        """is_healthy should be True when all checks pass."""
        report = DeviceHealthReport(
            disk_encryption="pass",
            device_integrity="pass",
            platform="Darwin",
        )
        assert report.is_healthy is True

    def test_is_healthy_one_fail(self):
        """is_healthy should be False when any check fails."""
        report = DeviceHealthReport(
            disk_encryption="pass",
            device_integrity="fail",
            platform="Darwin",
            errors=["SIP is disabled"],
        )
        assert report.is_healthy is False

    def test_is_healthy_unknown_treated_as_unhealthy(self):
        """is_healthy should be False when any check is unknown (Zero Trust)."""
        report = DeviceHealthReport(
            disk_encryption="unknown",
            device_integrity="pass",
            platform="Darwin",
            errors=["Could not determine FileVault status"],
        )
        assert report.is_healthy is False

    def test_to_dict_includes_all_fields(self):
        """to_dict should include all report fields."""
        report = DeviceHealthReport(
            disk_encryption="pass",
            device_integrity="fail",
            platform="Darwin",
            errors=["SIP is disabled"],
        )

        d = report.to_dict()

        assert d["disk_encryption"] == "pass"
        assert d["device_integrity"] == "fail"
        assert d["platform"] == "Darwin"
        assert d["is_healthy"] is False
        assert "SIP is disabled" in d["errors"]

    def test_str_representation(self):
        """__str__ should provide human-readable output."""
        report = DeviceHealthReport(
            disk_encryption="pass",
            device_integrity="pass",
            platform="Darwin",
        )

        s = str(report)
        assert "HEALTHY" in s
        assert "Darwin" in s


# ============================================================================
# Device Health Check Tests (with mocked subprocess)
# ============================================================================


class TestDeviceHealthChecks:
    """Tests for device health check functions."""

    def test_check_device_health_non_darwin_fails(self):
        """Should fail on non-Darwin platforms."""
        with patch("platform.system", return_value="Linux"):
            report = check_device_health()

        assert report.is_healthy is False
        assert report.disk_encryption == "fail"
        assert report.device_integrity == "fail"
        assert "macOS" in report.errors[0]

    def test_check_device_health_filevault_on(self):
        """Should pass when FileVault is enabled."""
        with patch("platform.system", return_value="Darwin"):
            with patch("subprocess.run") as mock_run:
                # FileVault check
                fv_result = MagicMock()
                fv_result.returncode = 0
                fv_result.stdout = "FileVault is On."

                # SIP check
                sip_result = MagicMock()
                sip_result.returncode = 0
                sip_result.stdout = "System Integrity Protection status: enabled."

                mock_run.side_effect = [fv_result, sip_result]

                report = check_device_health()

        assert report.disk_encryption == "pass"
        assert report.device_integrity == "pass"
        assert report.is_healthy is True

    def test_check_device_health_filevault_off(self):
        """Should fail when FileVault is disabled."""
        with patch("platform.system", return_value="Darwin"):
            with patch("subprocess.run") as mock_run:
                fv_result = MagicMock()
                fv_result.returncode = 0
                fv_result.stdout = "FileVault is Off."

                sip_result = MagicMock()
                sip_result.returncode = 0
                sip_result.stdout = "System Integrity Protection status: enabled."

                mock_run.side_effect = [fv_result, sip_result]

                report = check_device_health()

        assert report.disk_encryption == "fail"
        assert report.is_healthy is False
        assert "FileVault is disabled" in report.errors

    def test_check_device_health_sip_disabled(self):
        """Should fail when SIP is disabled."""
        with patch("platform.system", return_value="Darwin"):
            with patch("subprocess.run") as mock_run:
                fv_result = MagicMock()
                fv_result.returncode = 0
                fv_result.stdout = "FileVault is On."

                sip_result = MagicMock()
                sip_result.returncode = 0
                sip_result.stdout = "System Integrity Protection status: disabled."

                mock_run.side_effect = [fv_result, sip_result]

                report = check_device_health()

        assert report.device_integrity == "fail"
        assert report.is_healthy is False
        assert "SIP is disabled" in report.errors

    def test_check_device_health_command_timeout(self):
        """Should return unknown on command timeout."""
        import subprocess

        with patch("platform.system", return_value="Darwin"):
            with patch("subprocess.run") as mock_run:
                mock_run.side_effect = subprocess.TimeoutExpired("fdesetup", 5)

                report = check_device_health()

        assert report.disk_encryption == "unknown"
        assert report.is_healthy is False


# ============================================================================
# JWTValidator Tests (basic - full tests need JWKS mock)
# ============================================================================


class TestJWTValidatorBasic:
    """Basic tests for JWTValidator (without JWKS mocking)."""

    def test_normalize_audience_string(self, oidc_config: OIDCConfig):
        """Should normalize string audience to list."""
        validator = JWTValidator(oidc_config)

        result = validator._normalize_audience("single-audience")
        assert result == ["single-audience"]

    def test_normalize_audience_list(self, oidc_config: OIDCConfig):
        """Should pass through list audience."""
        validator = JWTValidator(oidc_config)

        result = validator._normalize_audience(["aud1", "aud2"])
        assert result == ["aud1", "aud2"]

    def test_decode_without_validation(self, oidc_config: OIDCConfig, valid_jwt: str):
        """Should decode token without validating signature."""
        validator = JWTValidator(oidc_config)

        claims = validator.decode_without_validation(valid_jwt)

        assert claims["sub"] == "auth0|12345"
        assert claims["iss"] == oidc_config.issuer
        assert claims["aud"] == oidc_config.audience

    def test_decode_without_validation_malformed_token(self, oidc_config: OIDCConfig):
        """Should raise AuthenticationError for malformed token."""
        validator = JWTValidator(oidc_config)

        with pytest.raises(AuthenticationError, match="Failed to decode"):
            validator.decode_without_validation("not-a-valid-jwt")

    def test_clear_cache(self, oidc_config: OIDCConfig):
        """Should clear JWKS cache."""
        validator = JWTValidator(oidc_config)
        validator._jwks_cache = MagicMock()  # Simulate cached value

        validator.clear_cache()

        assert validator._jwks_cache is None


# ============================================================================
# Integration: create_token_storage factory
# ============================================================================


class TestCreateTokenStorage:
    """Tests for create_token_storage factory."""

    def test_returns_encrypted_file_when_keyring_unavailable(self):
        """Should return EncryptedFileStorage when keyring not available."""
        with patch(
            "mcp_acp_extended.security.auth.token_storage._is_keyring_available",
            return_value=False,
        ):
            storage = create_token_storage()

        assert isinstance(storage, EncryptedFileStorage)
