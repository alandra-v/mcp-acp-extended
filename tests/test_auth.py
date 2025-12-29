"""Tests for authentication infrastructure.

Tests cover:
- Token storage (StoredToken model, EncryptedFileStorage)
- JWT validation (ValidatedToken model, JWTValidator with test keys)
- Device flow (DeviceCodeResponse parsing, DeviceFlow with mocked HTTP)
- Device health (DeviceHealthReport model, check functions with mocked subprocess)
"""

from __future__ import annotations

import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
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
    """Valid stored token (expires in 1 hour)."""
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
    """Expired stored token (expired 1 hour ago)."""
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
    """Create a valid JWT signed with test RSA key."""
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


@pytest.fixture
def device_code_response_data() -> dict:
    """Sample Auth0 device code response."""
    return {
        "device_code": "device-code-123",
        "user_code": "HDFC-LQRT",
        "verification_uri": "https://test.auth0.com/activate",
        "verification_uri_complete": "https://test.auth0.com/activate?user_code=HDFC-LQRT",
        "expires_in": 900,
        "interval": 5,
    }


@pytest.fixture
def device_code(device_code_response_data: dict) -> DeviceCodeResponse:
    """Parsed device code for polling tests."""
    data = device_code_response_data.copy()
    data["interval"] = 0  # No delay for tests
    return DeviceCodeResponse.from_response(data)


# ============================================================================
# Tests: StoredToken Model
# ============================================================================


class TestStoredToken:
    """Tests for StoredToken model validation and behavior."""

    def test_is_expired_returns_false_for_valid_token(self, stored_token: StoredToken):
        """Given a token expiring in the future, is_expired returns False."""
        # Act
        result = stored_token.is_expired

        # Assert
        assert result is False

    def test_is_expired_returns_true_for_expired_token(self, expired_token: StoredToken):
        """Given a token that expired in the past, is_expired returns True."""
        # Act
        result = expired_token.is_expired

        # Assert
        assert result is True

    def test_seconds_until_expiry_positive_for_valid_token(self, stored_token: StoredToken):
        """Given a valid token, seconds_until_expiry is positive."""
        # Act
        result = stored_token.seconds_until_expiry

        # Assert
        assert result > 0
        assert result <= 3600  # 1 hour max

    def test_seconds_until_expiry_negative_for_expired_token(self, expired_token: StoredToken):
        """Given an expired token, seconds_until_expiry is negative."""
        # Act
        result = expired_token.seconds_until_expiry

        # Assert
        assert result < 0

    def test_serialization_roundtrip(self, stored_token: StoredToken):
        """Given a token, JSON serialization preserves all fields."""
        # Act
        json_str = stored_token.to_json()
        restored = StoredToken.from_json(json_str)

        # Assert
        assert restored.access_token == stored_token.access_token
        assert restored.refresh_token == stored_token.refresh_token
        assert restored.id_token == stored_token.id_token
        assert restored.expires_at == stored_token.expires_at
        assert restored.issued_at == stored_token.issued_at

    def test_optional_fields_can_be_none(self):
        """Given minimal required fields, optional fields default to None."""
        # Arrange
        now = datetime.now(timezone.utc)

        # Act
        token = StoredToken(
            access_token="access",
            expires_at=now + timedelta(hours=1),
            issued_at=now,
        )

        # Assert
        assert token.refresh_token is None
        assert token.id_token is None


# ============================================================================
# Tests: ValidatedToken Model
# ============================================================================


class TestValidatedToken:
    """Tests for ValidatedToken model properties."""

    def test_token_age_seconds_returns_time_since_issued(self):
        """Given a token issued 5 minutes ago, token_age_seconds is ~300."""
        # Arrange
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

        # Act
        age = token.token_age_seconds

        # Assert
        assert 299 <= age <= 301

    def test_auth_age_seconds_returns_time_since_auth(self):
        """Given auth_time 10 minutes ago, auth_age_seconds is ~600."""
        # Arrange
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

        # Act
        age = token.auth_age_seconds

        # Assert
        assert age is not None
        assert 599 <= age <= 601

    def test_auth_age_seconds_none_when_no_auth_time(self):
        """Given no auth_time, auth_age_seconds returns None."""
        # Arrange
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

        # Act
        result = token.auth_age_seconds

        # Assert
        assert result is None


# ============================================================================
# Tests: EncryptedFileStorage
# ============================================================================


class TestEncryptedFileStorage:
    """Tests for EncryptedFileStorage backend."""

    def test_save_and_load_preserves_token(self, tmp_path: Path, stored_token: StoredToken):
        """Given a saved token, load returns identical token."""
        # Arrange
        storage = EncryptedFileStorage()
        storage._storage_path = tmp_path / "tokens.enc"

        # Act
        storage.save(stored_token)
        loaded = storage.load()

        # Assert
        assert loaded is not None
        assert loaded.access_token == stored_token.access_token
        assert loaded.refresh_token == stored_token.refresh_token

    def test_load_returns_none_when_no_file(self, tmp_path: Path):
        """Given no token file exists, load returns None."""
        # Arrange
        storage = EncryptedFileStorage()
        storage._storage_path = tmp_path / "nonexistent.enc"

        # Act
        result = storage.load()

        # Assert
        assert result is None

    def test_exists_returns_false_when_no_file(self, tmp_path: Path):
        """Given no token file, exists returns False."""
        # Arrange
        storage = EncryptedFileStorage()
        storage._storage_path = tmp_path / "nonexistent.enc"

        # Act
        result = storage.exists()

        # Assert
        assert result is False

    def test_exists_returns_true_after_save(self, tmp_path: Path, stored_token: StoredToken):
        """Given a saved token, exists returns True."""
        # Arrange
        storage = EncryptedFileStorage()
        storage._storage_path = tmp_path / "tokens.enc"
        storage.save(stored_token)

        # Act
        result = storage.exists()

        # Assert
        assert result is True

    def test_delete_removes_file(self, tmp_path: Path, stored_token: StoredToken):
        """Given an existing token file, delete removes it."""
        # Arrange
        storage = EncryptedFileStorage()
        storage._storage_path = tmp_path / "tokens.enc"
        storage.save(stored_token)

        # Act
        storage.delete()

        # Assert
        assert storage.exists() is False

    def test_delete_silent_when_no_file(self, tmp_path: Path):
        """Given no token file, delete does not raise."""
        # Arrange
        storage = EncryptedFileStorage()
        storage._storage_path = tmp_path / "nonexistent.enc"

        # Act & Assert (should not raise)
        storage.delete()

    def test_file_has_secure_permissions(self, tmp_path: Path, stored_token: StoredToken):
        """Given a saved token, file permissions are 0o600."""
        # Arrange
        storage = EncryptedFileStorage()
        storage._storage_path = tmp_path / "tokens.enc"

        # Act
        storage.save(stored_token)

        # Assert
        mode = storage._storage_path.stat().st_mode & 0o777
        assert mode == 0o600


# ============================================================================
# Tests: DeviceCodeResponse
# ============================================================================


class TestDeviceCodeResponse:
    """Tests for DeviceCodeResponse parsing from Auth0 response."""

    def test_from_response_parses_all_fields(self, device_code_response_data: dict):
        """Given complete Auth0 response, parses all fields correctly."""
        # Act
        response = DeviceCodeResponse.from_response(device_code_response_data)

        # Assert
        assert response.device_code == "device-code-123"
        assert response.user_code == "HDFC-LQRT"
        assert response.verification_uri == "https://test.auth0.com/activate"
        assert response.verification_uri_complete is not None
        assert response.expires_in == 900
        assert response.interval == 5

    def test_from_response_handles_missing_optional_fields(self):
        """Given minimal Auth0 response, uses defaults for optional fields."""
        # Arrange
        data = {
            "device_code": "device-code-123",
            "user_code": "HDFC-LQRT",
            "verification_uri": "https://test.auth0.com/activate",
            "expires_in": 900,
        }

        # Act
        response = DeviceCodeResponse.from_response(data)

        # Assert
        assert response.verification_uri_complete is None
        assert response.interval == 5  # Default


# ============================================================================
# Tests: DeviceFlow (with mocked HTTP)
# ============================================================================


class TestDeviceFlow:
    """Tests for DeviceFlow with mocked HTTP client."""

    def test_request_device_code_success(self, oidc_config: OIDCConfig, device_code_response_data: dict):
        """Given valid config, request_device_code returns device code."""
        # Arrange
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = device_code_response_data
        mock_response.raise_for_status = MagicMock()

        mock_client = MagicMock(spec=httpx.Client)
        mock_client.post.return_value = mock_response

        flow = DeviceFlow(oidc_config, http_client=mock_client)

        # Act
        response = flow.request_device_code()

        # Assert
        assert response.user_code == "HDFC-LQRT"
        mock_client.post.assert_called_once()

    def test_request_device_code_raises_on_http_error(self, oidc_config: OIDCConfig):
        """Given HTTP failure, raises DeviceFlowError."""
        # Arrange
        mock_client = MagicMock(spec=httpx.Client)
        mock_client.post.side_effect = httpx.HTTPError("Connection failed")

        flow = DeviceFlow(oidc_config, http_client=mock_client)

        # Act & Assert
        with pytest.raises(DeviceFlowError, match="HTTP error"):
            flow.request_device_code()

    def test_poll_for_token_returns_token_on_success(
        self, oidc_config: OIDCConfig, device_code: DeviceCodeResponse
    ):
        """Given user completes auth, poll_for_token returns token."""
        # Arrange
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

        # Act
        with patch("time.sleep"):
            result = flow.poll_for_token(device_code, timeout=10)

        # Assert
        assert result.token.access_token == "access-token-123"
        assert result.user_code == "HDFC-LQRT"

    def test_poll_for_token_continues_on_authorization_pending(
        self, oidc_config: OIDCConfig, device_code: DeviceCodeResponse
    ):
        """Given authorization_pending, continues polling until success."""
        # Arrange
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

        # Act
        with patch("time.sleep"):
            result = flow.poll_for_token(device_code, timeout=10)

        # Assert
        assert result.token.access_token == "access-token-123"
        assert mock_client.post.call_count == 2

    @pytest.mark.parametrize(
        ("error_code", "expected_exception"),
        [
            ("access_denied", DeviceFlowDeniedError),
            ("expired_token", DeviceFlowExpiredError),
        ],
        ids=["access_denied", "expired_token"],
    )
    def test_poll_for_token_raises_on_terminal_error(
        self,
        oidc_config: OIDCConfig,
        device_code: DeviceCodeResponse,
        error_code: str,
        expected_exception: type,
    ):
        """Given terminal error from Auth0, raises appropriate exception."""
        # Arrange
        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.json.return_value = {"error": error_code}

        mock_client = MagicMock(spec=httpx.Client)
        mock_client.post.return_value = mock_response

        flow = DeviceFlow(oidc_config, http_client=mock_client)

        # Act & Assert
        with patch("time.sleep"):
            with pytest.raises(expected_exception):
                flow.poll_for_token(device_code, timeout=10)


# ============================================================================
# Tests: DeviceHealthReport Model
# ============================================================================


class TestDeviceHealthReport:
    """Tests for DeviceHealthReport model and is_healthy logic."""

    @pytest.mark.parametrize(
        ("disk_encryption", "device_integrity", "expected_healthy"),
        [
            ("pass", "pass", True),
            ("fail", "pass", False),
            ("pass", "fail", False),
            ("unknown", "pass", False),
            ("pass", "unknown", False),
            ("fail", "fail", False),
        ],
        ids=[
            "both_pass",
            "disk_fail",
            "integrity_fail",
            "disk_unknown",
            "integrity_unknown",
            "both_fail",
        ],
    )
    def test_is_healthy_requires_all_pass(
        self, disk_encryption: str, device_integrity: str, expected_healthy: bool
    ):
        """Given check results, is_healthy is True only when all pass."""
        # Arrange
        report = DeviceHealthReport(
            disk_encryption=disk_encryption,  # type: ignore[arg-type]
            device_integrity=device_integrity,  # type: ignore[arg-type]
            platform="Darwin",
        )

        # Act
        result = report.is_healthy

        # Assert
        assert result is expected_healthy

    def test_to_dict_includes_all_fields(self):
        """Given a report, to_dict includes all fields."""
        # Arrange
        report = DeviceHealthReport(
            disk_encryption="pass",
            device_integrity="fail",
            platform="Darwin",
            errors=["SIP is disabled"],
        )

        # Act
        d = report.to_dict()

        # Assert
        assert d["disk_encryption"] == "pass"
        assert d["device_integrity"] == "fail"
        assert d["platform"] == "Darwin"
        assert d["is_healthy"] is False
        assert "SIP is disabled" in d["errors"]

    def test_str_shows_health_status(self):
        """Given a healthy report, __str__ shows HEALTHY."""
        # Arrange
        report = DeviceHealthReport(
            disk_encryption="pass",
            device_integrity="pass",
            platform="Darwin",
        )

        # Act
        s = str(report)

        # Assert
        assert "HEALTHY" in s
        assert "Darwin" in s


# ============================================================================
# Tests: Device Health Checks (with mocked subprocess)
# ============================================================================


class TestDeviceHealthChecks:
    """Tests for device health check functions with mocked subprocess."""

    def test_non_darwin_platform_fails(self):
        """Given non-Darwin platform, returns unhealthy with error."""
        # Arrange & Act
        with patch("platform.system", return_value="Linux"):
            report = check_device_health()

        # Assert
        assert report.is_healthy is False
        assert report.disk_encryption == "fail"
        assert report.device_integrity == "fail"
        assert "macOS" in report.errors[0]

    def test_filevault_on_and_sip_enabled_passes(self):
        """Given FileVault On and SIP enabled, returns healthy."""
        # Arrange
        fv_result = MagicMock()
        fv_result.returncode = 0
        fv_result.stdout = "FileVault is On."

        sip_result = MagicMock()
        sip_result.returncode = 0
        sip_result.stdout = "System Integrity Protection status: enabled."

        # Act
        with patch("platform.system", return_value="Darwin"):
            with patch("subprocess.run", side_effect=[fv_result, sip_result]):
                report = check_device_health()

        # Assert
        assert report.disk_encryption == "pass"
        assert report.device_integrity == "pass"
        assert report.is_healthy is True

    def test_filevault_off_fails(self):
        """Given FileVault Off, returns unhealthy."""
        # Arrange
        fv_result = MagicMock()
        fv_result.returncode = 0
        fv_result.stdout = "FileVault is Off."

        sip_result = MagicMock()
        sip_result.returncode = 0
        sip_result.stdout = "System Integrity Protection status: enabled."

        # Act
        with patch("platform.system", return_value="Darwin"):
            with patch("subprocess.run", side_effect=[fv_result, sip_result]):
                report = check_device_health()

        # Assert
        assert report.disk_encryption == "fail"
        assert report.is_healthy is False
        assert "FileVault is disabled" in report.errors

    def test_sip_disabled_fails(self):
        """Given SIP disabled, returns unhealthy."""
        # Arrange
        fv_result = MagicMock()
        fv_result.returncode = 0
        fv_result.stdout = "FileVault is On."

        sip_result = MagicMock()
        sip_result.returncode = 0
        sip_result.stdout = "System Integrity Protection status: disabled."

        # Act
        with patch("platform.system", return_value="Darwin"):
            with patch("subprocess.run", side_effect=[fv_result, sip_result]):
                report = check_device_health()

        # Assert
        assert report.device_integrity == "fail"
        assert report.is_healthy is False
        assert "SIP is disabled" in report.errors

    def test_command_timeout_returns_unknown(self):
        """Given command timeout, returns unknown (treated as unhealthy)."""
        # Act
        with patch("platform.system", return_value="Darwin"):
            with patch(
                "subprocess.run",
                side_effect=subprocess.TimeoutExpired("fdesetup", 5),
            ):
                report = check_device_health()

        # Assert
        assert report.disk_encryption == "unknown"
        assert report.is_healthy is False


# ============================================================================
# Tests: JWTValidator (basic - full tests need JWKS mock)
# ============================================================================


class TestJWTValidatorBasic:
    """Basic tests for JWTValidator (without JWKS endpoint mocking)."""

    @pytest.mark.parametrize(
        ("input_aud", "expected"),
        [
            ("single-audience", ["single-audience"]),
            (["aud1", "aud2"], ["aud1", "aud2"]),
        ],
        ids=["string", "list"],
    )
    def test_normalize_audience(self, oidc_config: OIDCConfig, input_aud: str | list, expected: list):
        """Given audience as string or list, normalizes to list."""
        # Arrange
        validator = JWTValidator(oidc_config)

        # Act
        result = validator._normalize_audience(input_aud)

        # Assert
        assert result == expected

    def test_decode_without_validation_extracts_claims(self, oidc_config: OIDCConfig, valid_jwt: str):
        """Given valid JWT, decode_without_validation extracts claims."""
        # Arrange
        validator = JWTValidator(oidc_config)

        # Act
        claims = validator.decode_without_validation(valid_jwt)

        # Assert
        assert claims["sub"] == "auth0|12345"
        assert claims["iss"] == oidc_config.issuer
        assert claims["aud"] == oidc_config.audience

    def test_decode_without_validation_raises_on_malformed(self, oidc_config: OIDCConfig):
        """Given malformed token, raises AuthenticationError."""
        # Arrange
        validator = JWTValidator(oidc_config)

        # Act & Assert
        with pytest.raises(AuthenticationError, match="Failed to decode"):
            validator.decode_without_validation("not-a-valid-jwt")

    def test_clear_cache_removes_cached_jwks(self, oidc_config: OIDCConfig):
        """Given cached JWKS, clear_cache removes it."""
        # Arrange
        validator = JWTValidator(oidc_config)
        validator._jwks_cache = MagicMock()

        # Act
        validator.clear_cache()

        # Assert
        assert validator._jwks_cache is None


# ============================================================================
# Tests: create_token_storage Factory
# ============================================================================


class TestCreateTokenStorage:
    """Tests for create_token_storage factory function."""

    def test_returns_encrypted_file_when_keyring_unavailable(self):
        """Given keyring unavailable, returns EncryptedFileStorage."""
        # Arrange & Act
        with patch(
            "mcp_acp_extended.security.auth.token_storage._is_keyring_available",
            return_value=False,
        ):
            storage = create_token_storage()

        # Assert
        assert isinstance(storage, EncryptedFileStorage)


# ============================================================================
# Tests: OIDCIdentityProvider
# ============================================================================


class TestOIDCIdentityProvider:
    """Tests for OIDCIdentityProvider."""

    async def test_get_identity_raises_when_no_token(self, oidc_config: OIDCConfig):
        """Given no stored token, raises AuthenticationError."""
        from mcp_acp_extended.pips.auth import OIDCIdentityProvider

        # Arrange: Mock storage with no token
        mock_storage = MagicMock()
        mock_storage.load.return_value = None

        provider = OIDCIdentityProvider(
            config=oidc_config,
            token_storage=mock_storage,
        )

        # Act & Assert
        with pytest.raises(AuthenticationError, match="Not authenticated"):
            await provider.get_identity()

    async def test_get_identity_returns_cached_identity(self, oidc_config: OIDCConfig):
        """Given cached identity, returns from cache without reloading."""
        from mcp_acp_extended.pips.auth import OIDCIdentityProvider
        from mcp_acp_extended.pips.auth.oidc_provider import _CachedIdentity
        import time

        # Arrange: Provider with pre-populated cache
        mock_storage = MagicMock()
        mock_validator = MagicMock()

        provider = OIDCIdentityProvider(
            config=oidc_config,
            token_storage=mock_storage,
            jwt_validator=mock_validator,
        )

        # Set up cache with valid identity
        from mcp_acp_extended.telemetry.models.audit import SubjectIdentity

        cached_identity = SubjectIdentity(
            subject_id="auth0|cached-user",
            subject_claims={"auth_type": "oidc"},
        )
        cached_token = ValidatedToken(
            subject_id="auth0|cached-user",
            issuer=oidc_config.issuer,
            audience=[oidc_config.audience],
            scopes=frozenset(["openid", "profile"]),
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            issued_at=datetime.now(timezone.utc),
            auth_time=None,
            claims={},
        )
        provider._cache = _CachedIdentity(
            identity=cached_identity,
            validated_token=cached_token,
            cached_at=time.monotonic(),  # Fresh cache
        )

        # Act
        identity = await provider.get_identity()

        # Assert: Returns cached identity, storage not called
        assert identity.subject_id == "auth0|cached-user"
        mock_storage.load.assert_not_called()
        mock_validator.validate.assert_not_called()

    async def test_get_identity_validates_token_when_cache_expired(
        self, oidc_config: OIDCConfig, stored_token: StoredToken
    ):
        """Given expired cache, reloads and validates token."""
        from mcp_acp_extended.pips.auth import OIDCIdentityProvider
        from mcp_acp_extended.pips.auth.oidc_provider import _CachedIdentity, IDENTITY_CACHE_TTL_SECONDS
        import time

        # Arrange
        mock_storage = MagicMock()
        mock_storage.load.return_value = stored_token

        mock_validator = MagicMock()
        mock_validator.validate.return_value = ValidatedToken(
            subject_id="auth0|fresh-user",
            issuer=oidc_config.issuer,
            audience=[oidc_config.audience],
            scopes=frozenset(["openid"]),
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            issued_at=datetime.now(timezone.utc),
            auth_time=None,
            claims={},
        )

        provider = OIDCIdentityProvider(
            config=oidc_config,
            token_storage=mock_storage,
            jwt_validator=mock_validator,
        )

        # Set up expired cache (older than TTL)
        from mcp_acp_extended.telemetry.models.audit import SubjectIdentity

        old_identity = SubjectIdentity(subject_id="old-user")
        old_token = ValidatedToken(
            subject_id="old-user",
            issuer=oidc_config.issuer,
            audience=[oidc_config.audience],
            scopes=frozenset(),
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            issued_at=datetime.now(timezone.utc),
            auth_time=None,
            claims={},
        )
        provider._cache = _CachedIdentity(
            identity=old_identity,
            validated_token=old_token,
            cached_at=time.monotonic() - IDENTITY_CACHE_TTL_SECONDS - 1,  # Expired
        )

        # Act
        identity = await provider.get_identity()

        # Assert: Fresh identity from validation
        assert identity.subject_id == "auth0|fresh-user"
        mock_storage.load.assert_called_once()
        mock_validator.validate.assert_called_once()

    def test_is_authenticated_returns_true_when_token_exists(self, oidc_config: OIDCConfig):
        """Given stored token, is_authenticated returns True."""
        from mcp_acp_extended.pips.auth import OIDCIdentityProvider

        # Arrange
        mock_storage = MagicMock()
        mock_storage.exists.return_value = True

        provider = OIDCIdentityProvider(
            config=oidc_config,
            token_storage=mock_storage,
        )

        # Act & Assert
        assert provider.is_authenticated is True

    def test_is_authenticated_returns_false_when_no_token(self, oidc_config: OIDCConfig):
        """Given no stored token, is_authenticated returns False."""
        from mcp_acp_extended.pips.auth import OIDCIdentityProvider

        # Arrange
        mock_storage = MagicMock()
        mock_storage.exists.return_value = False

        provider = OIDCIdentityProvider(
            config=oidc_config,
            token_storage=mock_storage,
        )

        # Act & Assert
        assert provider.is_authenticated is False

    def test_clear_cache_invalidates_cached_identity(self, oidc_config: OIDCConfig):
        """Given cached identity, clear_cache removes it."""
        from mcp_acp_extended.pips.auth import OIDCIdentityProvider
        from mcp_acp_extended.pips.auth.oidc_provider import _CachedIdentity
        import time

        # Arrange
        provider = OIDCIdentityProvider(
            config=oidc_config,
            token_storage=MagicMock(),
        )

        from mcp_acp_extended.telemetry.models.audit import SubjectIdentity

        provider._cache = _CachedIdentity(
            identity=SubjectIdentity(subject_id="test"),
            validated_token=MagicMock(),
            cached_at=time.monotonic(),
        )

        # Act
        provider.clear_cache()

        # Assert
        assert provider._cache is None

    def test_logout_clears_storage_and_cache(self, oidc_config: OIDCConfig):
        """Given active session, logout clears everything."""
        from mcp_acp_extended.pips.auth import OIDCIdentityProvider

        # Arrange
        mock_storage = MagicMock()
        provider = OIDCIdentityProvider(
            config=oidc_config,
            token_storage=mock_storage,
        )
        provider._cache = MagicMock()  # Simulate cached state

        # Act
        provider.logout()

        # Assert
        mock_storage.delete.assert_called_once()
        assert provider._cache is None


# ============================================================================
# Tests: Claims Utilities
# ============================================================================


class TestClaimsUtilities:
    """Tests for claims-to-Subject mapping utilities."""

    def test_build_subject_from_validated_token(self, oidc_config: OIDCConfig):
        """Given ValidatedToken, builds Subject with full OIDC claims."""
        from mcp_acp_extended.pips.auth.claims import build_subject_from_validated_token
        from mcp_acp_extended.context.provenance import Provenance

        # Arrange
        now = datetime.now(timezone.utc)
        validated = ValidatedToken(
            subject_id="auth0|user123",
            issuer="https://test.auth0.com",
            audience=["https://api.test.com"],
            scopes=frozenset(["openid", "profile", "read:data"]),
            expires_at=now + timedelta(hours=1),
            issued_at=now - timedelta(minutes=5),
            auth_time=now - timedelta(hours=1),
            claims={"azp": "client-app-id"},
        )

        # Act
        subject = build_subject_from_validated_token(validated)

        # Assert
        assert subject.id == "auth0|user123"
        assert subject.issuer == "https://test.auth0.com"
        assert subject.audience == ["https://api.test.com"]
        assert subject.client_id == "client-app-id"
        assert subject.scopes == frozenset(["openid", "profile", "read:data"])
        assert subject.auth_time == now - timedelta(hours=1)
        assert subject.provenance.id == Provenance.TOKEN
        assert subject.provenance.scopes == Provenance.TOKEN

    def test_build_subject_from_identity_local(self):
        """Given local identity, builds minimal Subject."""
        from mcp_acp_extended.pips.auth.claims import build_subject_from_identity
        from mcp_acp_extended.telemetry.models.audit import SubjectIdentity
        from mcp_acp_extended.context.provenance import Provenance

        # Arrange
        identity = SubjectIdentity(
            subject_id="local-user",
            subject_claims={"auth_type": "local"},
        )

        # Act
        subject = build_subject_from_identity(identity)

        # Assert
        assert subject.id == "local-user"
        assert subject.issuer is None
        assert subject.audience is None
        assert subject.scopes is None
        assert subject.provenance.id == Provenance.DERIVED

    def test_build_subject_from_identity_oidc(self):
        """Given OIDC identity with claims, builds rich Subject."""
        from mcp_acp_extended.pips.auth.claims import build_subject_from_identity
        from mcp_acp_extended.telemetry.models.audit import SubjectIdentity
        from mcp_acp_extended.context.provenance import Provenance

        # Arrange - claims are stored as comma-separated strings
        identity = SubjectIdentity(
            subject_id="auth0|user456",
            subject_claims={
                "auth_type": "oidc",
                "issuer": "https://test.auth0.com",
                "audience": "https://api.test.com",
                "scopes": "openid,profile",
            },
        )

        # Act
        subject = build_subject_from_identity(identity)

        # Assert
        assert subject.id == "auth0|user456"
        assert subject.issuer == "https://test.auth0.com"
        assert subject.audience == ["https://api.test.com"]
        assert subject.scopes == frozenset(["openid", "profile"])
        assert subject.provenance.id == Provenance.TOKEN


# ============================================================================
# Tests: Identity Provider Factory
# ============================================================================


class TestCreateIdentityProvider:
    """Tests for create_identity_provider factory function."""

    def test_returns_local_provider_when_no_config(self):
        """Given no config, returns LocalIdentityProvider."""
        from mcp_acp_extended.security.identity import (
            create_identity_provider,
            LocalIdentityProvider,
        )

        # Act
        provider = create_identity_provider(config=None)

        # Assert
        assert isinstance(provider, LocalIdentityProvider)

    def test_returns_local_provider_when_no_auth(self):
        """Given config without auth, returns LocalIdentityProvider."""
        from mcp_acp_extended.security.identity import (
            create_identity_provider,
            LocalIdentityProvider,
        )
        from mcp_acp_extended.config import (
            AppConfig,
            LoggingConfig,
            BackendConfig,
            StdioTransportConfig,
        )

        # Arrange
        config = AppConfig(
            logging=LoggingConfig(log_dir="/tmp"),
            backend=BackendConfig(
                server_name="test",
                transport="stdio",
                stdio=StdioTransportConfig(command="echo"),
            ),
        )

        # Act
        provider = create_identity_provider(config=config)

        # Assert
        assert isinstance(provider, LocalIdentityProvider)

    def test_returns_oidc_provider_when_auth_configured(self):
        """Given config with auth, returns OIDCIdentityProvider."""
        from mcp_acp_extended.security.identity import create_identity_provider
        from mcp_acp_extended.pips.auth import OIDCIdentityProvider
        from mcp_acp_extended.config import (
            AppConfig,
            LoggingConfig,
            BackendConfig,
            StdioTransportConfig,
            AuthConfig,
            OIDCConfig,
        )

        # Arrange
        config = AppConfig(
            auth=AuthConfig(
                oidc=OIDCConfig(
                    issuer="https://test.auth0.com",
                    client_id="test-client",
                    audience="https://api.test.com",
                ),
            ),
            logging=LoggingConfig(log_dir="/tmp"),
            backend=BackendConfig(
                server_name="test",
                transport="stdio",
                stdio=StdioTransportConfig(command="echo"),
            ),
        )

        # Act
        provider = create_identity_provider(config=config, transport="stdio")

        # Assert
        assert isinstance(provider, OIDCIdentityProvider)

    def test_raises_not_implemented_for_http_transport(self):
        """Given HTTP transport, raises NotImplementedError (future work)."""
        from mcp_acp_extended.security.identity import create_identity_provider
        from mcp_acp_extended.config import (
            AppConfig,
            LoggingConfig,
            BackendConfig,
            StdioTransportConfig,
            AuthConfig,
            OIDCConfig,
        )

        # Arrange
        config = AppConfig(
            auth=AuthConfig(
                oidc=OIDCConfig(
                    issuer="https://test.auth0.com",
                    client_id="test-client",
                    audience="https://api.test.com",
                ),
            ),
            logging=LoggingConfig(log_dir="/tmp"),
            backend=BackendConfig(
                server_name="test",
                transport="stdio",
                stdio=StdioTransportConfig(command="echo"),
            ),
        )

        # Act & Assert
        with pytest.raises(NotImplementedError, match="HTTP transport"):
            create_identity_provider(config=config, transport="http")
