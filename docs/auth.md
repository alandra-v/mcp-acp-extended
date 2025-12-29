# Authentication

## Primary Goals

Authentication supports the Zero Trust security model with three primary goals:

1. **User Identity**: Prove WHO the user is via OAuth/OIDC (Auth0)
2. **Device Posture**: Validate device meets security requirements (disk encryption, SIP)
3. **Session Binding**: Link all requests to authenticated identity

**Zero Trust compliance**: Authentication is MANDATORY. There is no option to disable or bypass authentication. The proxy refuses to start without valid credentials.

---

## Authentication Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ FIRST TIME SETUP (one-time)                                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│ 1. User runs: mcp-acp-extended init  (configures Auth0)                     │
│ 2. User runs: mcp-acp-extended auth login                                   │
│    └── Browser opens → Auth0 login page                                     │
│    └── User authenticates (username/password, SSO, MFA)                     │
│    └── Token stored in OS Keychain                                          │
│ 3. User configures Claude Desktop to use proxy                              │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│ EVERY SESSION (automatic)                                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│ 1. User opens Claude Desktop                                                │
│ 2. Claude Desktop starts proxy via STDIO                                    │
│ 3. Proxy startup:                                                           │
│    a. Load token from Keychain                                              │
│    b. Validate JWT (signature, issuer, audience, expiry)                    │
│    c. If expired → try refresh with refresh_token                           │
│    d. Run device health checks (disk encryption, SIP)                       │
│    e. If all pass → proxy ready, log session_started                        │
│    f. If ANY fail → proxy exits with error popup                            │
│ 4. Per-request: validate identity (60s cache for performance)               │
└─────────────────────────────────────────────────────────────────────────────┘
```

This follows the same pattern as `gh auth login`, `aws sso login`, `gcloud auth login`.

---

## Token Storage

Tokens are stored securely using OS-native credential storage:

| Platform | Backend | Location |
|----------|---------|----------|
| macOS | Keychain | `keychain.KeychainStorage` via `keyring` |
| Linux | Secret Service | D-Bus Secret Service API |
| Windows | Credential Locker | Windows Credential Manager |

**Fallback**: If keychain is unavailable (e.g., headless server), uses encrypted file storage with PBKDF2-derived key. File permissions are set to 0600 (owner read/write only).

### Stored Token Structure

```python
class StoredToken(BaseModel):
    access_token: str           # JWT for API access
    refresh_token: str | None   # For silent refresh
    id_token: str | None        # OIDC identity claims
    expires_at: datetime        # Token expiration time (UTC)
    issued_at: datetime         # Token issued time (UTC)
```

---

## JWT Validation

Every request validates the JWT with the following checks:

1. **Signature**: Verify signature using JWKS from Auth0
2. **Issuer**: Must match configured `oidc.issuer`
3. **Audience**: Must match configured `oidc.audience`
4. **Expiration**: Token must not be expired

### JWKS Caching

JWKS keys are cached for 1 hour per-instance to avoid excessive network calls:

```python
JWKS_CACHE_TTL_SECONDS = 3600  # 1 hour
```

### Identity Caching

For performance, validated identity is cached for 60 seconds (Zero Trust with performance):

```python
IDENTITY_CACHE_TTL_SECONDS = 60
```

This means:
- First request in 60s: Full JWT validation
- Subsequent requests: Return cached identity
- After 60s: Re-validate JWT

---

## Device Health Checks

Before proxy startup, device security posture is validated:

| Check | macOS | Requirement |
|-------|-------|-------------|
| Disk Encryption | `fdesetup status` | FileVault must be enabled |
| System Integrity | `csrutil status` | SIP must be enabled |

**Hard gate**: Proxy refuses to start if device is unhealthy.

**Periodic monitoring**: Device health is checked every 5 minutes during operation. If device becomes unhealthy (e.g., FileVault disabled), proxy shuts down immediately (fail-closed).

---

## Identity Provider Architecture

Two patterns support different transport types:

### Pattern 1: STDIO (Current)

For STDIO clients (Claude Desktop), tokens are loaded from OS keychain:

```
┌──────────┐   STDIO    ┌─────────────────────┐
│  Claude  │◄──────────►│       Proxy         │
│  Desktop │            │  (mcp-acp-extended) │
└──────────┘            └──────────┬──────────┘
                                   │
                                   │ Token from Keychain
                                   │ (pre-authenticated via CLI)
                        ┌──────────┴──────────┐
                        │   OS Keychain       │
                        └─────────────────────┘
```

- `OIDCIdentityProvider` loads token from keychain at startup
- Validates JWT per-request (60s cache)
- Auto-refreshes when access_token expires

### Pattern 2: HTTP (Future)

For HTTP clients, tokens come via Bearer header:

```
┌──────────┐   HTTP+Bearer  ┌─────────────────────┐
│  Client  │◄──────────────►│       Proxy         │
│          │   Auth header  │  (FastMCP context)  │
└──────────┘                └─────────────────────┘
```

- `HTTPIdentityProvider` uses FastMCP's `get_access_token()`
- Token extracted from Authorization header by FastMCP
- Same JWT validation, different token source

---

## Configuration

Authentication is configured via `config.json`:

```json
{
  "auth": {
    "oidc": {
      "issuer": "https://your-tenant.auth0.com/",
      "client_id": "your-client-id",
      "audience": "https://your-api.example.com",
      "scopes": ["openid", "profile", "email", "offline_access"]
    }
  }
}
```

| Field | Description |
|-------|-------------|
| `issuer` | Auth0 tenant URL (or other OIDC provider) |
| `client_id` | OAuth client ID for Device Flow |
| `audience` | API identifier for token validation |
| `scopes` | OAuth scopes to request (default includes `offline_access` for refresh) |

**Zero Trust**: `auth` configuration is MANDATORY. The proxy refuses to start without valid OIDC configuration. There is no fallback to `LocalIdentityProvider` in production.

---

## Token Lifetimes

| Token | Auth0 Default | Strategy |
|-------|---------------|----------|
| Access Token | 24 hours | Validate per-request (60s cache) |
| Refresh Token | 30 days | Auto-refresh silently |
| ID Token | 24 hours | Extract claims for Subject |

When refresh token expires:
1. Proxy shows osascript popup: "Authentication expired"
2. User runs: `mcp-acp-extended auth login`
3. User restarts Claude Desktop

---

## Subject Claims

Validated OIDC tokens populate the ABAC Subject model:

| Subject Field | Source | Provenance |
|---------------|--------|------------|
| `id` | JWT `sub` claim | TOKEN |
| `issuer` | JWT `iss` claim | TOKEN |
| `audience` | JWT `aud` claim | TOKEN |
| `scopes` | JWT `scope` claim | TOKEN |
| `client_id` | JWT `azp` claim | TOKEN |
| `token_age_s` | Computed from `iat` | TOKEN |
| `auth_time` | JWT `auth_time` | TOKEN |

These claims enable fine-grained policies:
- Require specific scopes: `subject.scopes contains "admin"`
- Time-based access: `subject.token_age_s < 3600`
- Audience validation: `subject.audience contains "prod-api"`

---

## Design Decisions

### Why OS Keychain over Environment Variables?

1. **Security**: Keychain is encrypted at rest, environment variables are not
2. **User experience**: Single login persists across sessions
3. **Standard practice**: Follows `gh`, `aws`, `gcloud` patterns

### Why 60-second Cache TTL?

Balance between:
- **Security**: Re-validate frequently for Zero Trust
- **Performance**: Avoid network call on every request
- **Token refresh**: Catch expiration within reasonable window

### Why Comma-separated Strings in SubjectIdentity?

`SubjectIdentity.subject_claims` is typed as `dict[str, str]` for JSON serialization in audit logs. Lists (scopes, audience) are stored as comma-separated strings and parsed back when building the full Subject.

### Why Async get_identity()?

1. **OIDC validation may require network**: JWKS fetch, token refresh
2. **Concurrency safety**: `asyncio.Lock` prevents cache race conditions
3. **Future-proof**: HTTP identity providers need async

---

## Security

### Fail-closed Behavior

Authentication failures result in proxy shutdown:

| Failure | Exit Code | Recovery |
|---------|-----------|----------|
| No token in keychain | 13 | `auth login` |
| Token expired + refresh failed | 13 | `auth login` |
| Invalid signature | 13 | `auth login` |
| Issuer/audience mismatch | 13 | Check config |
| Device unhealthy | 14 | Enable FileVault/SIP |

### Audit Logging

Authentication events are logged to `audit/auth.jsonl`:

- `token_validated`: Successful JWT validation
- `token_invalid`: Validation failure
- `token_refreshed`: Successful token refresh
- `token_refresh_failed`: Refresh failure
- `session_started`: Proxy startup with valid auth
- `session_ended`: Proxy shutdown
- `device_health_passed`: Device checks passed
- `device_health_failed`: Device checks failed

---

## Supported Identity Providers

The proxy uses standard OIDC/OAuth 2.0 protocols and works with any compliant provider:

| Protocol | Standard | Purpose |
|----------|----------|---------|
| OAuth 2.0 Device Flow | RFC 8628 | CLI authentication without browser redirect |
| OpenID Connect (OIDC) | OIDC Core 1.0 | Identity layer, JWT tokens with user claims |
| JWKS | RFC 7517 | Public keys for JWT signature verification |

### Compatible Providers

Any provider supporting Device Flow + JWKS:

| Provider | Status | Notes |
|----------|--------|-------|
| Auth0 | ✅ Tested | Create Native app, enable Device Code grant |
| Okta | ✅ Compatible | Enterprise standard |
| Azure AD / Entra ID | ✅ Compatible | Microsoft identity platform |
| Google Workspace | ✅ Compatible | Google Cloud Identity |
| Keycloak | ✅ Compatible | Open source, self-hosted option |
| AWS Cognito | ✅ Compatible | AWS identity service |
| OneLogin | ✅ Compatible | |
| PingIdentity | ✅ Compatible | |

### Provider Setup Requirements

1. Create an application that supports **Device Authorization Grant** (Device Flow)
2. Note the **Client ID** (public, no secret needed for Device Flow)
3. Create an API/Resource Server for the **audience** claim
4. Ensure **JWKS endpoint** is accessible (usually `/.well-known/jwks.json`)

The proxy fetches public keys from your provider's JWKS endpoint to verify JWT signatures - no shared secrets required.

---

## Session Binding

Sessions are bound to user identity to prevent session hijacking per MCP security spec:

```
Session ID Format: <user_id>:<session_uuid>
Example: auth0|12345:550e8400-e29b-41d4-a716-446655440000
```

### BoundSession

```python
@dataclass(frozen=True)
class BoundSession:
    user_id: str         # OIDC subject ID
    session_id: str      # Cryptographically secure random ID (256 bits)
    created_at: datetime
    expires_at: datetime

    @property
    def bound_id(self) -> str:
        """Full bound format: <user_id>:<session_id>"""
        return f"{self.user_id}:{self.session_id}"
```

### Session Manager

The `SessionManager` handles session lifecycle:

| Operation | Description |
|-----------|-------------|
| `create_session(identity)` | Create session bound to user |
| `create_session_from_token(validated_token)` | Create session from validated JWT |
| `validate_session(bound_id, identity)` | Verify session belongs to user |
| `invalidate_session(bound_id)` | End session (logout, timeout) |

**Session TTL**: 8 hours (shorter than token lifetime for security)

### Security Guarantees

- Session created after identity validation
- Session ID includes user binding (`<user_id>:<session_id>`)
- Session validation checks user binding
- Prevents cross-user session hijacking
- Sessions MUST NOT be used for authentication (token validation on every request)

---

## mTLS (Mutual TLS)

mTLS provides mutual authentication between the proxy and backend servers. When configured, the proxy presents a client certificate to prove its identity to the backend.

### How mTLS Works

```
Standard TLS (one-way):
┌───────┐                    ┌─────────┐
│ Proxy │ ──── TLS ────────► │ Backend │
│       │ ◄─ Server Cert ─── │         │
│       │    (verified)      │         │
└───────┘                    └─────────┘
Backend identity verified, but backend doesn't know who proxy is

mTLS (two-way):
┌───────┐                    ┌─────────┐
│ Proxy │ ──── TLS ────────► │ Backend │
│       │ ◄─ Server Cert ─── │         │  Backend presents cert
│       │ ── Client Cert ──► │         │  Proxy presents cert
│       │    (verified)      │         │  Both verified
└───────┘                    └─────────┘
```

### Configuration

mTLS is configured during `mcp-acp-extended init` when an HTTPS backend is detected:

```json
{
  "auth": {
    "oidc": { ... },
    "mtls": {
      "client_cert_path": "/path/to/client.pem",
      "client_key_path": "/path/to/client-key.pem",
      "ca_bundle_path": "/path/to/ca-bundle.pem"
    }
  }
}
```

| Field | Description |
|-------|-------------|
| `client_cert_path` | Client certificate (PEM format) - presented to backend |
| `client_key_path` | Client private key (PEM format) - must match certificate |
| `ca_bundle_path` | CA bundle (PEM format) - verifies backend's server certificate |

### Certificate Requirements

- All certificates must be PEM format
- Client certificate and key must be a matching pair
- CA bundle must contain the CA that signed the backend server's certificate
- All files must be readable by the proxy process (0600 permissions recommended)
- Paths support `~` expansion (e.g., `~/certs/client.pem`)

### Behavior

**Backend doesn't require mTLS:** Works fine. The proxy sends its client cert, but the backend simply ignores it. Connection proceeds as standard TLS.

**Backend requires mTLS:** The proxy presents its client certificate during TLS handshake. If the backend doesn't trust the cert, connection fails at startup (during health check).

**No mTLS configured for HTTPS backend:** Works fine with standard TLS. The proxy verifies the backend's certificate but doesn't present a client certificate.

### Startup Validation

At proxy startup, mTLS certificates are validated:

1. **File existence**: All three paths must exist
2. **PEM format**: Files must be valid PEM-encoded certificates/keys
3. **Cert-key match**: Certificate and private key must form a valid pair

If validation fails, proxy refuses to start with a descriptive error.

### When to Use mTLS

mTLS is recommended when:
- Backend requires client certificate authentication
- Zero Trust network architecture requires mutual authentication
- Additional layer of security beyond bearer tokens is needed
- Compliance requirements mandate mutual TLS

### How to Obtain mTLS Certificates

The process for obtaining certificates depends on your organization:

#### Enterprise / Corporate Environment

Contact your IT or Security team. They typically:
1. Issue certificates from an internal Certificate Authority (CA)
2. Provide you with three files:
   - **Client certificate** (`client.pem`) - Your proxy's identity
   - **Client private key** (`client-key.pem`) - Keep this secure!
   - **CA bundle** (`ca-bundle.pem`) - To verify the backend server

Common enterprise PKI systems:
- Microsoft Active Directory Certificate Services (AD CS)
- HashiCorp Vault PKI
- AWS Private CA
- Google Cloud Certificate Authority Service

#### Cloud / SaaS Backend

Your backend provider may have a certificate provisioning process:
- Check your provider's documentation for "client certificates" or "mTLS setup"
- They typically provide a CA bundle and instructions for generating client certs
- Some providers use their own CLI tools for certificate management

#### Self-Hosted / Development

Generate self-signed certificates for testing:

```bash
# Create a directory for certificates
mkdir -p ~/.mcp-certs && cd ~/.mcp-certs

# 1. Generate CA (Certificate Authority)
openssl genrsa -out ca-key.pem 4096
openssl req -new -x509 -days 365 -key ca-key.pem -out ca-cert.pem \
  -subj "/CN=My CA/O=My Organization"

# 2. Generate client certificate for the proxy
openssl genrsa -out client-key.pem 4096
openssl req -new -key client-key.pem -out client.csr \
  -subj "/CN=mcp-proxy/O=My Organization"
openssl x509 -req -days 365 -in client.csr \
  -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial \
  -out client-cert.pem

# 3. Set secure permissions
chmod 600 client-key.pem

# 4. Verify certificates
openssl verify -CAfile ca-cert.pem client-cert.pem
```

Then configure during init:
```bash
mcp-acp-extended init
# When prompted for mTLS:
# Client certificate: ~/.mcp-certs/client-cert.pem
# Client key: ~/.mcp-certs/client-key.pem
# CA bundle: ~/.mcp-certs/ca-cert.pem
```

#### Certificate File Formats

The proxy expects **PEM format** files. If you have other formats:

| Format | Extension | Convert to PEM |
|--------|-----------|----------------|
| DER | `.der`, `.cer` | `openssl x509 -in cert.der -inform DER -out cert.pem` |
| PKCS#12 | `.p12`, `.pfx` | `openssl pkcs12 -in cert.p12 -out cert.pem -nodes` |
| PKCS#7 | `.p7b` | `openssl pkcs7 -in cert.p7b -print_certs -out cert.pem` |

#### Certificate Renewal

Certificates expire. Plan for renewal:
- The proxy warns when certificates expire within **14 days**
- Critical warning when certificates expire within **7 days**
- Expired certificates **block proxy startup**

Check certificate status anytime:
```bash
mcp-acp-extended auth status
```

To check expiry manually:
```bash
openssl x509 -in /path/to/client-cert.pem -noout -enddate
```

---

## See Also

- [Security](security.md) - Overall security architecture
- [Logging](logging.md) - Audit log format and integrity
- [Auth Logging Spec](logging_specs/audit/auth.md) - Auth event schema for audit/auth.jsonl
- [Configuration](configuration.md) - Full configuration reference
- [Design: Authentication](design/authentication_implementation.md) - Implementation details
