# mcp-acp-extended Implementation Progress

## Stage 2: Zero Trust Authentication & Enhanced Context
Full Zero Trust authentication with OIDC, mTLS, device health checks, and enhanced context attributes.

**Design Document:** [docs/design/authentication_implementation.md](docs/design/authentication_implementation.md)

---

## Phase 1: Infrastructure & Configuration ✓

**Status: Complete**

Logging infrastructure, auth audit trail, and configuration schema.

- [x] **Startup validation for audit logs**
  - Check write permissions before proxy starts
  - Verify directory structure exists (create if needed)
  - Fail fast if audit logging cannot be guaranteed

- [x] **AuditHealthMonitor integration**
  - Start monitor as background task on proxy startup (via FastMCP lifespan)
  - Register audit log paths (operations, decisions, auth)
  - Clean shutdown: cancel task, await completion
  - Handle monitor crash → trigger fail-closed shutdown

- [x] **Auth audit logger** (`telemetry/audit/auth_logger.py`)
  - Log to `audit/auth.jsonl` with fail-closed handler
  - Events: `token_validated`, `token_invalid`, `token_refreshed`, `token_refresh_failed`, `session_started`, `session_ended`, `device_health_passed`, `device_health_failed`
  - AuthEvent model with DeviceHealthChecks

- [x] **Configuration models** (`config.py`)
  - `OIDCConfig`, `MTLSConfig`, `AuthConfig` models
  - `auth: AuthConfig` required on `AppConfig` (Zero Trust)
  - CLI init prompts and flags for auth configuration

- [x] **Dependencies** (`pyproject.toml`)
  - PyJWT, cryptography, keyring, httpx

---

## Phase 2: OAuth Authentication ✓

**Status: Complete**

Token storage, JWT validation, device flow, and token refresh.

- [x] **Token storage** (`security/auth/token_storage.py`)
  - `KeychainStorage` (primary) using keyring library
  - `EncryptedFileStorage` (fallback) using Fernet with PBKDF2
  - `StoredToken` model with expiry tracking
  - Auto-selection via `create_token_storage()`

- [x] **JWT validation** (`security/auth/jwt_validator.py`)
  - Validate JWT signature using JWKS from Auth0
  - Verify issuer, audience, expiration
  - Cache JWKS for 1 hour (per-instance)
  - `ValidatedToken` dataclass with extracted claims

- [x] **Device Authorization Flow** (`security/auth/device_flow.py`)
  - OAuth Device Flow (RFC 8628) implementation
  - Request device code, display user_code/verification_uri
  - Poll token endpoint with slow_down handling
  - Returns `StoredToken` ready for keychain storage
  - Constants moved to `constants.py`

- [x] **Token refresh** (`security/auth/token_refresh.py`)
  - Refresh access token using refresh_token grant
  - `TokenRefreshError`, `TokenRefreshExpiredError` exceptions
  - Handles expired/invalid_grant → re-authentication required

---

## Phase 3: Device Posture ✓

**Status: Complete**

Device health checks and periodic monitoring.

- [x] **Device health checker** (`security/posture/device.py`)
  - Disk encryption: `fdesetup status` (FileVault on macOS)
  - Device integrity: `csrutil status` (SIP on macOS)
  - Hard gate: proxy won't start if unhealthy

- [x] **Periodic health monitor** (`security/posture/device_monitor.py`)
  - Background async task checks every 5 minutes
  - Zero Trust: fails on first check failure (threshold=1)
  - Triggers shutdown via `ShutdownCoordinator` if device becomes unhealthy
  - Logs to auth.jsonl audit trail

- [x] **Proxy integration**
  - Hard gate at startup: proxy won't start if device unhealthy
  - `DeviceHealthMonitor` starts/stops with proxy lifespan

---

## Phase 4: OIDC Identity Provider

**Status: Not Started**

Wire authentication into the proxy request flow.

- [ ] **OIDCIdentityProvider** (`pips/auth/oidc_provider.py`)
  - Implements `IdentityProvider` protocol
  - Load token from keychain, validate per-request (60s cache)
  - Auto-refresh expired tokens
  - Extract claims → populate Subject with TOKEN provenance

- [ ] **Identity provider migration**
  - Update `create_identity_provider(config)` for OIDC
  - Populate full Subject fields from OIDC claims
  - Handle `AuthenticationError` at startup

---

## Phase 5: CLI & Integration

**Status: Not Started**

CLI auth commands and proxy integration.

- [ ] **Auth CLI commands** (`cli/commands/auth.py`)
  - `auth login` - Device Flow, store token in keychain
  - `auth logout` - Clear stored tokens
  - `auth status` - Show token validity, user info, storage backend

- [ ] **Proxy integration**
  - Load token → validate → device health → create provider
  - Show osascript popup on auth failure

---

## Phase 6: Session & mTLS

**Status: Not Started**

Session binding and mTLS transport.

- [ ] **Session binding** (`pips/auth/session.py`)
  - Cryptographically secure session IDs
  - Sessions bound to subject_id per MCP spec

- [ ] **mTLS transport** (`utils/transport.py`)
  - SSL context with client cert, client key, CA bundle
  - Integration with httpx for HTTP backends

---

## Phase 7: Testing & Documentation

**Status: Not Started**

- [ ] Unit tests for auth components
- [ ] Documentation (authentication.md, security.md)
- [ ] E2E testing with Auth0

---

## Future Phases

See below for context enhancements, policy improvements, and Web UI.

---

## Phase 8: Context Enhancements

- [ ] Approval context (HITL tracking)
- [ ] Data inspection (regex-based secret/PII detection)
- [ ] Tool registry with side effects
- [ ] Environment context conditions (mcp_client_name, time windows)
- [ ] Provenance tracking with confidence levels

---

## Phase 9: Policy Enhancements

- [ ] List support for conditions (OR logic)
- [ ] Trace/explanation in decision logs
- [ ] Policy IDs with content hash
- [ ] Subject-based conditions (issuer, audience, scopes, groups)
- [ ] Multiple path support for data flow policies
- [ ] Provenance-based conditions
- [ ] Hot reload via SIGHUP

---

## Phase 10: CLI Enhancements

- [ ] `policy validate` command
- [ ] `config validate` command
- [ ] `config export --claude` for Claude Desktop

---

## Phase 11: Web UI (React + shadcn)

- [ ] FastAPI backend (embedded)
- [ ] React + Vite + shadcn dashboard
- [ ] Logs viewer, HITL queue, config view
- [ ] `start --ui-port 8080`

---

## Session Architecture

**Single-session design:** CLI login stores token in OS keychain. Proxy reads from keychain on startup and validates per-request. Web UI (when added) inherits the same session via the proxy - no separate login required.

```
User runs: mcp-acp-extended auth login
    ↓
Device Flow → Auth0 → access_token + refresh_token
    ↓
Tokens stored in OS keychain
    ↓
User runs: mcp-acp-extended start
    ↓
Proxy loads token from keychain
    ↓
Per-request: validate JWT (60s cache), refresh if expired
    ↓
Web UI requests go through proxy → uses same session
```

---

## Stage 2 Completion Criteria

- [x] Startup validation for audit logs
- [x] AuditHealthMonitor integrated with proxy lifecycle
- [x] Device health checks (disk encryption, SIP)
- [ ] Zero Trust authentication with Auth0 (Device Flow)
- [ ] mTLS for HTTP backend connections
- [ ] Per-request token validation with caching
- [ ] Session binding to user identity
- [x] Auth event audit logging (auth.jsonl)
- [ ] Subject claims in policy conditions
- [ ] Policy OR logic, trace, IDs
- [ ] Environment and provenance conditions
- [ ] Hot reload via SIGHUP
- [ ] React web UI
- [ ] Documentation and E2E testing
