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
  - Wired up in Phase 5 (auth.jsonl created on first auth event)

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
  - Auth logging integrated (wired up in Phase 5)

- [x] **Proxy integration**
  - Hard gate at startup: proxy won't start if device unhealthy
  - `DeviceHealthMonitor` starts/stops with proxy lifespan

---

## Phase 4: OIDC Identity Provider ✓

**Status: Complete**

Wire authentication into the proxy request flow.

- [x] **OIDCIdentityProvider** (`pips/auth/oidc_provider.py`)
  - Implements `IdentityProvider` protocol
  - Load token from keychain, validate per-request (60s cache)
  - Auto-refresh expired tokens
  - Extract claims → populate Subject with TOKEN provenance

- [x] **Claims mapping utilities** (`pips/auth/claims.py`)
  - `build_subject_from_validated_token()` - full OIDC claims to Subject
  - `build_subject_from_identity()` - SubjectIdentity to Subject (both local and OIDC)
  - Shared logic for both STDIO and future HTTP patterns

- [x] **Identity provider migration**
  - Update `create_identity_provider(config, transport)` for OIDC
  - Factory returns `OIDCIdentityProvider` when auth configured
  - Zero Trust: raises `AuthenticationError` if auth not configured (no fallback)
  - `LocalIdentityProvider` exists only for unit tests, not exported for production
  - Future HTTP transport support documented (NotImplementedError)

- [x] **Proxy integration**
  - `proxy.py` passes config to identity provider factory
  - Handle startup errors with osascript popup
  - `show_startup_error_popup()` added to `pep/applescript.py`

- [x] **Context integration**
  - `context/context.py` uses `build_subject_from_identity()`
  - Subject populated with full OIDC claims when available

- [x] **Tests** (14 new tests in `test_auth.py`)
  - `TestOIDCIdentityProvider` - caching, auth errors, logout
  - `TestClaimsUtilities` - claims-to-Subject mapping
  - `TestCreateIdentityProvider` - factory function behavior

---

## Phase 5: CLI & Integration ✓

**Status: Complete**

CLI auth commands and proxy integration.

- [x] **Auth CLI commands** (`cli/commands/auth.py`)
  - `auth login` - Device Flow, store token in keychain
  - `auth logout` - Clear stored tokens
  - `auth status` - Show token validity, user info, storage backend

- [x] **Proxy integration**
  - Load token → validate → device health → create provider
  - Show osascript popup on auth failure
  - Zero Trust: `create_identity_provider()` raises `AuthenticationError` if auth not configured

- [x] **Wire up auth.jsonl logging**
  - Create `AuthLogger` in proxy startup
  - Pass `auth_logger` to `OIDCIdentityProvider` and `DeviceHealthMonitor`
  - Log auth events: token validation, session start/end, device health
  - Token validation logged to auth.jsonl (failures also to system.jsonl)

---

## Phase 6: Session Binding ✓

**Status: Complete**

Session binding per MCP security spec.

- [x] **Session binding** (`pips/auth/session.py`)
  - `BoundSession` dataclass with `bound_id` property
  - `SessionManager` for create/validate/invalidate operations
  - Sessions bound to subject_id: `<user_id>:<session_id>` format
  - Prevents session hijacking across users per MCP spec

- [x] **Proxy integration**
  - `SessionManager` created in proxy startup
  - Session created after identity validation with bound format
  - Session invalidated on proxy shutdown
  - Auth failures use placeholder ID for audit logging

- [x] **Tests** (25 new tests in `test_session.py`)
  - BoundSession format and expiry
  - SessionManager CRUD operations
  - User binding validation

---

## Phase 7: CLI Enhancements ✓

**Status: Complete**

- [x] `policy validate` command
- [x] `config validate` command

---

## Phase 8: Testing & Documentation ✓

**Status: Complete**

- [x] Unit tests for auth components (test_auth.py, test_session.py)
- [x] Documentation (docs/auth.md - comprehensive auth documentation)

---

## Phase 9: mTLS Transport ✓

**Status: Complete**

mTLS support for proxy-to-backend authentication via HTTPS.

- [x] **mTLS client factory** (`utils/transport.py`)
  - `create_mtls_client_factory()` with SSL context
  - Client certificate and key for mutual authentication
  - CA bundle for server verification
  - Certificate expiry checking with warnings/critical alerts
  - Integration with FastMCP's StreamableHttpTransport

- [x] **CLI integration** (`cli/commands/init.py`, `cli/prompts.py`)
  - Prompt for mTLS config when using HTTPS URLs
  - Certificate path validation during init
  - `auth status` shows mTLS certificate expiry

- [x] **Transport auto-detection**
  - mTLS applied only to HTTPS URLs (not HTTP)
  - Falls back to STDIO if HTTP+mTLS fails with both transports configured
  - Improved error messages for SSL/certificate failures

- [x] **Documentation** (`docs/manual-e2e-testing.md`)
  - Test certificate generation with proper key usage extensions
  - End-to-end testing instructions for mTLS

See [docs/auth.md](docs/auth.md) for configuration details.

---

## Phase 10: Security Hardening

**Status: In Progress**

Simplified scope focusing on real risks (FastMCP already handles JSON-RPC validation).

- [x] **HITL approval caching** (Complete)
  - `ApprovalStore` caches approvals by (subject_id, tool_name, path)
  - Configurable TTL (default 10 minutes, min 5, max 15)
  - 3-button dialog: Deny, Allow (Xm), Allow once
  - CODE_EXEC tools never cached (security)
  - Unknown side effects treated as unsafe (not cached)
  - API endpoints for cache visibility (`/api/approvals`)
  - Embedded uvicorn server for shared memory access
  - See `docs/roadmap.md` section 2.7 for future policy-exposed approval conditions

- [x] **Foundation** (Complete)
  - Rate limiting integrated directly with `PermissionDeniedError`

- [x] **Rate/burst anomaly detection** (Complete)
  - Per-session, per-tool sliding window rate tracking (`security/rate_limiter.py`)
  - Default: 30 calls/tool/minute (catches runaway loops in 15-30s)
  - Configurable per-tool thresholds via `RateLimitConfig`
  - HITL dialog on breach (user decides if activity is legitimate)
  - Integrated with `PolicyEnforcementMiddleware`

- [x] **Tool description sanitization** (Complete)
  - Sanitize `tools/list` responses from backends
  - Sanitizes both `tool.description` and `inputSchema.properties.*.description`
  - Cap length (500 chars), strip markdown links, strip HTML tags
  - Normalize Unicode (NFKC), remove control characters
  - Detect suspicious patterns (prompt injection) - logged as warnings
  - `security/sanitizer.py` - pure sanitization functions
  - Integrated into `PolicyEnforcementMiddleware` (in-place, documented)
  - Fail-open on errors (logs error, returns unsanitized)
  - Sanitization events logged to `decisions.jsonl`, warnings to `system.jsonl`

---

## Phase 11: Policy Enhancements

Focused on high-value policy improvements for single-user context.

- [x] **Rule descriptions** (Complete)
  - Added optional `description` field to `PolicyRule` for documentation
  - Self-documenting policies, included in `MatchedRule` for audit logs and UI
  - Implementation: `description: str | None = None` in `PolicyRule` model

- [x] **List/OR logic for conditions** (Complete)
  - Most conditions accept single value or list (e.g., `tool_name: ["bash", "rm", "mv"]`)
  - ANY match = rule applies (OR logic within field, AND across fields)
  - `_match_any()` helper in matcher.py handles both cases
  - Empty list `[]` never matches (no valid values)

- [x] **Multiple path support (source/destination)** (Complete)
  - Added `source_path` and `dest_path` conditions for data flow policies
  - Enables policies like "allow copy FROM /tmp TO /project"
  - Extracts paths from tool arguments (source, dest, from, to, etc.)
  - Current `path_pattern` remains for single-path operations

- [x] **Decision traces in logs** (Complete)
  - Matched rules now include id, effect, and description
  - `MatchedRuleLog` model for structured logging
  - Helps debug policy behavior and understand why requests were allowed/denied

- [x] **Hot reload via SIGHUP** (Complete)
  - `PolicyReloader` class with asyncio.Lock for concurrent safety
  - SIGHUP signal handler (Unix) and API endpoint (`POST /api/control/reload-policy`)
  - CLI command: `mcp-acp-extended policy reload`
  - Validates new policy before applying (LKG pattern on failure)
  - Updates RateBreachHandler and DecisionEventLogger on reload
  - Rollback all state on error
  - Logs reload events to system.jsonl

---

## Stage 2 Completion Criteria

- [x] Startup validation for audit logs
- [x] AuditHealthMonitor integrated with proxy lifecycle
- [x] Device health checks (disk encryption, SIP)
- [x] Token storage (keychain/encrypted file)
- [x] JWT validation with JWKS caching
- [x] Device Flow implementation
- [x] Token refresh logic
- [x] OIDCIdentityProvider with per-request validation
- [x] Subject claims from OIDC tokens
- [x] Auth event audit logging (auth.jsonl)
- [x] CLI auth commands (login, logout, status)
- [x] Session binding to user identity (`<user_id>:<session_id>` format)
- [x] Zero Trust enforcement (auth MANDATORY, no fallback)
- [x] Documentation (docs/auth.md)
- [x] E2E testing guide (docs/manual-e2e-testing.md)
- [x] mTLS for HTTP backend connections
- [x] Policy OR logic for conditions
- [x] Multiple path support (source/destination)
- [x] Decision trace in logs
- [x] Hot reload via SIGHUP

---

## Phase 12: CLI Enhancements for No-UI Mode

CLI commands for visibility without the web UI. Enables headless deployments, security-conscious users, scripting, and debugging.

**Why**: UI introduces dependencies and attack surface. CLI should work independently, reading files directly where possible.

**Approach**: File-based commands read directly from disk (work offline). Only runtime state commands need the API (require running proxy).

---

### File-Based Commands (no API, work offline)

#### JSON Output for Existing Commands
- [x] `auth status --json` - Token info as JSON
- [x] `config show --json` - Config as JSON
- [x] `policy show --json` - Policy as JSON

#### Log Viewing
- [x] **`logs` command group** (`cli/commands/logs.py`)
  - [x] `logs tail` - Tail log files (like `tail -f`)
    - [x] `--type=TYPE`: decisions, operations, auth, system
    - [x] `--json` for raw JSONL output
    - [x] Default: formatted, human-readable output
    - [x] Ctrl+C to stop
  - [x] `logs show` - Show recent log entries
    - [x] `--type=TYPE`: decisions, operations, auth, system
    - [x] `--limit=N` (default: 50)
    - [x] `--json` for raw output

#### Policy Management (extend `cli/commands/policy.py`)
- [x] `policy show` - Display current policy from file
  - [x] `--json` flag
  - [x] Shows rule count, last modified
- [x] `policy edit` - Open policy in $EDITOR (let user know policy reload necessary or proxy restart)
- [x] `policy add` - Add rule interactively (let user know policy reload necessary or proxy restart)

---

### Runtime Commands (require running proxy via API)

#### Status & Health
- [x] **`status` command** (`cli/commands/status.py`)
  - [x] Proxy health (running, uptime)
  - [x] Active session count
  - [x] `--json` for scriptable output

#### Session Management
- [x] **`sessions list` command** (`cli/commands/sessions.py`)
  - [x] Show active sessions
  - [x] Columns: session_id, user_id, started_at
  - [x] `--json` for scriptable output

#### Approval Management
- [x] **`approvals` command group** (`cli/commands/approvals.py`)
  - [x] `approvals cache` - Show cached approvals
    - [x] Columns: tool, path, user, expires_at
  - [x] `approvals clear` - Clear cache entries
    - [x] `--all` clears entire cache
    - [x] `--entry=N` clears specific entry by number
    - [x] Confirmation prompt

#### Policy Reload (already exists)
- [x] `policy reload` - Trigger hot reload via API

---

### Implementation Notes

**File-based commands:**
- Read directly from disk using existing config/policy loaders
- Work even when proxy is not running
- Use `get_config_path()`, `get_log_dir()` helpers

**Runtime commands:**
- Connect to proxy API via shared helper (`cli/api_client.py`)
- Read port/token from `~/.mcp-acp-extended/manager.json`
- Graceful error: "Proxy not running. Start with 'mcp-acp-extended start'"

**All commands:**
- Default: human-readable formatted output
- `--json` flag for scriptable output
- Follow existing CLI patterns (click groups, styled output)

**Deliverable**: Full CLI visibility - file-based works offline, runtime state when proxy running.
